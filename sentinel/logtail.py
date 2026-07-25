"""Follows alerts.log, turning new lines into in-memory alerts.

Also owns the email high-water mark, which is what stops a restart from
re-mailing the whole log. See load_email_mark() for the three startup cases.
"""
import json
import os
import threading
import time
from datetime import datetime

from .config import (BASE_SEVERITY, LOG_DIR, LOG_FILE, LOG_TIME_FORMAT,
                     MAX_ALERTS_PER_DETECTOR)
from . import state
from .state import (alerts, detector_lock, detector_state, lock,
                    replay_complete)
from .emailer import queue_email_alert
from .correlation import parse_log_time, run_correlation, next_id

# ---- Email high-water mark ----
# On startup the dashboard replays alerts.log from the beginning so the alert
# list and timeline chart repopulate (alerts are held in memory only). Without a
# marker that replay also re-queues every historical alert for email, so each
# restart re-sends the entire log.
#
# This file records how far into alerts.log the mailer has got. Anything at or
# before the mark is replayed into the UI but never emailed. It is a byte offset
# rather than a timestamp because log lines are second-granular -- several alerts
# can share a timestamp, and an offset is exact.
#
# It is stored separately from email_config.json deliberately: it is mailer
# progress, not user configuration, and must not be lost when settings are
# rewritten or exported.
EMAIL_MARK_FILE = os.path.join(LOG_DIR, "email_sent_mark")
email_mark_lock = threading.Lock()


def log_size():
    try:
        return os.stat(LOG_FILE).st_size
    except OSError:
        return 0


def load_email_mark():
    """Byte offset in alerts.log up to which alerts have already been mailed.

    Three distinct outcomes, because they need opposite handling:

      None  no prior state at all (first ever run). The caller assumes the
            existing log has been dealt with -- replaying months of history into
            someone's inbox is never what they wanted.
      0     we have run before, but the log was rotated or truncated. The file
            now holds content this install has never mailed, so all of it is
            genuine catch-up.
      n>0   normal case: mailed up to byte n.
    """
    try:
        with open(EMAIL_MARK_FILE, 'r') as f:
            data = json.load(f)
        mark = int(data.get('offset', 0))
        inode = data.get('inode')
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None

    # If the log was rotated, archived or truncated the old offset is
    # meaningless -- and a stale large offset would skip genuinely new alerts.
    try:
        st = os.stat(LOG_FILE)
    except OSError:
        return None
    if inode is not None and inode != st.st_ino:
        print("[*] alerts.log was rotated since last run — treating the new "
              "file as unmailed")
        return 0
    if mark > st.st_size:
        print("[*] alerts.log is shorter than the email mark (truncated) — "
              "treating the new contents as unmailed")
        return 0
    return max(0, mark)


def save_email_mark(offset):
    """Persist the mailer's progress. Best-effort: failing to record it risks a
    duplicate email after a crash, which is far better than crashing the
    tailer or, worse, dropping alerts."""
    try:
        inode = os.stat(LOG_FILE).st_ino
    except OSError:
        inode = None
    tmp = EMAIL_MARK_FILE + ".tmp"
    try:
        with open(tmp, 'w') as f:
            json.dump({'offset': int(offset), 'inode': inode}, f)
        os.replace(tmp, EMAIL_MARK_FILE)
    except OSError as e:
        print(f"[!] Could not persist email mark: {e}")


# Alerts at or before this offset must not be emailed again.
_loaded_mark = load_email_mark()
FIRST_EVER_RUN = _loaded_mark is None
# No usable mark => treat the whole existing log as already handled.
email_mark = log_size() if FIRST_EVER_RUN else _loaded_mark

# Alerts written while the dashboard was down are genuinely unmailed, so they do
# get sent -- but through the digest rather than as immediate mail, however
# CRITICAL they are. Paging someone the instant the dashboard comes back, about
# an event from hours ago, is noise; a batched summary is the useful form. This
# also bounds a long-downtime backlog to one email per detector instead of one
# per alert.
#
# `replay_complete` is the Event imported from .state above -- deliberately not
# re-created here. Waiters (the test suite, via Sentinel.replay_complete) hold
# the state module's object, so a second Event would be set while theirs never
# was.

# How far into alerts.log the tailer has read, in bytes. Starts at 0 so the
# first pass replays the whole file into the dashboard.
last_position = 0


def tail_log():
    """Follow alerts.log, parsing new lines into the in-memory alert store.

    On the first pass this replays the whole file so the dashboard has history
    to show. Replayed lines at or before `email_mark` are flagged as backfill so
    they populate the UI without generating email -- otherwise every restart
    would re-send the entire log.
    """
    global last_position, email_mark
    first_pass = True
    last_error = None
    while True:
        try:
            if os.path.exists(LOG_FILE):
                caught_up = 0
                with open(LOG_FILE, 'r') as f:
                    f.seek(last_position)
                    # readline() rather than `for line in f`: iterating a text
                    # file disables tell(), and the byte offset after each line
                    # is exactly what the email mark is measured in.
                    while True:
                        line = f.readline()
                        if not line:
                            break
                        if not line.endswith('\n'):
                            # A detector is mid-write. Leave the partial line
                            # for the next poll rather than parsing half of it.
                            break
                        end = f.tell()
                        last_position = end
                        line = line.strip()
                        if not line:
                            continue
                        if end <= email_mark:
                            mode = 'none'      # a previous run already had it
                        elif first_pass:
                            mode = 'digest'    # missed while we were down
                            caught_up += 1
                        else:
                            mode = 'normal'    # live
                        parse_alert(line, email_mode=mode)

                # Advance the mark to everything just consumed. Doing this once
                # per poll rather than per line keeps it to one small write a
                # second at most. Always write on the first pass even if the
                # offset is unchanged, so the file (and the inode it records for
                # rotation detection) exists from the start.
                if last_position > email_mark or first_pass:
                    with email_mark_lock:
                        email_mark = max(email_mark, last_position)
                        save_email_mark(email_mark)

                if first_pass and caught_up:
                    print(f"[*] {caught_up} alert(s) arrived while the dashboard "
                          f"was down — queued as a digest, not as immediate mail.")
                last_error = None
        except Exception as e:
            # Report the first occurrence and any *change* of error, but not the
            # same one every second. Reporting only on the first pass hid a
            # permanent failure behind one startup line while the dashboard went
            # on showing "no threats detected" -- the one outcome this tool must
            # never produce silently.
            msg = f"{type(e).__name__}: {e}"
            if msg != last_error:
                print(f"[!] Error reading {LOG_FILE}: {msg} "
                      f"(further identical errors suppressed)")
                last_error = msg

        if first_pass:
            if FIRST_EVER_RUN and email_mark:
                print(f"[*] Existing alerts.log ({email_mark} bytes) shown in the "
                      f"dashboard but not emailed — only new alerts are mailed.")
            replay_complete.set()
            first_pass = False

        time.sleep(1)


def parse_alert(line, email_mode='normal'):
    """Parse one log line into the in-memory alert store.

    email_mode controls the mail side only -- the alert always reaches the
    dashboard, charts and correlation engine:
      'normal'  live alert; immediate or digest per configuration
      'digest'  real but late (arrived while we were down); never immediate
      'none'    already mailed by a previous run; replayed for display only
    """
    try:
        parts = line.split(' | ')
        if len(parts) >= 4:
            timestamp = parts[0]
            detector = parts[1].lower()
            alert_type = parts[2]
            details = ' | '.join(parts[3:])
            if detector in alerts:
                alert_obj = {
                    'id': next_id(),
                    'time': timestamp,
                    'epoch': parse_log_time(timestamp),
                    'type': alert_type,
                    'details': details,
                    'severity': BASE_SEVERITY.get(detector, 'MEDIUM'),
                    'correlated': [],
                }
                with lock:
                    alerts[detector].append(alert_obj)
                    if len(alerts[detector]) > MAX_ALERTS_PER_DETECTOR:
                        alerts[detector] = alerts[detector][-MAX_ALERTS_PER_DETECTOR:]
                with detector_lock:
                    entry = detector_state.get(detector)
                    if entry:
                        entry['last_alert'] = alert_obj['time']
                        entry['alert_count'] += 1
                if email_mode != 'none':
                    queue_email_alert(detector, alert_obj,
                                      force_digest=(email_mode == 'digest'))
                run_correlation(detector, alert_obj,
                                email=(email_mode == 'normal'))
    except Exception as e:
        print(f"[!] Failed to parse alert line: {e}")
