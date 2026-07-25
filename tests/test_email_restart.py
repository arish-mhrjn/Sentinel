#!/usr/bin/env python3
"""Restarting SENTINEL must not re-send email for alerts already mailed.

The dashboard replays alerts.log from byte 0 on every start so the alert list
and timeline chart repopulate (alerts are memory-only). That replay used to run
the whole log back through the mailer, so each restart re-sent the entire
history. These tests drive real restarts -- fresh interpreters, same log dir --
against a real SMTP server and count what actually arrives.
"""
import os
import subprocess
import sys
import tempfile
import textwrap
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from fake_smtp import FakeSMTPServer  # noqa: E402

FAILURES = []


def check(name, cond, extra=""):
    if cond:
        print(f"  ✓ {name}")
    else:
        print(f"  ✗ {name} {extra}")
        FAILURES.append(name)


LOG_DIR = tempfile.mkdtemp(prefix="sentinel-restart-")
DET_DIR = tempfile.mkdtemp(prefix="sentinel-restart-det-")
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")

server = FakeSMTPServer()
server.start()

CONFIG = {
    "enabled": True,
    "smtp_host": server.host,
    "smtp_port": server.port,
    "smtp_username": "sentinel@example.test",
    "smtp_password": "hunter2",
    "use_tls": False,
    "from_addr": "sentinel@example.test",
    "to_addrs": ["soc@example.test"],
    "digest_interval": 5,
    "immediate_detectors": ["network", "syscall"],
}

# A driver run in a *separate interpreter*, so each call is a genuine restart
# with no leftover in-process state.
DRIVER = textwrap.dedent("""
    import json, os, sys, time
    sys.path.insert(0, {root!r})
    import Sentinel as S

    S.update_email_config(json.loads(os.environ['CFG']))

    # Wait for the startup replay to finish.
    S.replay_complete.wait(timeout=15)

    # Append any alerts this run is supposed to generate live.
    new = json.loads(os.environ.get('NEW_ALERTS', '[]'))
    if new:
        with open(S.LOG_FILE, 'a') as f:
            for line in new:
                f.write(line + "\\n")
        # Let the tailer pick them up (it polls once a second).
        time.sleep(3.5)

    if os.environ.get('FLUSH') == '1':
        S.flush_email_digest()
    time.sleep(1.5)
    print("MARK=%d" % S.email_mark)
""").format(root=ROOT)


def run_sentinel(new_alerts=(), flush=True):
    """Start Sentinel in a fresh interpreter, let it settle, then exit."""
    import json
    env = dict(os.environ)
    env.update({
        'SENTINEL_LOG_DIR': LOG_DIR,
        'SENTINEL_DETECTORS_DIR': DET_DIR,
        'SENTINEL_EMAIL_INTERVAL': '5',
        'CFG': json.dumps(CONFIG),
        'NEW_ALERTS': json.dumps(list(new_alerts)),
        'FLUSH': '1' if flush else '0',
    })
    p = subprocess.run([sys.executable, '-c', DRIVER], env=env,
                       capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        print("    driver stderr:", p.stderr[-800:])
    return p


def alert_line(ts, detector, atype, details):
    return f"{ts} | {detector.upper()} | {atype} | {details}"


HIST = [
    alert_line("2026-07-25 09:00:00", "process", "HIDDEN_PROCESS", "PID=101|NAME=old1"),
    alert_line("2026-07-25 09:00:05", "file", "HIDDEN_FILE_ACCESS", "HIDDEN_FILE|/tmp/.old"),
    alert_line("2026-07-25 09:00:09", "network", "HIDDEN_CONNECTION", "HIDDEN_CONN|9.9.9.9:1337"),
]
with open(LOG_FILE, 'w') as f:
    f.write("\n".join(HIST) + "\n")

print(f"\n[1] First ever run against an existing {os.path.getsize(LOG_FILE)}-byte log")
server.reset()
p = run_sentinel()
check("run completed", p.returncode == 0, p.returncode)
check("pre-existing history is NOT emailed", len(server.messages) == 0,
      [m['Subject'] for m in server.messages])
check("a mark file was written",
      os.path.exists(os.path.join(LOG_DIR, "email_sent_mark")))
check("the mark covers the whole existing log",
      "MARK=%d" % os.path.getsize(LOG_FILE) in p.stdout, p.stdout.strip())

print("\n[2] Restart with no new alerts sends nothing")
server.reset()
p = run_sentinel()
check("restart is silent", len(server.messages) == 0,
      [m['Subject'] for m in server.messages])

print("\n[3] A live alert after startup is emailed exactly once")
server.reset()
live = [alert_line("2026-07-25 10:00:00", "network", "HIDDEN_CONNECTION",
                   "HIDDEN_CONN|5.5.5.5:4444")]
p = run_sentinel(new_alerts=live)
check("the new alert is emailed", len(server.messages) >= 1,
      [m['Subject'] for m in server.messages])
if server.messages:
    check("...and it is the new one, not history",
          any('5.5.5.5:4444' in m.get_payload() for m in server.messages),
          [m.get_payload()[:60] for m in server.messages])
    check("...and no history leaked into it",
          not any('9.9.9.9:1337' in m.get_payload() for m in server.messages))
sent_once = len(server.messages)

print("\n[4] Restarting after that does NOT re-send it")
server.reset()
p = run_sentinel()
check("the previously-mailed alert is not re-sent", len(server.messages) == 0,
      [m.get_payload()[:80] for m in server.messages])
check("(it was genuinely sent the first time)", sent_once >= 1, sent_once)

print("\n[5] Alerts written while the dashboard is down are still delivered")
# Simulate downtime: append directly to the log with no Sentinel running.
with open(LOG_FILE, 'a') as f:
    f.write(alert_line("2026-07-25 11:00:00", "syscall", "SYSCALL_HOOK",
                       "SYSCALL|getdents64|invoked=90|handled=10") + "\n")
server.reset()
p = run_sentinel()
check("the missed alert is delivered on next start", len(server.messages) >= 1,
      [m['Subject'] for m in server.messages])
if server.messages:
    check("...containing the missed alert",
          any('getdents64' in m.get_payload() for m in server.messages),
          [m.get_payload()[:80] for m in server.messages])
    check("...as a digest, not an immediate page (it is already stale)",
          all('alert(s)' in m['Subject'] for m in server.messages),
          [m['Subject'] for m in server.messages])

print("\n[6] ...and is not re-sent on the run after that")
server.reset()
p = run_sentinel()
check("no duplicate of the caught-up alert", len(server.messages) == 0,
      [m.get_payload()[:80] for m in server.messages])

print("\n[7] Log rotation resets the mark instead of skipping new alerts")
# Replace the log with a brand new, shorter file (new inode).
os.rename(LOG_FILE, LOG_FILE + ".1")
with open(LOG_FILE, 'w') as f:
    f.write(alert_line("2026-07-25 12:00:00", "module", "HIDDEN_MODULE",
                       "HIDDEN_MODULE|rootkit_lkm") + "\n")
server.reset()
p = run_sentinel()
check("alerts in the rotated-in log are not skipped", len(server.messages) >= 1,
      [m['Subject'] for m in server.messages])
if server.messages:
    check("...and contain the new module alert",
          any('rootkit_lkm' in m.get_payload() for m in server.messages),
          [m.get_payload()[:80] for m in server.messages])

print("\n[8] The dashboard still shows replayed history it did not email")
server.reset()
import json  # noqa: E402
env = dict(os.environ)
env.update({'SENTINEL_LOG_DIR': LOG_DIR, 'SENTINEL_DETECTORS_DIR': DET_DIR,
            'CFG': json.dumps(CONFIG)})
probe = textwrap.dedent("""
    import json, os, sys
    sys.path.insert(0, {root!r})
    import Sentinel as S
    S.replay_complete.wait(timeout=15)
    c = S.app.test_client()
    with c.session_transaction() as s: s['logged_in'] = True
    data = c.get('/api/alerts').get_json()
    print("TOTAL=%d" % sum(data['total_counts'].values()))
""").format(root=ROOT)
p = subprocess.run([sys.executable, '-c', probe], env=env,
                   capture_output=True, text=True, timeout=120)
total = int(p.stdout.split("TOTAL=")[1].split()[0]) if "TOTAL=" in p.stdout else -1
check("replayed alerts still populate the dashboard", total >= 1,
      f"total={total} stderr={p.stderr[-300:]}")
check("...while sending no email", len(server.messages) == 0,
      [m['Subject'] for m in server.messages])

server.stop()

print("\n" + "=" * 58)
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s):")
    for f in FAILURES:
        print(f"  - {f}")
    sys.exit(1)
print("RESTART / DE-DUPLICATION CHECKS PASSED")
sys.exit(0)
