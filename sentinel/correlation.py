"""Cross-detector correlation engine.

Each detector on its own produces a fair number of low-confidence findings: a
transient PID that vanishes between the kernel snapshot and the /proc read, a
short-lived file, a socket closing mid-scan. Those are individually ambiguous.

What is *not* ambiguous is the same host producing findings from two different
detectors within a few seconds of each other, because a real rootkit has to
hide on several axes at once. Each rule in config.CORRELATION_RULES encodes one
such combination, and firing a rule escalates every contributing alert.
"""
import threading
import time
from datetime import datetime

from .config import (CORRELATION_RULES, IS_ROOT, LOG_TIME_FORMAT,
                     MAX_CORRELATIONS, MAX_CORRELATION_WINDOW, SEVERITY_ORDER)
from .state import (_alert_seq, _rule_last_fired, corr_lock, correlations,
                    lock, recent_events)
from .emailer import get_email_config, send_email

def parse_log_time(ts):
    """Convert a detector log timestamp to epoch seconds, falling back to now."""
    try:
        return datetime.strptime(ts, LOG_TIME_FORMAT).timestamp()
    except (ValueError, TypeError):
        return time.time()



def next_id():
    """Monotonic id shared by alerts and correlations, so the UI can key on it."""
    _alert_seq[0] += 1
    return _alert_seq[0]


# Kept as a private alias: correlation internals below still call _next_id().
_next_id = next_id


def _record_correlation(corr, email=True):
    """Append a correlation, honouring the cap, and email it if configured.

    email=False is used when the correlation was recomputed from replayed log
    history: the finding still belongs in the UI, but a previous run already
    raised it and mailing it again on every restart is exactly the duplicate
    the log replay is otherwise responsible for.
    """
    with corr_lock:
        correlations.append(corr)
        if len(correlations) > MAX_CORRELATIONS:
            del correlations[:-MAX_CORRELATIONS]

    print(f"[!!] CORRELATION {corr['severity']}: {corr['title']}")

    cfg = get_email_config()
    if email and cfg.get('enabled') and cfg.get('to_addrs'):
        lines = [
            f"SENTINEL - CORRELATED {corr['severity']} FINDING",
            "=" * 60,
            f"Rule:  {corr['rule']}",
            f"Time:  {corr['time']}",
            f"What:  {corr['title']}",
            "",
            corr['explain'],
            "",
            "Contributing alerts:",
        ]
        for c in corr['contributors']:
            lines.append(f"  [{c['time']}] {c['detector'].upper()} | {c['type']} | {c['details']}")
        threading.Thread(
            target=send_email,
            args=(f"[SENTINEL] {corr['severity']}: {corr['title']}", "\n".join(lines)),
            daemon=True,
        ).start()


def record_detector_down(name, returncode, uptime, why=None):
    """Raise a correlation event when a detector process dies unexpectedly."""
    now = time.time()
    explain = (
        f'The {name} detector exited with code {returncode} after {uptime:.0f}s. '
        'Until it restarts, this detection axis is blind — and a process terminating '
        'the monitoring itself is a recognised anti-forensic step, so the exit is '
        'reported rather than silently repaired.'
    )
    if not IS_ROOT:
        explain += (
            ' NOTE: SENTINEL is not running as root, which is the overwhelmingly likely '
            'cause here rather than anything malicious — restart with sudo.'
        )
    if why:
        explain += f' Detector stderr: {why}'
    _record_correlation({
        'id': _next_id(),
        'rule': 'DETECTOR_DOWN',
        'title': f'{name.upper()} detector stopped unexpectedly',
        'severity': 'CRITICAL',
        'time': datetime.fromtimestamp(now).strftime(LOG_TIME_FORMAT),
        'epoch': now,
        'explain': explain,
        'contributors': [],
    })


def run_correlation(detector, alert_obj, email=True):
    """Feed one alert through the rule set, firing any rule whose conditions hold."""
    now = alert_obj['epoch']
    fired = []

    with corr_lock:
        recent_events.append({'epoch': now, 'detector': detector, 'alert': alert_obj})
        cutoff = now - MAX_CORRELATION_WINDOW
        while recent_events and recent_events[0]['epoch'] < cutoff:
            recent_events.pop(0)

        for rule in CORRELATION_RULES:
            window_start = now - rule['window']
            in_window = [e for e in recent_events if e['epoch'] >= window_start]
            present = {e['detector'] for e in in_window}

            if 'require' in rule:
                if not rule['require'].issubset(present):
                    continue
                contributors = [e for e in in_window if e['detector'] in rule['require']]
            else:
                if len(present) < rule['min_detectors']:
                    continue
                contributors = in_window

            # The rule holds — but only report it if it has not just fired, so a
            # sustained attack produces a readable timeline rather than one
            # correlation per alert.
            if now - _rule_last_fired.get(rule['name'], 0) < rule['cooldown']:
                continue
            _rule_last_fired[rule['name']] = now

            # Keep the most recent alert from each contributing detector.
            latest = {}
            for e in contributors:
                if e['detector'] not in latest or e['epoch'] >= latest[e['detector']]['epoch']:
                    latest[e['detector']] = e
            picked = sorted(latest.values(), key=lambda e: e['epoch'])

            fired.append({
                'id': _next_id(),
                'rule': rule['name'],
                'title': rule['title'],
                'severity': rule['severity'],
                'time': datetime.fromtimestamp(now).strftime(LOG_TIME_FORMAT),
                'epoch': now,
                'explain': rule['explain'].format(window=rule['window']),
                'contributors': [
                    {
                        'detector': e['detector'],
                        'time': e['alert']['time'],
                        'type': e['alert']['type'],
                        'details': e['alert']['details'],
                    }
                    for e in picked
                ],
                '_contributing_alerts': [e['alert'] for e in picked],
            })

    # Escalate contributing alerts outside the correlation lock.
    for corr in fired:
        with lock:
            for a in corr.pop('_contributing_alerts'):
                if SEVERITY_ORDER[corr['severity']] > SEVERITY_ORDER[a['severity']]:
                    a['severity'] = corr['severity']
                tags = a.setdefault('correlated', [])
                if corr['rule'] not in tags:
                    tags.append(corr['rule'])
        _record_correlation(corr, email=email)
