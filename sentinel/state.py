"""Mutable runtime state shared across the application.

Kept in one module so the locking discipline is visible in a single place.

Lock ordering: `lock` -> `corr_lock` -> `detector_lock` -> `email_lock`. No code
path takes two of these at once; that is deliberate, and the ordering is
documented so it stays that way.
"""
import threading

from .config import DETECTORS

alerts = {
    'process': [],
    'module': [],
    'file': [],
    'network': [],
    'syscall': []
}
lock = threading.Lock()          # guards `alerts`

# ---- Email queue state ----
email_queue = {k: [] for k in alerts}
email_lock = threading.Lock()

detector_state = {
    name: {
        'name': name,
        'script': script,
        'pid': None,
        'status': 'stopped',   # running | stopped | missing | failed
        'started_at': None,
        'restarts': 0,
        'last_alert': None,
        'alert_count': 0,
        'error': None,
    }
    for name, script in DETECTORS
}
_detector_procs = {}           # name -> Popen, kept out of the JSON-serialisable state
detector_lock = threading.Lock()

# ---- Correlation state ----
correlations = []          # newest last, same convention as alerts
recent_events = []         # rolling window feeding the rules
_rule_last_fired = {}      # rule name -> epoch, enforces per-rule cooldown
corr_lock = threading.Lock()
_alert_seq = [0]

# Set once the startup replay of alerts.log has finished.
replay_complete = threading.Event()
