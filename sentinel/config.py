"""Static configuration: paths, credentials, thresholds and rule definitions.

Everything here is a constant decided at import time. Mutable runtime state
lives in state.py, so it is always clear which is which.
"""
import os

# SENTINEL_LOG_DIR exists so the dashboard can be run and tested without root;
# in normal operation it stays at the default and the detectors write there too.
LOG_DIR = os.environ.get("SENTINEL_LOG_DIR", "/var/log/sentinel")
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")
# Resolve the detectors relative to the project root (this file lives in
# sentinel/, one level down) so the dashboard works from any checkout location.
# Override with SENTINEL_DETECTORS_DIR for unusual layouts.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DETECTORS_DIR = os.environ.get(
    "SENTINEL_DETECTORS_DIR",
    os.path.join(PROJECT_ROOT, "src", "bpf"),
)
os.makedirs(LOG_DIR, exist_ok=True)

# eBPF programs can only be loaded as root, and BCC needs to read tracepoint
# formats out of /sys/kernel/debug (mode 0700, root-owned) to compile them at
# all. Without root every detector dies on a compile error, so this is surfaced
# loudly at startup and in /api/health rather than left to be inferred.
IS_ROOT = os.geteuid() == 0

# ---- Auth config ----
SENTINEL_USERNAME = "admin"
# This hash corresponds to password: changeme123
# Generate your own: python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('YOUR_PASSWORD'))"
SENTINEL_PASSWORD_HASH = "scrypt:32768:8:1$itLjDUyroGMZ4q7D$a4a5e841dd54d7fbd41b451d41dc257b5e2996d4fb63cbac58e132efb191ae5a73c1f08574f6fbff49a5d79be1405516fe7a86ab23e7e434971321f2ec994bd8"


MAX_ALERTS_PER_DETECTOR = 200
LOG_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'  # what src/bpf/*.py log_alert() writes

# ---- Severity model ----
# Severity is assigned server-side at parse time (rather than being re-derived in
# the browser) so that the API, the export files, the email alerts and the
# dashboard can never disagree about how serious an alert is.
#
# The base severity reflects how hard the hiding technique is to achieve:
# syscall-table tampering and hidden sockets require kernel-level control, so
# they outrank a single hidden file. The correlation engine below can escalate
# an alert above its base severity when it appears alongside corroborating
# evidence from a different detector.
BASE_SEVERITY = {
    'process': 'HIGH',
    'module': 'HIGH',
    'file': 'MEDIUM',
    'network': 'CRITICAL',
    'syscall': 'CRITICAL',
}
SEVERITY_ORDER = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}


# ---------------- Detector supervision ----------------

DETECTORS = [
    ('process', 'process_detector.py'),
    ('module', 'module_detector.py'),
    ('file', 'file_detector.py'),
    ('network', 'network_detector.py'),
    ('syscall', 'syscall_monitor.py'),
]

WATCHDOG_INTERVAL = 5      # seconds between liveness checks
MAX_RESTARTS = 5           # give up after this many respawns, to avoid a crash loop
RESTART_GRACE = 10         # a detector must survive this long for its restart budget to reset


# ---------------- Correlation rules ----------------
#
# Each detector on its own produces a fair number of low-confidence findings: a
# transient PID that vanishes between the kernel snapshot and the /proc read, a
# short-lived file, a socket closing mid-scan. Those are individually ambiguous.
#
# What is *not* ambiguous is the same host producing findings from two different
# detectors within a few seconds of each other, because a real rootkit has to
# hide on several axes at once — it loads a module, hooks syscalls to conceal

CORRELATION_RULES = [
    {
        'name': 'LKM_ROOTKIT',
        'title': 'LKM rootkit — hidden module with syscall table tampering',
        'require': {'module', 'syscall'},
        'window': 30,
        'severity': 'CRITICAL',
        'cooldown': 120,
        'explain': (
            'A kernel module invisible to /proc/modules was observed loading, and within '
            '{window}s a syscall was invoked more often than its real handler executed. '
            'A module hiding itself is suspicious; a module hiding itself while the syscall '
            'table is diverging is the defining signature of an LKM rootkit.'
        ),
    },
    {
        'name': 'HIDDEN_BACKDOOR',
        'title': 'Hidden backdoor — concealed process holding a network socket',
        'require': {'process', 'network'},
        'window': 60,
        'severity': 'CRITICAL',
        'cooldown': 120,
        'explain': (
            'A PID present in the kernel task list but absent from /proc appeared within '
            '{window}s of a TCP connection seen at the socket layer. A process that hides '
            'itself and talks to the network is the shape of a C2 implant or bind shell.'
        ),
    },
    {
        'name': 'STEALTH_FOOTPRINT',
        'title': 'Stealth footprint — hidden process with hidden files on disk',
        'require': {'process', 'file'},
        'window': 60,
        'severity': 'HIGH',
        'cooldown': 180,
        'explain': (
            'A hidden process and a file opened at the kernel level but invisible to normal '
            'directory listing were seen within {window}s. This is consistent with an implant '
            'concealing both itself and its payload or configuration on disk.'
        ),
    },
    {
        'name': 'MULTI_VECTOR',
        'title': 'Multi-vector compromise — concurrent hiding across the whole stack',
        'min_detectors': 4,
        'window': 120,
        'severity': 'CRITICAL',
        'cooldown': 300,
        'explain': (
            'Four or more independent detectors reported anomalies within {window}s. Detectors '
            'disagreeing with userspace on this many axes at once is very difficult to produce '
            'accidentally and indicates a broad, active compromise.'
        ),
    },
]

MAX_CORRELATION_WINDOW = max(r['window'] for r in CORRELATION_RULES)
MAX_CORRELATIONS = 100
