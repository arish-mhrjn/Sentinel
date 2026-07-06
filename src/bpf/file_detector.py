#!/usr/bin/python3
from bcc import BPF
import os
import time
from datetime import datetime

LOG_FILE = "/var/log/sentinel/alerts.log"
os.makedirs("/var/log/sentinel", exist_ok=True)

def log_alert(alert_type, message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"{timestamp} | FILE | {alert_type} | {message}"
    with open(LOG_FILE, 'a') as f:
        f.write(log_line + "\n")
    print(log_line)

ebpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

struct file_event_t {
    u32 pid;
    char comm[16];
    char filename[128];
};

BPF_PERF_OUTPUT(open_events);

int kprobe__do_sys_open(struct pt_regs *ctx, int dfd, const char __user *filename) {
    struct file_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read(&event.filename, sizeof(event.filename), (void *)filename);
    open_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Paths to skip BEFORE doing any filesystem work (fast string check)
SKIP_PREFIXES = (
    '/proc/', '/sys/', '/dev/', '/run/', '/lib/', '/lib64/',
    '/usr/lib/', '/usr/lib64/', '/usr/share/', '/usr/bin/',
    '/usr/sbin/', '/bin/', '/sbin/', '/etc/ld', '/etc/ssl',
    '/var/cache/', '/var/lib/', '/snap/',
)
SKIP_SUFFIXES = ('.so', '.pyc', '.cache', '.conf', '.log', '.db', '.json')

# Two caches — avoid re-checking same path repeatedly
not_hidden_cache = set()   # paths confirmed visible → skip forever
alerted_files    = set()   # paths already alerted → don't repeat

MY_PID = os.getpid()

def resolve_path(fname, pid):
    if not fname:
        return None
    if fname.startswith('/'):
        return fname
    try:
        cwd = os.readlink(f'/proc/{pid}/cwd')
        return os.path.normpath(os.path.join(cwd, fname))
    except Exception:
        return None

def is_hidden(filepath):
    """
    Only called for paths that passed all pre-filters and aren't cached.
    open() works but getdents() doesn't list it → rootkit hiding it.
    """
    directory = os.path.dirname(filepath) or '/'
    basename  = os.path.basename(filepath)
    try:
        fd = os.open(filepath, os.O_RDONLY | os.O_NONBLOCK)
        os.close(fd)
    except OSError:
        not_hidden_cache.add(filepath)   # can't open → cache as safe, skip next time
        return False
    try:
        if basename in os.listdir(directory):
            not_hidden_cache.add(filepath)   # visible → cache, skip next time
            return False
    except Exception:
        return False
    return True

def handle_event(cpu, data, size):
    try:
        event     = b["open_events"].event(data)
        raw_name  = event.filename.decode('utf-8', 'replace').strip('\x00').strip()
        proc_name = event.comm.decode('utf-8', 'replace').strip('\x00')
        pid_num   = event.pid

        # Never inspect our own opens (would cause infinite loop)
        if pid_num == MY_PID:
            return

        if not raw_name:
            return

        # Fast pre-filter: skip noisy paths without touching the filesystem
        if any(raw_name.startswith(p) for p in SKIP_PREFIXES):
            return
        if any(raw_name.endswith(s) for s in SKIP_SUFFIXES):
            return

        filepath = resolve_path(raw_name, pid_num)
        if not filepath:
            return
        if any(filepath.startswith(p) for p in SKIP_PREFIXES):
            return

        # Already alerted or confirmed not-hidden → skip with zero syscalls
        if filepath in alerted_files or filepath in not_hidden_cache:
            return

        # Only now do the expensive hidden check
        if is_hidden(filepath):
            message = f"HIDDEN_FILE|{filepath}|PID={pid_num}|PROC={proc_name}"
            log_alert("HIDDEN_FILE_ACCESS", message)
            alerted_files.add(filepath)

    except Exception:
        pass

print("[*] File Detector Started (Logging to /var/log/sentinel/alerts.log)")
print("[*] Ring buffer + path cache active — no sample loss")

b = BPF(text=ebpf_code)
b["open_events"].open_perf_buffer(handle_event, page_cnt=256)

try:
    while True:
        b.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    print("\n[!] Stopping SENTINEL...")
except Exception as e:
    print(f"Error: {e}")
