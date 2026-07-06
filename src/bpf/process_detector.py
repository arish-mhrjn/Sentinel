#!/usr/bin/python3
from bcc import BPF
import os
import time
from ctypes import c_uint
from datetime import datetime

# --- LOGGING SETUP ---
LOG_FILE = "/var/log/sentinel/alerts.log"
os.makedirs("/var/log/sentinel", exist_ok=True)

def log_alert(alert_type, message):
    """Write alert to log file with standard format"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"{timestamp} | PROCESS | {alert_type} | {message}"
    with open(LOG_FILE, 'a') as f:
        f.write(log_line + "\n")
    print(log_line)

# --- CONFIGURATION ---
WHITELIST = [
    "vmtoolsd", "VGAuthService", "snapd", "kworker", "sentinel",
    "python3", "python", "flask", "werkzeug", "bash", "sh", "dash",
    "sshd", "systemd", "ps", "grep", "insmod", "rmmod", "cat", "echo",
     "kthreadd", "rcu_sched", "migration", "ksoftirqd",
    "watchdog", "systemd-journal", "dbus-daemon", "polkitd", "cron",
    "sudo", "su", "login", "init", "systemd-logind", "NetworkManager",
    "dashboard", "orchestrator", "process_detector", "module_detector",
    "file_detector", "network_detector", "syscall_monitor"
]

CHECK_INTERVAL = 3
STRIKE_THRESHOLD = 2

# --- eBPF PROGRAM ---
ebpf_code = """
BPF_HASH(processes, u32, u32);

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 pid = args->child_pid;
    u32 val = 1;
    processes.update(&pid, &val);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 pid = args->pid;
    processes.delete(&pid);
    return 0;
}
"""

def get_proc_pids():
    pids = set()
    for entry in os.scandir('/proc'):
        if entry.is_dir() and entry.name.isdigit():
            try:
                if os.path.exists(f"/proc/{entry.name}/comm"):
                    pids.add(int(entry.name))
            except:
                continue
    return pids

def get_process_name(pid):
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except:
        return "Unknown/Hidden"

def is_whitelisted(pid, name):
    if name in WHITELIST:
        return True
    try:
        with open(f"/proc/{pid}/cmdline", "r") as f:
            cmd = f.read().lower()
            if 'sentinel' in cmd or 'detector' in cmd or 'dashboard' in cmd:
                return True
    except:
        pass
    return False

# Initialize eBPF
b = BPF(text=ebpf_code)
processes_map = b.get_table("processes")
suspicious_counts = {}
status_cache = {}

print("[*] Synchronizing SENTINEL with Kernel Task List...")
try:
    initial_pids = get_proc_pids()
    for pid in initial_pids:
        processes_map[c_uint(pid)] = c_uint(1)
    print(f"[*] Sync Complete: {len(initial_pids)} processes mapped.")
except Exception as e:
    print(f"[!] Warning: Sync partially failed: {e}")

print("="*60)
print(" SENTINEL: eBPF STEALTH PROCESS DETECTOR ACTIVE")
print("="*60)

try:
    while True:
        kernel_pids = set()
        for k, v in processes_map.items():
            kernel_pids.add(k.value)

        visible_pids = get_proc_pids()
        hidden_pids = kernel_pids - visible_pids

        for pid in list(hidden_pids):
            name = get_process_name(pid)

            if is_whitelisted(pid, name):
                continue

            suspicious_counts[pid] = suspicious_counts.get(pid, 0) + 1

            if suspicious_counts[pid] >= STRIKE_THRESHOLD:
                cache_key = f"proc_{pid}"
                if not status_cache.get(cache_key):
                    # Standard format alert
                    message = f"HIDDEN_PROCESS|PID={pid}|NAME={name}"
                    log_alert("HIDDEN_PROCESS", message)
                    status_cache[cache_key] = True

        # Cleanup
        for pid in list(suspicious_counts.keys()):
            if pid not in hidden_pids:
                del suspicious_counts[pid]
                cache_key = f"proc_{pid}"
                status_cache.pop(cache_key, None)

        time.sleep(CHECK_INTERVAL)

except KeyboardInterrupt:
    print("\n[!] Stopping SENTINEL...")

