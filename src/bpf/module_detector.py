#!/usr/bin/python3
from bcc import BPF
import os
import time
from datetime import datetime

# --- LOGGING SETUP ---
LOG_FILE = "/var/log/sentinel/alerts.log"
os.makedirs("/var/log/sentinel", exist_ok=True)

def log_alert(alert_type, message):
    """Write alert to log file with standard format"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"{timestamp} | MODULE | {alert_type} | {message}"
    with open(LOG_FILE, 'a') as f:
        f.write(log_line + "\n")
    print(log_line)

# 1. The Kernel Sensor (eBPF)
# --------------------------------------------------
bpf_code = """
#include <linux/module.h>
struct mod_info_t { char name[64]; };
BPF_HASH(detected_modules, u64, struct mod_info_t);

int kprobe__do_init_module(struct pt_regs *ctx, struct module *mod) {
    u64 ts = bpf_ktime_get_ns();
    struct mod_info_t info = {};
    if (mod) {
        bpf_probe_read(&info.name, sizeof(info.name), (void *)mod->name);
        detected_modules.update(&ts, &info);
    }
    return 0;
}
"""

def is_builtin(name):
    return not os.path.exists(f"/sys/module/{name}/initstate")

def get_public_view():
    try:
        with open("/proc/modules", "r") as f:
            return {line.split()[0] for line in f}
    except:
        return set()

def get_kernel_view():
    try:
        return {m for m in os.listdir("/sys/module") if not is_builtin(m)}
    except:
        return set()

# 2. Execution
# --------------------------------------------------
if os.getuid() != 0:
    print("[!] Run as root")
    exit(1)

b = BPF(text=bpf_code)
print("[*] Module Detector Started (Logging to /var/log/sentinel/alerts.log)")

status_cache = {}

try:
    while True:
        public_view = get_public_view()
        kernel_view = get_kernel_view()
        ebpf_map = b.get_table("detected_modules")
        ebpf_names = {val.name.decode('utf-8', 'ignore').strip() for key, val in ebpf_map.items()}
        internal_truth = (kernel_view | ebpf_names) - {''}

        for mod in internal_truth:
            is_hidden = mod not in public_view
            if status_cache.get(mod) != is_hidden:
                if is_hidden:
                    # Standard format alert
                    message = f"HIDDEN_MODULE|NAME={mod}"
                    log_alert("HIDDEN_MODULE", message)
                status_cache[mod] = is_hidden

        time.sleep(2)

except KeyboardInterrupt:
    print("\n[!] Stopped")
