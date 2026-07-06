#!/usr/bin/python3
"""
SENTINEL — Syscall Monitor

Detects syscall table tampering by any LKM rootkit.

How it works:
    Layer 1 (tracepoint) : records every time a syscall is INVOKED
    Layer 2 (kprobes)    : records every time the real handler EXECUTES
    Comparison           : invoked > executed = handler was replaced = ALERT
"""

from bcc import BPF
import os, time
from datetime import datetime
from collections import defaultdict

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_FILE = "/var/log/sentinel/alerts.log"
os.makedirs("/var/log/sentinel", exist_ok=True)

def log_alert(alert_type, message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line  = f"{timestamp} | SYSCALL | {alert_type} | {message}"
    with open(LOG_FILE, 'a') as f:
        f.write(log_line + "\n")
    print(log_line)

# ── Kernel symbols ────────────────────────────────────────────────────────────
def load_kallsyms():
    syms = {}
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                p = line.split()
                if len(p) >= 3:
                    syms[p[2]] = int(p[0], 16)
        print(f"[*] Loaded {len(syms)} kernel symbols")
    except Exception as e:
        print(f"[!] kallsyms error: {e}")
    return syms

# ── Syscalls to monitor ───────────────────────────────────────────────────────
# These are the syscalls LKM rootkits commonly hook to hide themselves
SYSCALL_HANDLER_MAP = {
    62:  ("kill",          ["__x64_sys_kill",          "sys_kill"]),
    78:  ("getdents",      ["__x64_sys_getdents",      "sys_getdents"]),
    59:  ("execve",        ["__x64_sys_execve",        "sys_execve"]),
    105: ("setuid",        ["__x64_sys_setuid",        "sys_setuid"]),
    106: ("setgid",        ["__x64_sys_setgid",        "sys_setgid"]),
    175: ("init_module",   ["__x64_sys_init_module",   "sys_init_module"]),
    176: ("delete_module", ["__x64_sys_delete_module", "sys_delete_module"]),
}

def resolve_handlers(syms):
    resolved = {}
    for nr, (name, candidates) in SYSCALL_HANDLER_MAP.items():
        for sym in candidates:
            if sym in syms and syms[sym] != 0:
                resolved[nr] = (name, sym)
                break
        if nr not in resolved:
            print(f"[!] Could not resolve {name}({nr}) — skipping")
    return resolved

# ── eBPF Program ──────────────────────────────────────────────────────────────
BPF_PROGRAM = """
#include <linux/sched.h>

struct key_t { u32 pid; u32 nr; };

BPF_HASH(invoked,  struct key_t, u64);
BPF_HASH(executed, struct key_t, u64);

// Layer 1 — fires on every syscall entry, always, rootkit cannot stop this
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 nr  = args->id;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (nr != 59 && nr != 62 && nr != 78 &&
        nr != 105 && nr != 106 &&
        nr != 175 && nr != 176) {
        return 0;
    }

    struct key_t key = {}; key.pid = pid; key.nr = (u32)nr;
    u64 one = 1, *val = invoked.lookup(&key);
    if (val) (*val)++; else invoked.update(&key, &one);
    return 0;
}

// Layer 2 — fires only if syscall table still points to the real handler
// If rootkit replaced the entry, these probes NEVER fire
int kprobe____x64_sys_kill(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {}; key.pid = pid; key.nr = 62;
    u64 one = 1, *val = executed.lookup(&key);
    if (val) (*val)++; else executed.update(&key, &one);
    return 0;
}
int kprobe____x64_sys_getdents(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {}; key.pid = pid; key.nr = 78;
    u64 one = 1, *val = executed.lookup(&key);
    if (val) (*val)++; else executed.update(&key, &one);
    return 0;
}
int kprobe____x64_sys_execve(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {}; key.pid = pid; key.nr = 59;
    u64 one = 1, *val = executed.lookup(&key);
    if (val) (*val)++; else executed.update(&key, &one);
    return 0;
}
int kprobe____x64_sys_setuid(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {}; key.pid = pid; key.nr = 105;
    u64 one = 1, *val = executed.lookup(&key);
    if (val) (*val)++; else executed.update(&key, &one);
    return 0;
}
int kprobe____x64_sys_setgid(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {}; key.pid = pid; key.nr = 106;
    u64 one = 1, *val = executed.lookup(&key);
    if (val) (*val)++; else executed.update(&key, &one);
    return 0;
}
int kprobe____x64_sys_init_module(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {}; key.pid = pid; key.nr = 175;
    u64 one = 1, *val = executed.lookup(&key);
    if (val) (*val)++; else executed.update(&key, &one);
    return 0;
}
int kprobe____x64_sys_delete_module(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {}; key.pid = pid; key.nr = 176;
    u64 one = 1, *val = executed.lookup(&key);
    if (val) (*val)++; else executed.update(&key, &one);
    return 0;
}
"""

# ── Detection ─────────────────────────────────────────────────────────────────
alert_count = 0
prev_gap    = defaultdict(int)

def check_hooks(b, resolved):
    global alert_count, prev_gap

    total_inv = defaultdict(int)
    total_exe = defaultdict(int)

    for k, v in b["invoked"].items():  total_inv[k.nr] += v.value
    for k, v in b["executed"].items(): total_exe[k.nr] += v.value

    for nr, (name, sym) in resolved.items():
        inv = total_inv.get(nr, 0)
        exe = total_exe.get(nr, 0)

        if inv == 0:
            continue  # syscall not triggered yet

        gap = inv - exe
        if gap > prev_gap[nr]:
            alert_count += 1
            prev_gap[nr] = gap
            log_alert(
                "SYSCALL_HOOK_DETECTED",
                f"SYSCALL={name}({nr})"
                f"|HOOKED_HANDLER={sym}"
                f"|CONCLUSION=syscall_table_tampered_by_lkm_rootkit"
            )

# ── Main ──────────────────────────────────────────────────────────────────────
CHECK_INTERVAL = 15
PRINT_INTERVAL = 30

print("[*] SENTINEL Syscall Monitor Starting...")
syms     = load_kallsyms()
resolved = resolve_handlers(syms)

print(f"[*] Monitoring {len(resolved)} syscall handlers:")
for nr, (name, sym) in resolved.items():
    print(f"    [{nr:>3}] {name:<20} → {sym}")

print("\n[*] Loading eBPF probes...")
b = BPF(text=BPF_PROGRAM)
print("[*] Active — checking every 15s\n")

start      = time.time()
last_check = time.time()
last_print = time.time()

try:
    while True:
        b.perf_buffer_poll(timeout=1000)
        now = time.time()

        if now - last_check >= CHECK_INTERVAL:
            check_hooks(b, resolved)
            last_check = now

        if now - last_print >= PRINT_INTERVAL:
            print(f"[*] Uptime:{int(now-start)}s | Alerts:{alert_count}")
            last_print = now

except KeyboardInterrupt:
    print("\n[!] Stopping SENTINEL...")
