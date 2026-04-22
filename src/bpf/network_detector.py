from bcc import BPF
import socket
import struct
import time

prog = """
#include <linux/sched.h>
#include <linux/socket.h>

struct connection {
    u32 pid;
    char comm[16];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

BPF_HASH(connections, u32, struct connection);

int trace_tcp_connect(struct pt_regs *ctx) {
    struct connection conn = {};

    conn.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&conn.comm, sizeof(conn.comm));

    connections.update(&conn.pid, &conn);
    return 0;
}

int trace_tcp_close(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    connections.delete(&pid);
    return 0;
}
"""

def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("I", addr))

def get_proc_connections():
    connections = []
    try:
        with open('/proc/net/tcp', 'r') as f:
            lines = f.readlines()[1:]
            for line in lines:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                local = parts[1]
                remote = parts[2]
                state = parts[3]
                local_ip = int_to_ip(int(local.split(':')[0], 16))
                local_port = int(local.split(':')[1], 16)
                remote_ip = int_to_ip(int(remote.split(':')[0], 16))
                remote_port = int(remote.split(':')[1], 16)
                connections.append({
                    'local': f"{local_ip}:{local_port}",
                    'remote': f"{remote_ip}:{remote_port}",
                    'state': state
                })
    except Exception as e:
        print(f"[!] Error reading /proc/net/tcp: {e}")
    return connections

def check_connections():
    print("\n[*] Checking network connections...")
    print("-" * 50)

    proc_conns = get_proc_connections()
    kernel_conns = b["connections"]

    states = {
        '01': 'ESTABLISHED',
        '0A': 'LISTEN',
        '06': 'TIME_WAIT',
        '08': 'CLOSE_WAIT'
    }

    listening = [c for c in proc_conns if c['state'] == '0A']
    established = [c for c in proc_conns if c['state'] == '01']

    print(f"[*] Total connections in /proc: {len(proc_conns)}")
    print(f"[*] Listening ports:            {len(listening)}")
    print(f"[*] Established connections:    {len(established)}")

    if listening:
        print("\n[*] Listening ports:")
        for c in listening:
            print(f"    {c['local']}")

    if established:
        print("\n[*] Established connections:")
        for c in established:
            print(f"    {c['local']} -> {c['remote']}")

    # Check kernel tracked connections
    print(f"\n[*] Kernel tracked connections: {len(kernel_conns)}")

    # Find hidden connections
    proc_remotes = set(c['remote'] for c in proc_conns)
    hidden = []
    for pid, conn in kernel_conns.items():
        daddr = int_to_ip(conn.daddr)
        dport = socket.ntohs(conn.dport)
        remote = f"{daddr}:{dport}"
        if remote not in proc_remotes and daddr != '0.0.0.0':
            hidden.append({
                'pid': pid.value,
                'comm': conn.comm.decode('utf-8', errors='replace'),
                'remote': remote
            })

    if hidden:
        print(f"\n[!!!] HIDDEN CONNECTIONS: {len(hidden)}")
        for h in hidden:
            print(f"    PID: {h['pid']} | {h['comm']} -> {h['remote']}")
    else:
        print("[OK] No hidden connections detected")

print("SENTINEL - Network Connection Detector")
print("=" * 60)

b = BPF(text=prog)
b.attach_kprobe(event="tcp_connect", fn_name="trace_tcp_connect")
b.attach_kprobe(event="tcp_close", fn_name="trace_tcp_close")

print("Monitoring network connections...")
print("Press CTRL+C to stop\n")

counter = 0
try:
    while True:
        time.sleep(1)
        counter += 1
        if counter % 10 == 0:
            check_connections()
            print("-" * 60)

except KeyboardInterrupt:
    print("\nSENTINEL stopped.")
