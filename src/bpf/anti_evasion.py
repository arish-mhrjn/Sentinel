from bcc import BPF
import os
import time
import subprocess
import hashlib
import json
import signal as signal_module
import sys
import select
from datetime import datetime

prog = """
#include <linux/sched.h>

struct attack_event {
    u32 attacker_pid;
    u32 target_pid;
    char attacker_comm[16];
    int signal_num;
    u64 timestamp;
};

BPF_PERF_OUTPUT(attack_events);
BPF_HASH(signal_count, u32, u64);

int trace_signal_send(struct pt_regs *ctx,
                      struct task_struct *t,
                      int priv,
                      int sig) {
    struct attack_event event = {};
    u32 target_pid;
    u64 count = 1;
    u64 *val;

    bpf_probe_read_kernel(&target_pid,
                          sizeof(target_pid),
                          &t->pid);

    if (sig != 9 && sig != 15 && sig != 19)
        return 0;

    event.attacker_pid = bpf_get_current_pid_tgid() >> 32;
    event.target_pid = target_pid;
    event.signal_num = sig;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.attacker_comm,
                         sizeof(event.attacker_comm));

    val = signal_count.lookup(&target_pid);
    if (val) count = *val + 1;
    signal_count.update(&target_pid, &count);

    attack_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

SENTINEL_PID = os.getpid()
SECRET_KEY = "sentinel-secret-2025"
TOKEN_TIMEOUT = 30  # Seconds to wait for token input
attack_log = []
attack_history = []
running = True
stop_requested = False
stop_source = None

# ── Token System ──────────────────────────────────────────

def generate_stop_token():
    """Time-based token valid for 60 seconds only"""
    timestamp = int(time.time() / 60)
    token = hashlib.sha256(
        f"{SECRET_KEY}{timestamp}".encode()
    ).hexdigest()[:8]
    return token

def get_admin_token():
    token = generate_stop_token()
    expiry = 60 - (int(time.time()) % 60)
    return token, expiry

def verify_stop_token(provided_token):
    """Check current and previous minute token"""
    current = generate_stop_token()
    if provided_token == current:
        return True
    timestamp = int(time.time() / 60) - 1
    previous = hashlib.sha256(
        f"{SECRET_KEY}{timestamp}".encode()
    ).hexdigest()[:8]
    if provided_token == previous:
        return True
    return False

def get_input_with_timeout(prompt, timeout):
    """Get user input with timeout - returns (input, timed_out)"""
    print(prompt, end='', flush=True)
    
    # Save current terminal settings
    import termios
    import tty
    
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    
    try:
        tty.setraw(fd)
        input_chars = []
        start_time = time.time()
        
        while True:
            # Check if timeout exceeded
            if time.time() - start_time > timeout:
                print("\n[*] TIMEOUT - No token entered")
                return None, True
            
            # Check if input is available
            rlist, _, _ = select.select([sys.stdin], [], [], 0.1)
            if rlist:
                char = sys.stdin.read(1)
                
                # Enter key
                if char in ('\n', '\r'):
                    break
                # Backspace
                elif char == '\x7f':
                    if input_chars:
                        input_chars.pop()
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                # Ctrl+C
                elif char == '\x03':
                    print("\n[*] Cancelled")
                    return None, True
                # Regular character
                elif char.isprintable():
                    input_chars.append(char)
                    sys.stdout.write(char)
                    sys.stdout.flush()
        
        print()  # New line after input
        return ''.join(input_chars), False
        
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

# ── Authentication Stop ───────────────────────────────────

def authenticated_stop(source):
    """
    Common authentication logic for all stop methods.
    Includes timeout - auto-resumes if token not entered within TOKEN_TIMEOUT.
    """
    global running

    print(f"\n{'='*60}")
    print(f"[*] Stop requested via {source}")
    print(f"[*] Token verification required")
    print(f"[*] Timeout: {TOKEN_TIMEOUT} seconds")
    print(f"{'='*60}")

    token_input, timed_out = get_input_with_timeout(
        f"[*] Enter stop token (timeout in {TOKEN_TIMEOUT}s): ", 
        TOKEN_TIMEOUT
    )
    
    if timed_out:
        print(f"[*] Token entry timeout - resuming monitoring")
        print(f"[*] Token hint shown in heartbeat")
        log_attack(
            "UNAUTHORIZED_STOP",
            f"Token timeout via {source} - possible rootkit stop attempt",
            "MEDIUM"
        )
        print(f"{'='*60}\n")
        return False
    
    if token_input and verify_stop_token(token_input):
        print("[✔] Token verified - admin authenticated")
        print(f"[*] Total attacks: {len(attack_log)}")
        print("[*] SENTINEL stopping gracefully...")
        running = False
        print(f"{'='*60}\n")
        return True
    else:
        print("[!!!] Invalid token - BLOCKED")
        print("[!!!] Attempt logged")
        log_attack(
            "UNAUTHORIZED_STOP",
            f"Invalid stop token via {source} - possible rootkit stop attempt",
            "HIGH"
        )
        print(f"[*] SENTINEL continuing...")
        print(f"[*] Token hint shown in heartbeat")
        print(f"{'='*60}\n")
        return False

# ── Signal Handlers ───────────────────────────────────────

def handle_ctrl_c(sig, frame):
    """CTRL+C with token authentication - non-blocking"""
    global stop_requested, stop_source
    stop_requested = True
    stop_source = "CTRL+C"

def handle_admin_stop(sig, frame):
    """SIGUSR1 with token authentication - non-blocking"""
    global stop_requested, stop_source
    stop_requested = True
    stop_source = "SIGUSR1"

def handle_termination(sig, frame):
    """SIGTERM/SIGHUP = rootkit attack - block it"""
    sig_names = {15: 'SIGTERM', 1: 'SIGHUP'}
    sig_name = sig_names.get(sig, str(sig))
    print(f"\n{'='*60}")
    print(f"[!!!] SENTINEL RECEIVED {sig_name}!")
    print(f"[!!!] ROOTKIT TERMINATION ATTEMPT!")
    log_attack(
        "SIGNAL_ATTACK",
        f"SENTINEL received {sig_name} - rootkit termination attempt blocked",
        "CRITICAL"
    )
    print(f"[*] BLOCKED + logged")
    print(f"[*] Admin stop: kill -SIGUSR1 {SENTINEL_PID}")
    print(f"{'='*60}\n")

# Register all signal handlers
signal_module.signal(signal_module.SIGINT, handle_ctrl_c)
signal_module.signal(signal_module.SIGUSR1, handle_admin_stop)
signal_module.signal(signal_module.SIGTERM, handle_termination)
signal_module.signal(signal_module.SIGHUP, handle_termination)

# ── Contextualization Functions ───────────────────────────

def get_process_lineage(pid):
    lineage = []
    current = pid
    for _ in range(10):
        try:
            with open(f'/proc/{current}/status', 'r') as f:
                status = f.read()
            name = ''
            ppid = 0
            for line in status.split('\n'):
                if line.startswith('Name:'):
                    name = line.split()[1]
                if line.startswith('PPid:'):
                    ppid = int(line.split()[1])
            lineage.append(f"{name}({current})")
            if ppid == 0 or ppid == current:
                break
            current = ppid
        except:
            break
    return ' -> '.join(reversed(lineage))

def get_cmdline(pid):
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            cmdline = f.read().replace(b'\x00', b' ')
            return cmdline.decode('utf-8', errors='replace').strip()
    except:
        return 'unknown'

def get_user_context(pid):
    try:
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if line.startswith('Uid:'):
                    uid = int(line.split()[1])
                    if uid == 0:
                        return 'root (CRITICAL)'
                    else:
                        return f'uid:{uid}'
    except:
        pass
    return 'unknown'

def get_network_context(pid):
    try:
        lineage = get_process_lineage(pid)
        if 'sshd' in lineage:
            return 'REMOTE via SSH - HIGH RISK'
        return 'LOCAL'
    except:
        return 'unknown'

def get_severity(sig, user, attack_count):
    score = 0
    if sig == 9:  score += 40
    if sig == 15: score += 20
    if sig == 19: score += 30
    if 'root' in str(user): score += 30
    if attack_count > 3: score += 20
    if score >= 70: return 'CRITICAL', score
    if score >= 50: return 'HIGH', score
    if score >= 30: return 'MEDIUM', score
    return 'LOW', score

def correlate_attacks():
    if len(attack_history) < 2:
        return None
    types = set(a['type'] for a in attack_history[-5:])
    if 'SIGNAL_ATTACK' in types and 'EBPF_TAMPER' in types:
        return "CONFIRMED ROOTKIT: Signal + eBPF tampering"
    if 'SIGNAL_ATTACK' in types and 'MAP_TAMPER' in types:
        return "CONFIRMED ROOTKIT: Signal + Map tampering"
    if 'PROC_TAMPER' in types and 'EBPF_TAMPER' in types:
        return "CONFIRMED ROOTKIT: Process + eBPF tampering"
    if len(attack_history) >= 3:
        return "SUSPICIOUS: Multiple attack attempts"
    return None

# ── Core Functions ────────────────────────────────────────

def log_attack(attack_type, details, severity='HIGH'):
    event = {
        'timestamp': datetime.now().isoformat(),
        'type': attack_type,
        'severity': severity,
        'details': details,
        'sentinel_pid': SENTINEL_PID
    }
    attack_log.append(event)
    attack_history.append({'type': attack_type})
    log_path = os.path.expanduser('~/sentinel/logs/attacks.json')
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, 'w') as f:
        json.dump(attack_log, f, indent=2)
    print(f"\n{'='*60}")
    print(f"[!!!] ATTACK DETECTED")
    print(f"      Type:     {attack_type}")
    print(f"      Severity: {severity}")
    print(f"      Details:  {details}")
    print(f"      Time:     {event['timestamp']}")
    correlation = correlate_attacks()
    if correlation:
        print(f"\n[!!!] CORRELATION: {correlation}")
    print(f"{'='*60}")

def check_ebpf_programs():
    try:
        result = subprocess.run(['bpftool', 'prog', 'list'], 
                              capture_output=True, text=True)
        return result.stdout.count('kprobe')
    except:
        return -1

def check_proc_integrity():
    try:
        with open(f'/proc/{SENTINEL_PID}/status', 'r') as f:
            status = f.read()
        return 'python' in status.lower()
    except:
        return False

def check_bpf_map_integrity(baseline_hash):
    try:
        result = subprocess.run(['bpftool', 'map', 'list'], 
                              capture_output=True, text=True)
        current_hash = hashlib.md5(result.stdout.encode()).hexdigest()
        if baseline_hash and current_hash != baseline_hash:
            return False, current_hash
        return True, current_hash
    except:
        return True, None

def get_baseline():
    try:
        result = subprocess.run(['bpftool', 'map', 'list'], 
                              capture_output=True, text=True)
        baseline_hash = hashlib.md5(result.stdout.encode()).hexdigest()
    except:
        baseline_hash = None
    return {
        'map_hash': baseline_hash,
        'prog_count': check_ebpf_programs(),
        'sentinel_pid': SENTINEL_PID
    }

def handle_attack_event(cpu, data, size):
    event = b["attack_events"].event(data)
    attacker = event.attacker_comm.decode('utf-8', errors='replace')
    sig_names = {9: 'SIGKILL', 15: 'SIGTERM', 19: 'SIGSTOP'}
    sig_name = sig_names.get(event.signal_num, str(event.signal_num))

    if event.target_pid == SENTINEL_PID:
        pid = event.attacker_pid
        lineage = get_process_lineage(pid)
        cmdline = get_cmdline(pid)
        user = get_user_context(pid)
        network = get_network_context(pid)
        try:
            count = b["signal_count"][event.target_pid].value
        except:
            count = 1
        severity, score = get_severity(event.signal_num, user, count)
        details = (f"Attacker: {attacker} (PID:{pid}) | "
                  f"Signal: {sig_name} | User: {user} | "
                  f"Origin: {network} | Lineage: {lineage} | "
                  f"CMD: {cmdline} | Score: {score}/100")
        log_attack("SIGNAL_ATTACK", details, severity)

# ── Main ──────────────────────────────────────────────────

print("SENTINEL - Anti-Evasion Monitor")
print("=" * 60)
print(f"[*] SENTINEL PID: {SENTINEL_PID}")
print("[*] Token-based authentication enabled")
print(f"[*] Token timeout: {TOKEN_TIMEOUT} seconds")
print("[*] Double CTRL+C bypass: BLOCKED")
print("[*] Full contextualization enabled")
print("[*] SIEM-style correlation active")

token, expiry = get_admin_token()
print(f"\n[*] Current stop token: {token}")
print(f"[*] Token expires in:   {expiry} seconds")
print(f"\n[*] Stop methods:")
print(f"    CTRL+C          → prompts for token ({TOKEN_TIMEOUT}s timeout)")
print(f"    kill -SIGUSR1   → prompts for token ({TOKEN_TIMEOUT}s timeout)")
print(f"    kill -9         → force stop (last resort)")
print(f"\n[*] Rootkit stops (SIGTERM/SIGHUP): BLOCKED")

b = BPF(text=prog)
b.attach_kprobe(event="__send_signal", fn_name="trace_signal_send")
b["attack_events"].open_perf_buffer(handle_attack_event)

print("\n[*] Establishing baseline...")
baseline = get_baseline()
print(f"[*] eBPF programs: {baseline['prog_count']}")
print(f"[*] Map hash: {baseline['map_hash'][:8] if baseline['map_hash'] else 'N/A'}...")
print(f"\n[*] Monitoring active! Heartbeat every 5 seconds\n")
sys.stdout.flush()

heartbeat = 0
last_heartbeat = time.time()

while running:
    try:
        # Handle stop request if any
        if stop_requested:
            if authenticated_stop(stop_source):
                break  # Exit loop if authenticated
            else:
                stop_requested = False  # Reset flag if auth failed
                last_heartbeat = time.time()  # Reset heartbeat timer
        
        # Poll for eBPF events with short timeout
        b.perf_buffer_poll(timeout=100)
        
        # Heartbeat and integrity checks every 5 seconds
        current_time = time.time()
        if current_time - last_heartbeat >= 5:
            heartbeat += 1
            last_heartbeat = current_time
            
            token, expiry = get_admin_token()
            print(f"[♥] Heartbeat #{heartbeat} | "
                  f"PID:{SENTINEL_PID} | "
                  f"Attacks:{len(attack_log)} | "
                  f"Token:{token}(exp:{expiry}s)")
            sys.stdout.flush()

            # Check 1: eBPF programs
            curr_progs = check_ebpf_programs()
            if curr_progs >= 0 and curr_progs < baseline['prog_count']:
                log_attack("EBPF_TAMPER", 
                          f"Programs: {baseline['prog_count']} -> {curr_progs}",
                          "CRITICAL")

            # Check 2: Map integrity
            intact, curr_hash = check_bpf_map_integrity(baseline['map_hash'])
            if not intact:
                log_attack("MAP_TAMPER", 
                          f"Hash: {baseline['map_hash'][:8]} -> {curr_hash[:8] if curr_hash else '?'}",
                          "CRITICAL")

            # Check 3: Process integrity
            if not check_proc_integrity():
                log_attack("PROC_TAMPER", 
                          "SENTINEL hidden from /proc",
                          "CRITICAL")

            _, baseline['map_hash'] = check_bpf_map_integrity(None)

    except KeyboardInterrupt:
        # Backup handler in case signal gets through
        stop_requested = True
        stop_source = "CTRL+C"
    except Exception as e:
        pass

print(f"\n[*] SENTINEL stopped.")
print(f"[*] Total attacks: {len(attack_log)}")
if attack_log:
    print("[*] Log: ~/sentinel/logs/attacks.json")
