from bcc import BPF
import os
import time

prog = """
#include <linux/sched.h>

BPF_HASH(syscall_count, u64, u64);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 syscall_nr = args->id;
    u64 count = 0;
    u64 *val;

    val = syscall_count.lookup(&syscall_nr);
    if (val) {
        count = *val + 1;
    } else {
        count = 1;
    }
    syscall_count.update(&syscall_nr, &count);
    return 0;
}
"""

WATCHED_SYSCALLS = {
    0:   "read",
    1:   "write",
    2:   "open",
    3:   "close",
    59:  "execve",
    62:  "kill",
    78:  "getdents",
    217: "getdents64",
}

def get_kernel_text_range():
    start = None
    end = None
    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    if parts[2] == '_stext':
                        start = int(parts[0], 16)
                    if parts[2] == '_etext':
                        end = int(parts[0], 16)
        return start, end
    except:
        return None, None

def check_syscall_table():
    print("\n[*] Checking syscall table integrity...")
    kernel_start, kernel_end = get_kernel_text_range()

    if not kernel_start or not kernel_end:
        print("[!] Could not read kernel text range")
        return

    print(f"[*] Kernel text: 0x{kernel_start:x} - 0x{kernel_end:x}")

    hooked = []
    clean = []

    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    addr = int(parts[0], 16)
                    name = parts[2]

                    # ONLY check real syscall handlers
                    # They always start with __x64_sys_
                    if name.startswith('__x64_sys_'):
                        if addr == 0:
                            continue
                        if addr < kernel_start or addr > kernel_end:
                            hooked.append((name, addr))
                        else:
                            clean.append((name, addr))

    except Exception as e:
        print(f"[!] Error: {e}")
        return

    print(f"[*] Checked {len(hooked) + len(clean)} syscall handlers")
    print(f"[*] Clean: {len(clean)} | Suspicious: {len(hooked)}")

    if hooked:
        print(f"\n[!!!] SYSCALL HOOKS DETECTED: {len(hooked)}")
        for name, addr in hooked:
            print(f"    {name} -> 0x{addr:x} OUTSIDE kernel text!")
    else:
        print("[OK] All syscall handlers within kernel text segment")

print("SENTINEL - Syscall Integrity Checker")
print("=" * 60)

b = BPF(text=prog)
print("Monitoring syscalls...")
print("Integrity check every 10 seconds")
print("Press CTRL+C to stop\n")

try:
    while True:
        time.sleep(10)

        check_syscall_table()

        print("\n[*] Top syscalls being called:")
        syscall_data = []
        for nr, count in b["syscall_count"].items():
            name = WATCHED_SYSCALLS.get(nr.value, f"syscall_{nr.value}")
            syscall_data.append((name, count.value))

        syscall_data.sort(key=lambda x: x[1], reverse=True)
        for name, count in syscall_data[:5]:
            print(f"    {name}: {count} calls")
        print("-" * 60)

except KeyboardInterrupt:
    print("\nSENTINEL stopped.")

