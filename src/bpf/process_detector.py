from bcc import BPF
import os
import time
import ctypes

prog = """
#include <linux/sched.h>

struct process_info {
    u32 pid;
    u32 ppid;
    char comm[16];
};

BPF_HASH(processes, u32, struct process_info);

int trace_process_start(struct pt_regs *ctx) {
    struct process_info info = {};
    struct task_struct *task;
    
    task = (struct task_struct *)bpf_get_current_task();
    info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_kernel(&info.ppid, sizeof(info.ppid),
                   &task->real_parent->tgid);
    bpf_probe_read_kernel_str(&info.comm, sizeof(info.comm),
                   &task->comm);
    processes.update(&info.pid, &info);
    return 0;
}

int trace_process_exit(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    processes.delete(&pid);
    return 0;
}
"""

def get_proc_pids():
    pids = set()
    for entry in os.listdir('/proc'):
        if entry.isdigit():
            pids.add(int(entry))
    return pids

def get_kernel_pids(processes_map):
    pids = set()
    for pid, info in processes_map.items():
        pids.add(pid.value)
    return pids

print("SENTINEL - Hidden Process Detector")
print("=" * 60)

b = BPF(text=prog)
b.attach_kprobe(event="wake_up_new_task", fn_name="trace_process_start")
b.attach_kprobe(event="do_exit", fn_name="trace_process_exit")

print("Monitoring kernel for hidden processes...")
print("Press CTRL+C to stop\n")

try:
    while True:
        time.sleep(3)
        
        proc_pids = get_proc_pids()
        ebpf_pids = get_kernel_pids(b["processes"])
        kernel_pids = proc_pids | ebpf_pids
        hidden = ebpf_pids - proc_pids
        
        print(f"[*] Kernel sees: {len(kernel_pids)} processes")
        print(f"[*] /proc shows: {len(proc_pids)} processes")
        
        if hidden:
            print(f"\n[!!!] HIDDEN PROCESSES DETECTED: {len(hidden)}")
            for pid in hidden:
                try:
                    info = b["processes"][ctypes.c_uint(pid)]
                    print(f"    PID: {pid} | Name: {info.comm.decode('utf-8', errors='replace')}")
                except:
                    print(f"    PID: {pid} | Name: unknown")
        else:
            print("[OK] No hidden processes detected")
        print("-" * 60)

except KeyboardInterrupt:
    print("\nSENTINEL stopped.")

