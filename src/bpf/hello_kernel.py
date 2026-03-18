from bcc import BPF

prog= """
int hello(void *ctx){
    u32 pid=bpf_get_current_pid_tgid()>>32;
    char comm[16];
    bpf_get_current_comm(&comm,sizeof(comm));
    bpf_trace_printk("SENTINEL: process %s PID %d\\n",comm,pid);
    return 0;
}
"""

b=BPF(text=prog)
print("Program loaded successfully")
b.attach_kprobe(event="wake_up_new_task", fn_name="hello")
print("SENTINEL active - watching kernel process creation...")
print("Open another terminal and run any command to see output")
print("-" * 60)
try:
    b.trace_print()
except KeyboardInterrupt:
    print("\nSENTINEL stopped.")
