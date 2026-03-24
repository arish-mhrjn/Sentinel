## Day 1 - Week 1
### Achieved
- Installed Ubuntu Server 22.04 (Kernel 5.15)
- Installed BCC, clang, libbpf development environment
- Written first eBPF kernel program in C
- Successfully detected real-time process creation from kernel space
- SENTINEL can see bash, systemd, lesspipe processes at kernel level

### What I Learned
- eBPF programs run inside the Linux kernel
- kprobes attach to kernel functions
- wake_up_new_task fires every time a new process is created
- bpf_trace_printk outputs from kernel space to userspace
