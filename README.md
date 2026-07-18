
# SENTINEL — Linux Rootkit Detection using eBPF

SENTINEL is a kernel-level intrusion detection system for Linux that uses eBPF
(via BCC) to detect the presence of rootkits by comparing what the kernel
actually knows against what userspace tools can see. When a rootkit hides a
process, module, file, or network connection, it creates a gap between these
two views — SENTINEL watches for that gap in real time.

## Why eBPF

Traditional rootkit detection tools (e.g. userspace scanners like chkrootkit)
compare filesystem snapshots or signatures, and can be fooled once a rootkit
has hooked the syscalls those tools rely on to read the system. SENTINEL
instead attaches directly to kernel tracepoints and kprobes, so its view of
the system is built from inside the kernel itself, at a layer most
userspace-hooking rootkits cannot easily hide from.

## Detection Modules

SENTINEL runs five independent eBPF-based detectors, each targeting a
different rootkit hiding technique:

1. **Process Detector** (`process_detector.py`)
   Tracks process creation/exit via `sched_process_fork` / `sched_process_exit`
   tracepoints, building a kernel-side PID map. This is diffed against the
   PIDs visible in `/proc`. A PID present in the kernel map but missing from
   `/proc` indicates a hidden process.

2. **Module Detector** (`module_detector.py`)
   Uses a kprobe on `do_init_module` to record every kernel module loaded,
   independent of `/proc/modules`. Diffing this kernel-side view against the
   public `/proc/modules` and `/sys/module` listing reveals hidden LKM rootkits.

3. **File Detector** (`file_detector.py`)
   Hooks `do_sys_open` to observe every file open at the kernel level, then
   checks whether the same path is visible via normal filesystem listing —
   catching files or directories hidden from userspace tools.

4. **Network Detector** (`network_detector.py`)
   Traces TCP state transitions directly from kernel socket structures
   (`sk->__sk_common`), capturing connections independent of `netstat`/`ss`,
   to detect hidden backdoor listeners or C2 connections.

5. **Syscall Monitor** (`syscall_monitor.py`)
   The core detection technique: compares syscall **invocation** counts
   (recorded via tracepoints) against syscall **handler execution** counts
   (recorded via kprobes on the real handler functions). If a syscall is
   invoked more often than its real handler executes, the syscall table
   has been tampered with — a direct indicator of LKM-based syscall hooking.

All detectors log to `/var/log/sentinel/alerts.log` in a standard
`timestamp | DETECTOR | TYPE | details` format, which is tailed and parsed
by the Flask dashboard (`sentinel.py`) for live visualization.

## Architecture

    ┌─────────────────┐     ┌─────────────────┐
    │  eBPF Detectors  │────▶│  alerts.log      │
    │  (5 processes)   │     │  (shared file)   │
    └─────────────────┘     └────────┬─────────┘
                                       │ tailed
                              ┌────────▼─────────┐
                              │  Flask Dashboard  │
                              │  (sentinel.py)    │
                              └───────────────────┘

Each detector runs as an independent Python process launched by the main
`sentinel.py` orchestrator, which also serves the live web dashboard.

## Requirements

- Linux with kernel headers installed (BCC requires them to compile eBPF programs)
- Python 3.x
- BCC (`bpfcc-tools` / `python3-bpfcc`)
- Flask
- Root privileges (required to load eBPF programs into the kernel)

## Installation

    sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
    pip install flask
    git clone <your-repo-url>
    cd sentinel

## Usage

    sudo python3 sentinel.py

This starts all five detectors and launches the dashboard, by default at
`http://localhost:5000`. Alerts appear in the dashboard in real time as
they're written to `/var/log/sentinel/alerts.log`.

## False Positive Handling

Each detector maintains a whitelist of known-legitimate system processes
and modules (e.g. `systemd`, `kworker`, `sshd`) and a strike-threshold
mechanism — an anomaly must persist across multiple check cycles before
it's raised as an alert, reducing noise from transient kernel state changes.

## Testing / Results

SENTINEL was validated against three real Linux rootkits to confirm
detection across different hiding techniques:

| Rootkit | Technique Used | Detected By | Time to Detection | Notes |
|---|---|---|---|---|
| [Rootkit 1 name] | [e.g. LKM syscall hooking] | [detector(s)] | [time] | [any misses/notes] |
| [Rootkit 2 name] | [e.g. DKOM process hiding] | [detector(s)] | [time] | [any misses/notes] |
| [Rootkit 3 name] | [e.g. hidden network backdoor] | [detector(s)] | [time] | [any misses/notes] |

*(Fill in actual values from your test runs — this table is the strongest
evidence in your report, so keep it accurate, including any partial misses.)*

## Limitations / Future Work

- Currently supports x86_64 syscall table monitoring; ARM64 syscall names
  would need separate handler mapping.
- ML/LLM-based anomaly analysis is planned but not yet implemented in this
  version — current detection is purely rule/diff-based.
- IPv6 connections are not currently tracked by the network detector.

## Project Context

Developed as a final-year software engineering capstone project, focused on
applying operating systems and kernel security concepts through direct
eBPF/BCC implementation rather than relying on third-party detection engines.
