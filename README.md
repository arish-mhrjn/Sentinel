
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
   `/proc`, and which procfs does not report as a thread of another process,
   indicates a hidden process.

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
by the Flask dashboard (`Sentinel.py`) for live visualization.

## Correlation Engine

Any single detector produces a fair number of low-confidence findings: a PID
that vanishes between the kernel snapshot and the `/proc` read, a short-lived
file, a socket that closes mid-scan. Individually these are ambiguous.

What is *not* ambiguous is two different detectors reporting within seconds of
each other, because a real rootkit has to hide on several axes at once — it
loads a module, hooks syscalls to conceal that module, then hides the processes
and sockets it owns. The dashboard therefore runs every alert through a rule
set and raises a separate, higher-confidence finding when a combination holds:

| Rule | Fires when | Window | Severity |
|---|---|---|---|
| `LKM_ROOTKIT` | hidden module + syscall table mismatch | 30 s | CRITICAL |
| `HIDDEN_BACKDOOR` | hidden process + kernel-visible TCP connection | 60 s | CRITICAL |
| `STEALTH_FOOTPRINT` | hidden process + hidden file | 60 s | HIGH |
| `MULTI_VECTOR` | any 4+ distinct detectors firing together | 120 s | CRITICAL |
| `DETECTOR_DOWN` | a detector process exits unexpectedly | — | CRITICAL |

Firing a rule escalates the severity of every contributing alert and tags it in
the UI, so a correlated finding is traceable back to its raw evidence. Each rule
has a cooldown, so a sustained attack produces a readable timeline rather than
one correlation per alert.

`DETECTOR_DOWN` exists because a detector exiting is itself security-relevant:
without it, a rootkit that kills the watcher would leave the dashboard happily
reporting "no threats detected".

## Severity Model

Severity is assigned server-side at parse time rather than re-derived in the
browser, so the API, the export files, the email alerts and the dashboard can
never disagree. Base severity reflects how hard the hiding technique is to
achieve — syscall-table tampering and hidden sockets need kernel-level control,
so they outrank a single hidden file — and the correlation engine can escalate
an alert above its base level when corroborating evidence appears.

| Detector | Base severity |
|---|---|
| Network, Syscall | CRITICAL |
| Process, Module | HIGH |
| File | MEDIUM |

## Architecture

    ┌──────────────────┐     ┌──────────────────┐
    │  eBPF Detectors  │────▶│   alerts.log     │
    │   (5 processes)  │     │  (shared file)   │
    └────────▲─────────┘     └────────┬─────────┘
             │ supervised              │ tailed
             │                ┌────────▼─────────┐
             └────────────────│ Flask Dashboard  │
              restart on death│   (Sentinel.py)  │
                              └────────┬─────────┘
                                       │
                          ┌────────────┴────────────┐
                          │   Correlation Engine    │
                          │  cross-detector rules   │
                          └─────────────────────────┘

Each detector runs as an independent Python process launched and supervised by
`Sentinel.py`, which also serves the live web dashboard. A watchdog thread polls
every 5 s and restarts any detector that dies, backing off after 5 rapid
crashes so a broken install fails visibly instead of spawning processes forever.

## Dashboard

- **Detector status strip** — live green/red pill per detector with uptime,
  alert count and restart count, so a blind detection axis is obvious at a glance.
- **Alert activity over time** — stacked per-detector line chart with a
  selectable 15 min – 24 h window.
- **Search and filter** — free-text search over alert type and details, plus
  severity and time-range filters. Filtering is applied server-side so the
  counts, charts and exports all agree on what the filter selects.
- **Correlations tab** — correlated findings with their contributing evidence
  and an explanation of why the combination matters.
- **Export** — per-detector logs plus a correlation report, as a ZIP.

## Email Alerting

Configured live from the dashboard's Settings panel and persisted to
`$SENTINEL_LOG_DIR/email_config.json` (mode 0600, since it holds an SMTP
password; the password is never sent back to the browser). Environment variables
seed the defaults the first time that file is created, for headless deploys.

Alerts are routed two ways. Detectors listed as *immediate* (`network` and
`syscall` by default, the two CRITICAL axes) email as they happen. Everything
else is batched into one digest per detector per interval, so a burst can't flood
an inbox or trip a provider rate limit.

### Not re-sending on restart

Alerts live in memory only, so the dashboard replays `alerts.log` from the
beginning on startup to repopulate the alert list and timeline chart. Left
unguarded, that replay also pushes every historical alert back through the
mailer — so each restart re-sends the entire log.

A byte offset into `alerts.log` is therefore persisted to
`$SENTINEL_LOG_DIR/email_sent_mark`, recording how far the mailer has got. An
offset is used rather than a timestamp because log lines are second-granular:
several alerts can share a timestamp, but an offset is exact. It is stored
separately from `email_config.json` because it is mailer progress, not user
configuration, and must survive settings being rewritten.

Startup then has three cases:

| Situation | Behaviour |
|---|---|
| No mark file (first ever run) | Existing log is displayed but **not** emailed |
| Mark present, log grew while down | The gap is emailed, but **as a digest** — never as immediate mail |
| Mark present, log rotated or truncated | Mark reset; the new file is treated as unmailed |

Alerts already covered by the mark are replayed into the dashboard, charts and
correlation engine as normal — only the email side is suppressed. Correlations
recomputed from replayed history are likewise displayed without being re-mailed.

Catch-up alerts are forced through the digest even when their detector is
configured for immediate mail. Paging someone the instant the dashboard returns,
about an event from hours ago, is noise rather than signal — and it bounds a long
downtime to one email per detector instead of one per alert.

### API

| Endpoint | Purpose |
|---|---|
| `GET /api/alerts` | Alert feed. Params: `q`, `severity`, `minutes`, `detector` |
| `GET /api/health` | Per-detector liveness, pid, uptime, restarts |
| `GET /api/timeline` | Bucketed alert counts. Params: `minutes`, `bucket` |
| `GET /api/correlations` | Correlated findings with contributing alerts |
| `GET /api/email-config` | Email settings (`GET`) / update them (`POST`) |
| `POST /api/email-test` | Send a test email with the current settings |
| `GET /export` | ZIP of selected detector logs + correlation report |

All endpoints require an authenticated session.

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

    sudo python3 Sentinel.py

This starts all five detectors and launches the dashboard, by default at
`http://localhost:5000`. Alerts appear in the dashboard in real time as
they're written to `/var/log/sentinel/alerts.log`.

The default login is `admin` / `changeme123` — change `SENTINEL_PASSWORD_HASH`
in `Sentinel.py` before running this anywhere that matters. The file prints the
command to generate a new hash.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_LOG_DIR` | `/var/log/sentinel` | Where alerts and config are written |
| `SENTINEL_DETECTORS_DIR` | `<repo>/src/bpf` | Detector scripts to supervise |

Both exist so the dashboard can run and be tested without root; normal
operation needs neither.

### Troubleshooting: all detectors show as down

Almost always this means SENTINEL was started without `sudo`. eBPF programs
need root to load, and BCC additionally reads tracepoint formats out of
`/sys/kernel/debug` (root-only, mode 0700) just to *compile* them — so without
root every detector dies on a compile error like:

    error: incomplete definition of type 'struct tracepoint__sched__sched_process_fork'

The dashboard detects this and shows a banner with the fix. Each detector's
stderr is captured to `$SENTINEL_LOG_DIR/detector_<name>.err`, and the tail of
it is shown against the failed detector in the status strip, so any other cause
(missing kernel headers, BCC version mismatch) is visible rather than silent.

## Testing

    python3 tests/test_dashboard.py         # parsing, severity, correlation, all API endpoints
    python3 tests/test_watchdog.py          # detector supervision and restart backoff
    python3 tests/test_detector_filters.py  # thread and atomic-write false positives
    python3 tests/test_email.py             # SMTP send path, config, alert routing
    python3 tests/test_email_restart.py     # no duplicate mail across restarts

All five run without root or BCC, and none of them touch the network. The first
two use a temporary log directory with stub detectors; the third execs only the
pure-logic prefix of each detector script, above the line where BPF is
instantiated. `test_watchdog.py` takes about a minute — it waits out real
watchdog intervals to confirm the restart cap is enforced.

`test_email_restart.py` launches SENTINEL repeatedly in fresh interpreters
against a shared log directory, so each start is a genuine restart with no
leftover in-process state, and counts what actually reaches the SMTP server
across them.

`test_email.py` runs against a real SMTP server (`tests/fake_smtp.py`) bound to
`127.0.0.1` on an ephemeral port, which speaks enough ESMTP (`EHLO`, `AUTH
PLAIN`/`LOGIN`, `MAIL`, `RCPT`, `DATA`) that `smtplib` performs the same
handshake it would against Gmail. Nothing is mocked, so a pass means the actual
send path works rather than that a stub was called. It also covers the failure
paths — rejected credentials, a `DATA` refusal and an unreachable host — by
making the server misbehave on demand.

## False Positive Handling

Each detector maintains a whitelist of known-legitimate system processes
and modules (e.g. `systemd`, `kworker`, `sshd`) and a strike-threshold
mechanism — an anomaly must persist across multiple check cycles before
it's raised as an alert, reducing noise from transient kernel state changes.

Two structural sources of noise needed more than a whitelist, because in both
cases the "anomaly" was an artifact of how the check was written rather than
anything on the system:

**Threads are not hidden processes.** `sched_process_fork` fires for every
`clone()`, so thread creation lands in the kernel-side PID map alongside real
processes. But the top level of `/proc` only lists thread-group *leaders*, so a
naive kernel-vs-`/proc` diff reports every worker thread on the machine as
hidden — a browser alone contributes hundreds, with names like `Heap helper`
and `JIT Worker`. The detector now reads `Tgid` from `/proc/<pid>/status` and
confirms the leader claims the task at `/proc/<tgid>/task/<tid>`; a task
belonging to another thread group is a thread, not a concealed process. This
does not weaken detection — a rootkit hiding a process from `/proc` readdir
still reports `Tgid == pid`, and a task procfs has no record of at all is still
flagged. On an idle test machine this removed 46 of 46 thread false positives
while leaving genuine detection intact.

**Atomic writes look like disappearing files.** `is_hidden()` concluded a file
was concealed when `open()` succeeded but the name was missing from the
directory listing. That is also exactly what the standard atomic write does —
write `foo.tmp`, `rename()` it over `foo` — if the rename lands between the two
checks. SENTINEL's own dashboard tripped this on
`/var/log/sentinel/email_config.json.tmp`. The check now confirms the path is
still reachable by `lstat()` before alerting: a genuinely hidden file is still
resolvable by name (`stat()` doesn't walk directory entries), whereas one that
was renamed away is gone. Transient suffixes (`.tmp`, `.swp`, `.part`, `~`, …)
and SENTINEL's own state directory are additionally skipped up front.

The general lesson, worth stating because it applies to this whole class of
tool: a detector built on comparing two views of the system has to account for
the views being sampled at different instants, and for the two views
legitimately differing by design.

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

- Alerts are held in memory only (200 per detector, newest kept). Restarting the
  dashboard loses history, and the timeline chart can only show what is still
  buffered. A SQLite store is the obvious next step and would also enable
  historical queries and attack replay.
- Currently supports x86_64 syscall table monitoring; ARM64 syscall names
  would need separate handler mapping.
- ML/LLM-based anomaly analysis is planned but not yet implemented in this
  version — current detection is rule, diff and correlation based.
- IPv6 connections are not currently tracked by the network detector.
- The dashboard polls (`/api/alerts` every 2 s); Server-Sent Events would push
  only new alerts instead of refetching the whole feed.
- Correlation windows and cooldowns are fixed constants in `CORRELATION_RULES`
  rather than being tunable from the UI.

## Project Context

Developed as a final-year software engineering capstone project, focused on
applying operating systems and kernel security concepts through direct
eBPF/BCC implementation rather than relying on third-party detection engines.
