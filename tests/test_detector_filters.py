#!/usr/bin/env python3
"""Regression tests for the two false positives reported against the detectors:

  process: browser worker threads ("Heap helper", "JIT Worker") reported as
           hidden processes
  file:    /var/log/sentinel/email_config.json.tmp reported as a hidden file

Both detectors instantiate BPF at module level, which needs root. These tests
exec only the part of each script above that line, so they run unprivileged and
without BCC. The cut points are asserted, so if a detector is restructured such
that the pure logic moves below the BPF init, the test fails loudly rather than
silently testing nothing.
"""
import ctypes
import os
import platform
import sys
import tempfile
import threading
import time

BPF_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "src", "bpf")

FAILURES = []


def check(name, cond, extra=""):
    if cond:
        print(f"  ✓ {name}")
    else:
        print(f"  ✗ {name} {extra}")
        FAILURES.append(name)


def load_prefix(script, stop_marker):
    """exec the top of a detector script, up to the line starting stop_marker."""
    path = os.path.join(BPF_DIR, script)
    with open(path) as f:
        lines = f.readlines()
    cut = next((i for i, ln in enumerate(lines) if ln.startswith(stop_marker)), None)
    if cut is None:
        print(f"  ✗ could not find {stop_marker!r} in {script} — test is stale")
        sys.exit(1)
    ns = {'__name__': f'_{script}'}
    exec(compile("".join(lines[:cut]), path, 'exec'), ns)
    return ns


proc_d = load_prefix('process_detector.py', 'b = BPF(')
file_d = load_prefix('file_detector.py', 'print("[*] File Detector Started')


# ---------------------------------------------------------------- process ---
print("\n[1] Thread vs. hidden process")

me = os.getpid()
check("our own process is not classified as a thread", proc_d['is_thread'](me) is False)
check("get_tgid of ourselves is our pid", proc_d['get_tgid'](me) == me,
      proc_d['get_tgid'](me))

# A pid procfs has no record of is exactly what a hidden process looks like,
# and must NOT be dismissed as a thread.
ghost = 4194303  # above the default pid_max, so it cannot exist
check("a pid absent from /proc is not dismissed as a thread",
      proc_d['is_thread'](ghost) is False)
check("get_tgid of an absent pid is None", proc_d['get_tgid'](ghost) is None,
      proc_d['get_tgid'](ghost))

if platform.machine() == 'x86_64':
    SYS_gettid = 186
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    tid_box, stop = [], threading.Event()

    def worker():
        tid_box.append(libc.syscall(SYS_gettid))
        stop.wait(20)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    for _ in range(200):
        if tid_box:
            break
        time.sleep(0.01)

    if not tid_box:
        check("spawned a worker thread", False, "gettid never returned")
    else:
        tid = tid_box[0]
        # This is the bug, reproduced: the thread's tid is a real task the
        # fork tracepoint sees, but it is not listed at the top level of /proc.
        check("worker tid is genuinely absent from the /proc listing",
              tid not in proc_d['get_proc_pids'](), tid)
        check("...and is therefore correctly identified as a thread",
              proc_d['is_thread'](tid) is True, tid)
        check("its name is still readable (why alerts had real names)",
              proc_d['get_process_name'](tid) != "Unknown/Hidden",
              proc_d['get_process_name'](tid))
    stop.set()
else:
    print(f"  - skipped live-thread checks (arch {platform.machine()}, "
          f"gettid number differs)")

print("\n[2] Reported thread names are whitelisted")
for name in ("Heap helper", "JIT Worker", "heap helper", "  GC Marker  "):
    check(f"{name!r} whitelisted", proc_d['is_whitelisted'](me, name) is True)
for name in ("evil_rootkit", "kworker_backdoor", "xmrig"):
    check(f"{name!r} NOT whitelisted", proc_d['is_whitelisted'](ghost, name) is False)


# ------------------------------------------------------------------- file ---
print("\n[3] File detector pre-filters cover the reported path")

TARGET = "/var/log/sentinel/email_config.json.tmp"
check("SENTINEL's own log dir is skipped by prefix",
      any(TARGET.startswith(p) for p in file_d['SKIP_PREFIXES']))
check(".tmp is skipped by suffix",
      any(TARGET.endswith(s) for s in file_d['SKIP_SUFFIXES']))
check("plain .json was already covered",
      any("/tmp/x.json".endswith(s) for s in file_d['SKIP_SUFFIXES']))
check("an ordinary path is still inspected",
      not any("/home/user/.hidden_impl".startswith(p)
              for p in file_d['SKIP_PREFIXES'])
      and not any("/home/user/.hidden_impl".endswith(s)
                  for s in file_d['SKIP_SUFFIXES']))

print("\n[4] is_hidden no longer misreads a mid-check rename")

is_hidden = file_d['is_hidden']
tmpdir = tempfile.mkdtemp(prefix="sentinel-fd-")
visible = os.path.join(tmpdir, "visible.txt")
with open(visible, 'w') as f:
    f.write("x")

check("a normally visible file is not hidden", is_hidden(visible) is False)
check("a nonexistent file is not hidden",
      is_hidden(os.path.join(tmpdir, "nope")) is False)
check("a directory open is not hidden", is_hidden(tmpdir + "/") is False)

real_listdir = os.listdir

# Simulate concealment: the file is openable and stat-able, but absent from the
# directory listing. This must still alert.
racy = os.path.join(tmpdir, "concealed")
with open(racy, 'w') as f:
    f.write("x")
os.listdir = lambda d: [e for e in real_listdir(d) if e != "concealed"]
try:
    check("a file present but unlisted IS still reported hidden",
          is_hidden(racy) is True)
finally:
    os.listdir = real_listdir

# Simulate the atomic write: the path is unlinked between the open and the
# listing, which is what email_config.json.tmp was doing.
renamed = os.path.join(tmpdir, "atomic.tmp")
with open(renamed, 'w') as f:
    f.write("x")


def listdir_then_rename(d):
    out = real_listdir(d)
    if renamed.startswith(d):
        os.replace(renamed, os.path.join(tmpdir, "atomic"))
        out = [e for e in out if e != "atomic.tmp"]
    return out


os.listdir = listdir_then_rename
try:
    check("a file renamed away mid-check is NOT reported hidden",
          is_hidden(renamed) is False)
finally:
    os.listdir = real_listdir

for p in (visible, racy, os.path.join(tmpdir, "atomic")):
    try:
        os.unlink(p)
    except OSError:
        pass
os.rmdir(tmpdir)

print("\n" + "=" * 58)
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s): {', '.join(FAILURES)}")
    sys.exit(1)
print("DETECTOR FILTER CHECKS PASSED")
sys.exit(0)
