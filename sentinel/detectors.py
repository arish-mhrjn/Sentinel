"""Supervises the five eBPF detector processes.

Each runs as its own Python process; this module spawns them, captures their
stderr (so a BCC compile failure is diagnosable rather than silent) and restarts
any that die, backing off after MAX_RESTARTS so a broken install fails visibly
instead of spawning processes forever.
"""
import os
import subprocess
import threading
import time

from .config import (DETECTORS, DETECTORS_DIR, IS_ROOT, LOG_DIR,
                     MAX_RESTARTS, RESTART_GRACE, WATCHDOG_INTERVAL)
from .state import detector_lock, detector_state, _detector_procs
from .correlation import record_detector_down

def detector_err_path(name):
    return os.path.join(LOG_DIR, f"detector_{name}.err")


def read_detector_error(name, max_lines=12):
    """Return the tail of a detector's stderr, for reporting why it died.

    BCC failures are verbose (a full clang diagnostic), so the tail is trimmed to
    the lines that actually identify the problem.
    """
    try:
        with open(detector_err_path(name), 'r', errors='replace') as f:
            lines = [ln.rstrip() for ln in f if ln.strip()]
    except OSError:
        return None
    if not lines:
        return None
    # Prefer real errors over the warnings clang emits alongside them.
    errors = [ln for ln in lines if 'error' in ln.lower() or 'Error' in ln]
    picked = (errors or lines)[-max_lines:]
    return " / ".join(picked)[:600]


def spawn_detector(name):
    """Launch one detector process and record its state. Returns True on success."""
    entry = detector_state[name]
    script_path = os.path.join(DETECTORS_DIR, entry['script'])
    if not os.path.exists(script_path):
        with detector_lock:
            entry['status'] = 'missing'
            entry['pid'] = None
            entry['error'] = f"{script_path} not found"
        return False
    try:
        # stderr is captured to a file per detector rather than discarded: when a
        # detector dies the reason is the single most useful thing to show, and
        # BCC compile failures only ever appear on stderr. Truncated on each
        # spawn so what is reported belongs to the current run.
        err_file = open(detector_err_path(name), 'w')
        proc = subprocess.Popen(
            ['python3', script_path],
            stdout=subprocess.DEVNULL,
            stderr=err_file,
        )
        err_file.close()
    except Exception as e:
        with detector_lock:
            entry['status'] = 'failed'
            entry['pid'] = None
            entry['error'] = str(e)
        return False
    with detector_lock:
        _detector_procs[name] = proc
        entry['pid'] = proc.pid
        entry['status'] = 'running'
        entry['started_at'] = time.time()
        entry['error'] = None
    return True


def start_detectors():
    print("\n[*] Starting detectors...")
    for name, _script in DETECTORS:
        if spawn_detector(name):
            print(f"    ✓ Started {name} detector (pid {detector_state[name]['pid']})")
        else:
            print(f"    ✗ {name}: {detector_state[name]['error']}")
    print("[*] Detector supervisor running\n")


def detector_watchdog():
    """Restart detectors that die.

    A detector exiting is itself security-relevant: a rootkit that notices it is
    being watched may try to kill the watcher, and without this the dashboard
    would simply keep showing 'no threats detected'. Every unexpected exit is
    therefore raised as a CRITICAL correlation event as well as being restarted.
    """
    while True:
        time.sleep(WATCHDOG_INTERVAL)
        for name, _script in DETECTORS:
            entry = detector_state[name]
            with detector_lock:
                proc = _detector_procs.get(name)
                status = entry['status']
                started_at = entry['started_at']
                restarts = entry['restarts']
            if status != 'running' or proc is None:
                continue
            if proc.poll() is None:
                continue  # still alive

            uptime = time.time() - (started_at or time.time())
            why = read_detector_error(name)
            # A detector that ran fine for a while and then died gets a fresh
            # restart budget; one that dies immediately does not, so a broken
            # install (e.g. missing BCC) stops after MAX_RESTARTS instead of
            # spawning processes forever.
            with detector_lock:
                if uptime >= RESTART_GRACE:
                    entry['restarts'] = 0
                    restarts = 0
                entry['status'] = 'stopped'
                entry['pid'] = None
                entry['error'] = why

            record_detector_down(name, proc.returncode, uptime, why)

            if restarts >= MAX_RESTARTS:
                reason = f"exited {MAX_RESTARTS}x in quick succession (last code {proc.returncode}) — not restarting"
                if why:
                    reason += f". Last error: {why}"
                if not IS_ROOT:
                    reason += (". SENTINEL is not running as root — eBPF programs cannot be "
                               "loaded and BCC cannot read tracepoint formats from /sys/kernel/debug. "
                               "Restart with: sudo python3 Sentinel.py")
                with detector_lock:
                    entry['status'] = 'failed'
                    entry['error'] = reason
                print(f"[!] {name} detector failed permanently after {MAX_RESTARTS} restarts")
                if why:
                    print(f"    reason: {why}")
                continue

            with detector_lock:
                entry['restarts'] = restarts + 1
            print(f"[!] {name} detector died (code {proc.returncode}) — restarting")
            if why:
                print(f"    stderr: {why[:200]}")
            spawn_detector(name)
