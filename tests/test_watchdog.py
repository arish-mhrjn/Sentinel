#!/usr/bin/env python3
"""Verify the detector watchdog actually restarts a dying detector.

Uses fake detector scripts (they just sleep then exit) so this runs without
root or BCC.
"""
import os
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="sentinel-wd-log-")
DET = tempfile.mkdtemp(prefix="sentinel-wd-det-")

SCRIPTS = ['process_detector.py', 'module_detector.py', 'file_detector.py',
           'network_detector.py', 'syscall_monitor.py']
# process_detector dies after 1s writing a recognisable error to stderr (tests
# restart + stderr capture); the rest stay up.
CRASH_MSG = "error: incomplete definition of type 'struct tracepoint__sched__sched_process_fork'"
for name in SCRIPTS:
    path = os.path.join(DET, name)
    if name == 'process_detector.py':
        with open(path, 'w') as f:
            f.write("import sys, time\n"
                    "time.sleep(1)\n"
                    f"sys.stderr.write({CRASH_MSG!r} + '\\n')\n"
                    "sys.exit(1)\n")
    else:
        with open(path, 'w') as f:
            f.write("import time\ntime.sleep(600)\n")

os.environ["SENTINEL_LOG_DIR"] = TMP
os.environ["SENTINEL_DETECTORS_DIR"] = DET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import Sentinel as S  # noqa: E402

FAILURES = []


def check(name, cond, extra=""):
    if cond:
        print(f"  ✓ {name}")
    else:
        print(f"  ✗ {name} {extra}")
        FAILURES.append(name)


print("\n[1] All five fake detectors start")
d = S.detector_state
check("all five running", all(d[n]['status'] == 'running' for n in d),
      {n: d[n]['status'] for n in d})
check("pids recorded", all(d[n]['pid'] for n in d))
first_pid = d['process']['pid']

print(f"\n[2] Waiting for the watchdog to notice process_detector died "
      f"(interval {S.WATCHDOG_INTERVAL}s)...")
deadline = time.time() + 40
while time.time() < deadline:
    if S.detector_state['process']['restarts'] >= 2:
        break
    time.sleep(1)

check("process detector was restarted",
      S.detector_state['process']['restarts'] >= 1,
      S.detector_state['process']['restarts'])
check("it got a new pid", S.detector_state['process']['pid'] != first_pid,
      f"{first_pid} -> {S.detector_state['process']['pid']}")
check("each death raised a DETECTOR_DOWN correlation",
      len([c for c in S.correlations if c['rule'] == 'DETECTOR_DOWN']) >= 1,
      [c['rule'] for c in S.correlations])
check("healthy detectors were left alone",
      all(S.detector_state[n]['restarts'] == 0
          for n in S.detector_state if n != 'process'),
      {n: S.detector_state[n]['restarts'] for n in S.detector_state})

print(f"\n[3] Waiting for the crash loop to be capped at MAX_RESTARTS="
      f"{S.MAX_RESTARTS}...")
deadline = time.time() + (S.WATCHDOG_INTERVAL * (S.MAX_RESTARTS + 4)) + 20
while time.time() < deadline:
    if S.detector_state['process']['status'] == 'failed':
        break
    time.sleep(1)

check("crash-looping detector eventually marked 'failed'",
      S.detector_state['process']['status'] == 'failed',
      S.detector_state['process']['status'])
check("restarts did not exceed the cap",
      S.detector_state['process']['restarts'] <= S.MAX_RESTARTS,
      S.detector_state['process']['restarts'])
check("failure reason recorded", bool(S.detector_state['process']['error']),
      S.detector_state['process']['error'])

print("\n[4] The detector's own stderr is captured and surfaced")
err = S.detector_state['process']['error'] or ''
check("stderr tail reaches detector_state", CRASH_MSG in err, err[:160])
check("stderr file written to LOG_DIR",
      os.path.exists(S.detector_err_path('process')))
check("read_detector_error picks out the error line",
      CRASH_MSG in (S.read_detector_error('process') or ''))
downs = [c for c in S.correlations if c['rule'] == 'DETECTOR_DOWN']
check("DETECTOR_DOWN correlation quotes the stderr",
      any(CRASH_MSG in c['explain'] for c in downs),
      downs[0]['explain'][:160] if downs else None)
check("non-root hint added to the failure reason",
      ('root' in err.lower()) is (not S.IS_ROOT),
      f"IS_ROOT={S.IS_ROOT}")

client = S.app.test_client()
with client.session_transaction() as sess:
    sess['logged_in'] = True
h = client.get('/api/health').get_json()
check("/api/health reports the degraded state", h['all_healthy'] is False)
check("/api/health shows 4 of 5 up", h['healthy'] == 4, h['healthy'])
check("/api/health reports root status", h['running_as_root'] == S.IS_ROOT)
proc = next(x for x in h['detectors'] if x['name'] == 'process')
check("/api/health carries the error text", CRASH_MSG in (proc['error'] or ''),
      (proc['error'] or '')[:160])

body = client.get('/').get_data(as_text=True)
for marker in ('root-warning', 'detector-errors'):
    check(f"template contains #{marker}", marker in body)

# Stop the long-lived fakes so the test exits cleanly.
for name, proc in S._detector_procs.items():
    try:
        proc.kill()
    except Exception:
        pass

print("\n" + "=" * 58)
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s): {', '.join(FAILURES)}")
    sys.exit(1)
print("WATCHDOG CHECKS PASSED")
sys.exit(0)
