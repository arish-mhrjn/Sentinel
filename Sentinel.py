#!/usr/bin/python3
"""SENTINEL — eBPF rootkit detection dashboard. Entrypoint.

The implementation lives in the `sentinel/` package; see sentinel/__init__.py
for the module layout. This file only starts the background threads and serves
the app.

It also re-exports the package's public names, so `import Sentinel` remains a
single handle on the whole system for the test suite and for interactive
poking. Values that are rebound at runtime (the log offset, the email mark) are
proxied through __getattr__ below rather than snapshotted at import.
"""
import threading

from sentinel import config, correlation, detectors, emailer, logtail, state, web
from sentinel.config import (BASE_SEVERITY, DETECTORS, DETECTORS_DIR, IS_ROOT,
                             LOG_DIR, LOG_FILE, LOG_TIME_FORMAT,
                             MAX_ALERTS_PER_DETECTOR, MAX_CORRELATIONS,
                             MAX_RESTARTS, RESTART_GRACE, SEVERITY_ORDER,
                             WATCHDOG_INTERVAL)
from sentinel.state import (alerts, corr_lock, correlations, detector_lock,
                            detector_state, email_lock, email_queue, lock,
                            recent_events, replay_complete, _detector_procs)
from sentinel.emailer import (EMAIL_CONFIG_FILE, flush_email_digest,
                              get_email_config, load_email_config,
                              queue_email_alert, save_email_config,
                              send_email, send_immediate_alert,
                              update_email_config)
from sentinel.correlation import (parse_log_time, record_detector_down,
                                  run_correlation)
from sentinel.detectors import (detector_err_path, read_detector_error,
                                spawn_detector, start_detectors)
from sentinel.logtail import parse_alert, tail_log
from sentinel.web import app

# Names whose value changes during the run. Re-exporting them with a plain
# import would freeze the value they had at startup, so they are looked up on
# each access instead.
_LIVE = {
    'email_mark': logtail,
    'last_position': logtail,
    'FIRST_EVER_RUN': logtail,
    'email_mark_lock': logtail,
}


def __getattr__(name):
    module = _LIVE.get(name)
    if module is not None:
        return getattr(module, name)
    raise AttributeError(f"module 'Sentinel' has no attribute {name!r}")


def start_background_threads():
    """Start log tailing, digest batching and detector supervision."""
    threading.Thread(target=logtail.tail_log, daemon=True).start()
    threading.Thread(target=emailer.email_digest_loop, daemon=True).start()
    threading.Thread(target=detectors.detector_watchdog, daemon=True).start()
    detectors.start_detectors()


def _banner():
    print("=" * 60)
    print("🛡️ SENTINEL DASHBOARD")
    print("=" * 60)
    if not IS_ROOT:
        print("!" * 60)
        print("[!] NOT RUNNING AS ROOT — all five detectors will fail to start.")
        print("[!] eBPF programs need root to load, and BCC reads tracepoint")
        print("[!] formats from /sys/kernel/debug (root-only, mode 0700) just to")
        print("[!] compile them, so every detector dies on a compile error.")
        print("[!] Restart with:  sudo python3 Sentinel.py")
        print("[!] (The dashboard itself will still run, for UI work.)")
        print("!" * 60)
    print("[*] Detectors starting automatically...")
    print("[*] Dashboard: http://localhost:5000")
    print("[*] Default login: admin / changeme123 — CHANGE THIS")

    cfg = get_email_config()
    if cfg.get('enabled'):
        if cfg.get('smtp_username') and cfg.get('smtp_password') and cfg.get('to_addrs'):
            print(f"[*] Email alerts: ENABLED -> {', '.join(cfg['to_addrs'])} "
                  f"via {cfg['smtp_host']}:{cfg['smtp_port']}")
            print(f"[*] Immediate detectors: "
                  f"{', '.join(cfg.get('immediate_detectors', [])) or 'none'} | "
                  f"Digest every {cfg.get('digest_interval')}s")
        else:
            print("[!] Email alerts: ENABLED but misconfigured — open the "
                  "dashboard Settings panel to finish setup")
    else:
        print("[*] Email alerts: disabled (enable it from the dashboard "
              "Settings panel)")
    print("=" * 60)


# Importing Sentinel has always started the background workers, and the test
# suite relies on that. Kept as an import side effect for compatibility.
start_background_threads()


if __name__ == '__main__':
    _banner()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
