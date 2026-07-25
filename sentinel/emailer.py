"""SMTP alerting: settings persistence, routing and the digest loop."""
import json
import os
import smtplib
import threading
import time
from email.message import EmailMessage

from .config import LOG_DIR
from .state import email_lock, email_queue

EMAIL_CONFIG_FILE = os.path.join(LOG_DIR, "email_config.json")
email_config_lock = threading.Lock()

DEFAULT_EMAIL_CONFIG = {
    "enabled": os.environ.get("SENTINEL_EMAIL_ENABLED", "false").lower() == "true",
    "smtp_host": os.environ.get("SENTINEL_SMTP_HOST", "smtp.gmail.com"),
    "smtp_port": int(os.environ.get("SENTINEL_SMTP_PORT", "587")),
    "smtp_username": os.environ.get("SENTINEL_SMTP_USERNAME", ""),
    "smtp_password": os.environ.get("SENTINEL_SMTP_PASSWORD", ""),
    "use_tls": os.environ.get("SENTINEL_SMTP_TLS", "true").lower() == "true",
    "from_addr": os.environ.get("SENTINEL_ALERT_FROM", os.environ.get("SENTINEL_SMTP_USERNAME", "")),
    "to_addrs": [a.strip() for a in os.environ.get("SENTINEL_ALERT_TO", "").split(",") if a.strip()],
    "digest_interval": int(os.environ.get("SENTINEL_EMAIL_INTERVAL", "60")),
    "immediate_detectors": sorted(
        set(d.strip() for d in os.environ.get("SENTINEL_EMAIL_IMMEDIATE", "network,syscall").split(",") if d.strip())
    ),
}


def load_email_config():
    if os.path.exists(EMAIL_CONFIG_FILE):
        try:
            with open(EMAIL_CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
            merged = dict(DEFAULT_EMAIL_CONFIG)
            merged.update(cfg)
            return merged
        except Exception as e:
            print(f"[!] Failed to load {EMAIL_CONFIG_FILE}, using defaults: {e}")
    return dict(DEFAULT_EMAIL_CONFIG)


def save_email_config(cfg):
    os.makedirs(os.path.dirname(EMAIL_CONFIG_FILE), exist_ok=True)
    tmp_path = EMAIL_CONFIG_FILE + ".tmp"
    with open(tmp_path, 'w') as f:
        json.dump(cfg, f, indent=2)
    os.chmod(tmp_path, 0o600)  # config holds an SMTP password — keep it off-limits to other users
    os.replace(tmp_path, EMAIL_CONFIG_FILE)


email_config = load_email_config()


def get_email_config():
    with email_config_lock:
        return dict(email_config)


def update_email_config(updates):
    with email_config_lock:
        email_config.update(updates)
        save_email_config(email_config)
        return dict(email_config)


# ---------------- Sending ----------------

def send_email(subject, body, cfg=None):
    """Send a single email via SMTP. Fails silently (with a log line) so a mail
    outage never takes down alert collection or the dashboard."""
    cfg = cfg or get_email_config()
    if not cfg.get("enabled"):
        return None
    if not cfg.get("smtp_username") or not cfg.get("smtp_password") or not cfg.get("to_addrs"):
        print("[!] Email alerts enabled but smtp_username/smtp_password/to_addrs not fully configured")
        return "Email is enabled but SMTP username, password, or recipients are missing."
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = cfg.get("from_addr") or cfg.get("smtp_username")
    msg['To'] = ", ".join(cfg.get("to_addrs", []))
    msg.set_content(body)
    try:
        host, port = cfg["smtp_host"], int(cfg["smtp_port"])
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=10) as server:
                server.login(cfg["smtp_username"], cfg["smtp_password"])
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=10) as server:
                if cfg.get("use_tls", True):
                    server.starttls()
                server.login(cfg["smtp_username"], cfg["smtp_password"])
                server.send_message(msg)
        return None
    except Exception as e:
        print(f"[!] Failed to send email alert: {e}")
        return str(e)


def send_immediate_alert(detector, alert):
    subject = f"[SENTINEL] CRITICAL {detector.upper()} alert"
    body = (
        f"SENTINEL - IMMEDIATE {detector.upper()} ALERT\n"
        f"{'=' * 50}\n"
        f"Time:    {alert['time']}\n"
        f"Type:    {alert['type']}\n"
        f"Details: {alert['details']}\n"
    )
    threading.Thread(target=send_email, args=(subject, body), daemon=True).start()


def queue_email_alert(detector, alert, force_digest=False):
    cfg = get_email_config()
    if not cfg.get("enabled") or not cfg.get("to_addrs"):
        return
    if not force_digest and detector in set(cfg.get("immediate_detectors", [])):
        send_immediate_alert(detector, alert)
        return
    with email_lock:
        email_queue[detector].append(alert)


def flush_email_digest(cfg=None):
    """Send one digest email per detector that has queued alerts.

    Returns the number of digests sent. Split out of the loop below so it can
    be driven directly by the tests instead of waiting on a timer."""
    cfg = cfg or get_email_config()
    if not cfg.get("enabled") or not cfg.get("to_addrs"):
        return 0

    # Snapshot and clear under the lock, then send outside it. Holding
    # email_lock across an SMTP round trip would block the log-tail thread --
    # which takes the same lock to enqueue -- for up to the socket timeout per
    # detector. It would also silently discard any alert that arrived mid-send,
    # since the old code cleared the queue after the send rather than before.
    with email_lock:
        batches = {d: items for d, items in email_queue.items() if items}
        for d in batches:
            email_queue[d] = []

    sent = 0
    for detector, items in batches.items():
        subject = f"[SENTINEL] {len(items)} new {detector.upper()} alert(s)"
        lines = [f"SENTINEL - {detector.upper()} ALERTS", "=" * 50, ""]
        for a in items:
            lines.append(f"[{a['time']}] [{a['type']}] {a['details']}")
        send_email(subject, "\n".join(lines), cfg=cfg)
        sent += 1
    return sent


def email_digest_loop():
    """Periodically batches up non-critical alerts into a single digest email
    per detector, so a burst of alerts doesn't flood the inbox or trip
    provider rate limits."""
    while True:
        cfg = get_email_config()
        time.sleep(max(5, int(cfg.get("digest_interval", 60))))
        try:
            flush_email_digest()
        except Exception as e:
            # A digest failure must never kill the thread and silently end all
            # future digest mail.
            print(f"[!] Email digest failed: {e}")
