"""Flask application: routes, the JSON API and auth."""
import json
import os
import secrets
import threading
import time
import zipfile
from datetime import datetime
from functools import wraps
from io import BytesIO

from flask import (Flask, jsonify, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.security import check_password_hash

from .config import (BASE_SEVERITY, DETECTORS, IS_ROOT, LOG_DIR,
                     LOG_TIME_FORMAT, MAX_ALERTS_PER_DETECTOR,
                     SENTINEL_PASSWORD_HASH, SENTINEL_USERNAME, SEVERITY_ORDER)
from . import state
from .state import (alerts, corr_lock, correlations, detector_lock,
                    detector_state, lock)
from .emailer import (get_email_config, send_email, update_email_config)
from .detectors import read_detector_error
from .correlation import parse_log_time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = Flask(__name__,
            template_folder=os.path.join(PROJECT_ROOT, 'templates'),
            static_folder=os.path.join(PROJECT_ROOT, 'static'))
app.secret_key = secrets.token_hex(32)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if u == SENTINEL_USERNAME and check_password_hash(SENTINEL_PASSWORD_HASH, p):
            session['logged_in'] = True
            return redirect(url_for('index'))
        error = "Invalid credentials"
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))




@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')


def _filter_alerts(items, q, severity, since_epoch):
    out = []
    for a in items:
        if since_epoch and a.get('epoch', 0) < since_epoch:
            continue
        if severity and a.get('severity') != severity:
            continue
        if q:
            haystack = f"{a.get('type','')} {a.get('details','')}".lower()
            if q not in haystack:
                continue
        out.append(a)
    return out


@app.route('/api/alerts')
@login_required
def get_alerts():
    """Alert feed with optional server-side filtering.

    Filtering happens here rather than in the browser so that the numbers on the
    dashboard, the export files and any future API consumer all agree on what
    the current filter selects.
    """
    q = request.args.get('q', '').strip().lower()
    severity = request.args.get('severity', '').strip().upper()
    if severity not in SEVERITY_ORDER:
        severity = ''
    detector_filter = request.args.get('detector', '').strip().lower()

    try:
        minutes = int(request.args.get('minutes', '0'))
    except ValueError:
        minutes = 0
    since_epoch = time.time() - (minutes * 60) if minutes > 0 else 0

    with lock:
        total_counts = {k: len(v) for k, v in alerts.items()}
        filtered = {}
        for det, items in alerts.items():
            if detector_filter and det != detector_filter:
                filtered[det] = []
                continue
            filtered[det] = _filter_alerts(items, q, severity, since_epoch)

    counts = {k: len(v) for k, v in filtered.items()}
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for items in filtered.values():
        for a in items:
            sev = a.get('severity', 'MEDIUM')
            if sev in severity_counts:
                severity_counts[sev] += 1

    with corr_lock:
        correlation_count = len(correlations)

    return jsonify({
        'alerts': filtered,
        'counts': counts,
        'total_counts': total_counts,
        'severity_counts': severity_counts,
        'correlation_count': correlation_count,
        'filtered': bool(q or severity or minutes or detector_filter),
    })


@app.route('/api/health')
@login_required
def get_health():
    """Liveness of every detector process, for the dashboard status strip."""
    now = time.time()
    with detector_lock:
        detectors = []
        for name, _script in DETECTORS:
            e = detector_state[name]
            detectors.append({
                'name': name,
                'status': e['status'],
                'pid': e['pid'],
                'uptime': int(now - e['started_at']) if e['started_at'] and e['status'] == 'running' else 0,
                'restarts': e['restarts'],
                'last_alert': e['last_alert'],
                'alert_count': e['alert_count'],
                'error': e['error'],
            })
    healthy = sum(1 for d in detectors if d['status'] == 'running')
    return jsonify({
        'detectors': detectors,
        'healthy': healthy,
        'total': len(detectors),
        'all_healthy': healthy == len(detectors),
        'running_as_root': IS_ROOT,
    })


@app.route('/api/timeline')
@login_required
def get_timeline():
    """Per-detector alert counts bucketed over time, for the trend chart.

    Note this is bounded by what is held in memory (MAX_ALERTS_PER_DETECTOR per
    detector), so a long window during a heavy alert burst shows the most recent
    slice rather than the full history.
    """
    try:
        minutes = max(1, min(1440, int(request.args.get('minutes', '30'))))
    except ValueError:
        minutes = 30
    try:
        bucket = max(10, min(3600, int(request.args.get('bucket', '60'))))
    except ValueError:
        bucket = 60

    now = time.time()
    n_buckets = max(1, int((minutes * 60) // bucket))
    # Anchor the series to the bucket 'now' falls in and count backwards, so the
    # newest alerts always land in the final bucket. Aligning to the start of the
    # window instead would push them one slot past the end of the array.
    current_bucket = (int(now) // bucket) * bucket
    origin = current_bucket - (n_buckets - 1) * bucket

    series = {det: [0] * n_buckets for det in alerts}
    with lock:
        for det, items in alerts.items():
            for a in items:
                epoch = a.get('epoch', 0)
                if epoch < origin:
                    continue
                idx = int((epoch - origin) // bucket)
                if 0 <= idx < n_buckets:
                    series[det][idx] += 1

    labels = [
        datetime.fromtimestamp(origin + i * bucket).strftime('%H:%M')
        for i in range(n_buckets)
    ]
    return jsonify({
        'labels': labels,
        'series': series,
        'bucket': bucket,
        'minutes': minutes,
        'truncated': any(len(v) >= MAX_ALERTS_PER_DETECTOR for v in alerts.values()),
    })


@app.route('/api/correlations')
@login_required
def get_correlations():
    with corr_lock:
        return jsonify({'correlations': list(correlations), 'count': len(correlations)})


@app.route('/export')
@login_required
def export_custom():
    detectors_param = request.args.get('detectors', '')
    selected = detectors_param.split(',') if detectors_param else []
    date_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    with lock:
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            total = 0
            for det in selected:
                if det in alerts and alerts[det]:
                    content = [f"SENTINEL - {det.upper()} ALERTS", "="*60, f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", f"Total: {len(alerts[det])}", "="*60 + "\n"]
                    for a in alerts[det]:
                        tags = f"  [correlated: {', '.join(a['correlated'])}]" if a.get('correlated') else ""
                        content.append(f"[{a['time']}] [{a.get('severity','MEDIUM')}] [{a['type']}] {a['details']}{tags}")
                    zip_file.writestr(f"{det}_alerts_{date_str}.txt", "\n".join(content))
                    total += len(alerts[det])

            # The correlation report is the analytical part of the export, so it
            # ships alongside the raw per-detector logs whenever any exist.
            with corr_lock:
                corr_snapshot = list(correlations)
            if corr_snapshot:
                report = [
                    "SENTINEL - CORRELATED FINDINGS", "=" * 60,
                    f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    f"Total: {len(corr_snapshot)}", "=" * 60, "",
                ]
                for c in corr_snapshot:
                    report.append(f"[{c['time']}] [{c['severity']}] {c['rule']} — {c['title']}")
                    report.append(f"    {c['explain']}")
                    for contrib in c['contributors']:
                        report.append(f"      · {contrib['detector'].upper()}: [{contrib['time']}] {contrib['type']} | {contrib['details']}")
                    report.append("")
                zip_file.writestr(f"correlations_{date_str}.txt", "\n".join(report))

            if total == 0 and not corr_snapshot:
                zip_file.writestr("no_alerts.txt", "No alerts found")
        zip_buffer.seek(0)
        return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name=f"sentinel_alerts_{date_str}.zip")


@app.route('/api/email-config', methods=['GET'])
@login_required
def get_email_config_route():
    cfg = get_email_config()
    safe = dict(cfg)
    safe['smtp_password_set'] = bool(cfg.get('smtp_password'))
    safe.pop('smtp_password', None)  # never send the password back to the browser
    return jsonify(safe)


@app.route('/api/email-config', methods=['POST'])
@login_required
def save_email_config_route():
    data = request.get_json(force=True, silent=True) or {}
    updates = {}

    if 'enabled' in data:
        updates['enabled'] = bool(data['enabled'])
    if 'smtp_host' in data:
        updates['smtp_host'] = str(data['smtp_host']).strip()
    if 'smtp_port' in data:
        try:
            updates['smtp_port'] = int(data['smtp_port'])
        except (TypeError, ValueError):
            return jsonify({'error': 'smtp_port must be a number'}), 400
    if 'smtp_username' in data:
        updates['smtp_username'] = str(data['smtp_username']).strip()
    if 'smtp_password' in data and data['smtp_password']:
        # blank password field means "leave unchanged" — only overwrite if non-empty
        updates['smtp_password'] = str(data['smtp_password'])
    if 'use_tls' in data:
        updates['use_tls'] = bool(data['use_tls'])
    if 'from_addr' in data:
        updates['from_addr'] = str(data['from_addr']).strip()
    if 'to_addrs' in data:
        raw = data['to_addrs']
        if isinstance(raw, str):
            raw = raw.split(',')
        updates['to_addrs'] = [a.strip() for a in raw if a.strip()]
    if 'digest_interval' in data:
        try:
            updates['digest_interval'] = max(5, int(data['digest_interval']))
        except (TypeError, ValueError):
            return jsonify({'error': 'digest_interval must be a number'}), 400
    if 'immediate_detectors' in data:
        raw = data['immediate_detectors']
        if isinstance(raw, str):
            raw = raw.split(',')
        valid = set(alerts.keys())
        updates['immediate_detectors'] = sorted(set(d.strip() for d in raw if d.strip() in valid))

    new_cfg = update_email_config(updates)
    safe = dict(new_cfg)
    safe['smtp_password_set'] = bool(new_cfg.get('smtp_password'))
    safe.pop('smtp_password', None)
    return jsonify(safe)


@app.route('/api/email-test', methods=['POST'])
@login_required
def test_email_route():
    cfg = get_email_config()
    if not cfg.get('to_addrs'):
        return jsonify({'ok': False, 'error': 'No recipient addresses configured. Add at least one and save first.'}), 400
    if not cfg.get('smtp_username') or not cfg.get('smtp_password'):
        return jsonify({'ok': False, 'error': 'SMTP username/password missing. Save your settings first.'}), 400
    # Force enabled for the test send. `enabled` gates *automatic* alerting, and
    # the normal flow is to verify SMTP settings before switching alerting on --
    # so honouring it here made send_email() no-op and return None, which the
    # check below reads as success. The button then reported "sent" having sent
    # nothing.
    err = send_email(
        "[SENTINEL] Test alert email",
        f"This is a test email from SENTINEL, sent {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.\n"
        f"If you received this, email alerting is configured correctly."
        + ("" if cfg.get('enabled') else
           "\n\nNote: automatic alerting is currently disabled — tick "
           "'Enable email alerts' and save to receive real alerts."),
        cfg=dict(cfg, enabled=True),
    )
    if err:
        return jsonify({'ok': False, 'error': err}), 502
    return jsonify({'ok': True, 'alerting_enabled': bool(cfg.get('enabled'))})
