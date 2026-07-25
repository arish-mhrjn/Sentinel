let selectedDetectors = { process: false, module: false, file: false, network: false, syscall: false };
let alertChart = null;
let severityChart = null;
let timelineChart = null;
let filterDebounce = null;
const TIMELINE_COLORS = {
    process: '#00d9ff',
    module:  '#a97bff',
    file:    '#ffdd44',
    network: '#ff6b6b',
    syscall: '#44ff88',
};
function openExportModal() { document.getElementById('exportModal').classList.add('active'); }
function closeExportModal() { document.getElementById('exportModal').classList.remove('active'); }
function openSettingsModal() {
    document.getElementById('settingsModal').classList.add('active');
    document.getElementById('settingsStatus').textContent = '';
    document.getElementById('settingsStatus').className = 'settings-status';
    fetch('/api/email-config').then(r => r.json()).then(cfg => {
        document.getElementById('set_enabled').checked = !!cfg.enabled;
        document.getElementById('set_smtp_host').value = cfg.smtp_host || '';
        document.getElementById('set_smtp_port').value = cfg.smtp_port || 587;
        document.getElementById('set_smtp_username').value = cfg.smtp_username || '';
        document.getElementById('set_smtp_password').value = '';
        document.getElementById('set_smtp_password').placeholder = cfg.smtp_password_set ? '•••••••• (leave blank to keep current)' : '(no password set)';
        document.getElementById('set_from_addr').value = cfg.from_addr || '';
        document.getElementById('set_to_addrs').value = (cfg.to_addrs || []).join(', ');
        document.getElementById('set_digest_interval').value = cfg.digest_interval || 60;
        document.getElementById('set_use_tls').checked = cfg.use_tls !== false;
        const imm = new Set(cfg.immediate_detectors || []);
        for (const d of ['process','module','file','network','syscall']) {
            document.getElementById(`imm_${d}`).checked = imm.has(d);
        }
    }).catch(e => console.error(e));
}
function closeSettingsModal() { document.getElementById('settingsModal').classList.remove('active'); }
function collectSettingsPayload() {
    const immediate = [];
    for (const d of ['process','module','file','network','syscall']) {
        if (document.getElementById(`imm_${d}`).checked) immediate.push(d);
    }
    return {
        enabled: document.getElementById('set_enabled').checked,
        smtp_host: document.getElementById('set_smtp_host').value,
        smtp_port: parseInt(document.getElementById('set_smtp_port').value || '587', 10),
        smtp_username: document.getElementById('set_smtp_username').value,
        smtp_password: document.getElementById('set_smtp_password').value,
        use_tls: document.getElementById('set_use_tls').checked,
        from_addr: document.getElementById('set_from_addr').value,
        to_addrs: document.getElementById('set_to_addrs').value,
        digest_interval: parseInt(document.getElementById('set_digest_interval').value || '60', 10),
        immediate_detectors: immediate,
    };
}
function saveSettings() {
    const status = document.getElementById('settingsStatus');
    status.textContent = 'Saving...';
    status.className = 'settings-status';
    fetch('/api/email-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(collectSettingsPayload())
    }).then(r => r.json().then(data => ({ ok: r.ok, data }))).then(({ok, data}) => {
        if (ok) {
            status.textContent = '✅ Settings saved';
            status.className = 'settings-status ok';
            document.getElementById('set_smtp_password').value = '';
            document.getElementById('set_smtp_password').placeholder = data.smtp_password_set ? '•••••••• (leave blank to keep current)' : '(no password set)';
        } else {
            status.textContent = '❌ ' + (data.error || 'Failed to save');
            status.className = 'settings-status err';
        }
    }).catch(e => {
        status.textContent = '❌ ' + e;
        status.className = 'settings-status err';
    });
}
function sendTestEmail() {
    const status = document.getElementById('settingsStatus');
    status.textContent = 'Sending test email...';
    status.className = 'settings-status';
    saveSettingsThenTest();
}
function saveSettingsThenTest() {
    const status = document.getElementById('settingsStatus');
    fetch('/api/email-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(collectSettingsPayload())
    }).then(() => fetch('/api/email-test', { method: 'POST' }))
      .then(r => r.json().then(data => ({ ok: r.ok, data })))
      .then(({ok, data}) => {
        if (ok) {
            status.textContent = data.alerting_enabled
                ? '✅ Test email sent — check your inbox'
                : '✅ Test email sent — but "Enable email alerts" is off, so real alerts will NOT be sent';
            status.className = data.alerting_enabled
                ? 'settings-status ok' : 'settings-status warn';
        } else {
            status.textContent = '❌ ' + (data.error || 'Failed to send test email');
            status.className = 'settings-status err';
        }
    }).catch(e => {
        status.textContent = '❌ ' + e;
        status.className = 'settings-status err';
    });
}
function toggleSelectAll() {
    const all = document.getElementById('selectAllCheckbox').checked;
    for (let key in selectedDetectors) {
        selectedDetectors[key] = all;
        const chk = document.getElementById(`chk_${key}`);
        if (chk) chk.checked = all;
    }
}
function updateDetector(detector) {
    selectedDetectors[detector] = document.getElementById(`chk_${detector}`).checked;
    const all = Object.values(selectedDetectors).every(v => v === true);
    const any = Object.values(selectedDetectors).some(v => v === true);
    document.getElementById('selectAllCheckbox').checked = all;
    document.getElementById('exportSubmit').disabled = !any;
}
function submitExport() {
    const selected = [];
    for (let key in selectedDetectors) if (selectedDetectors[key]) selected.push(key);
    if (selected.length === 0) return;
    window.location.href = `/export?detectors=${selected.join(',')}`;
    closeExportModal();
}
function switchMainTab(tabName, element) {
    document.querySelectorAll('.main-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.main-tab').forEach(t => t.classList.remove('active'));
    document.getElementById(`panel-${tabName}`).classList.add('active');
    element.classList.add('active');
}
function switchAlertTab(tabName, element) {
    document.querySelectorAll('.alert-container').forEach(c => c.classList.remove('active'));
    document.querySelectorAll('.sub-tab').forEach(t => t.classList.remove('active'));
    document.getElementById(`alerts-${tabName}`).classList.add('active');
    element.classList.add('active');
}
function currentFilters() {
    return {
        q: document.getElementById('filter-q').value.trim(),
        severity: document.getElementById('filter-severity').value,
        minutes: document.getElementById('filter-minutes').value,
    };
}
function filterQueryString() {
    const f = currentFilters();
    const p = new URLSearchParams();
    if (f.q) p.set('q', f.q);
    if (f.severity) p.set('severity', f.severity);
    if (f.minutes && f.minutes !== '0') p.set('minutes', f.minutes);
    return p.toString();
}
function onFilterChange() {
    clearTimeout(filterDebounce);
    filterDebounce = setTimeout(refresh, 250);
}
function clearFilters() {
    document.getElementById('filter-q').value = '';
    document.getElementById('filter-severity').value = '';
    document.getElementById('filter-minutes').value = '0';
    refresh();
}
function renderHealth(data) {
    const strip = document.getElementById('health-strip');
    if (!strip) return;
    let html = '';
    for (const d of data.detectors) {
        const up = d.status === 'running';
        const cls = up ? 'up' : (d.status === 'missing' ? 'warn' : 'down');
        let meta;
        if (up) {
            meta = `${formatUptime(d.uptime)} · ${d.alert_count} alerts`;
            if (d.restarts > 0) meta += ` · ↻${d.restarts}`;
        } else {
            meta = d.status.toUpperCase();
        }
        const tip = d.error ? ` title="${escapeHtml(d.error)}"` : (up ? ` title="pid ${d.pid}"` : '');
        html += `<div class="health-pill ${cls}"${tip}><span class="hp-dot"></span>`
              + `<span class="hp-name">${d.name.toUpperCase()}</span>`
              + `<span class="hp-meta">${escapeHtml(meta)}</span></div>`;
    }
    strip.innerHTML = html;
    const summary = document.getElementById('health-summary');
    if (summary) {
        if (data.all_healthy) {
            summary.textContent = `✅ ALL ${data.total} DETECTORS ONLINE`;
            summary.className = 'health-summary';
        } else {
            summary.textContent = `⚠️ ${data.healthy}/${data.total} DETECTORS ONLINE — DETECTION COVERAGE IS INCOMPLETE`;
            summary.className = 'health-summary degraded';
        }
    }
    // Not running as root is by far the most common reason for a wall of
    // dead detectors, so it gets an unmissable banner with the fix rather
    // than being buried in a per-pill tooltip.
    const rootWarn = document.getElementById('root-warning');
    if (rootWarn) {
        if (data.running_as_root === false) {
            rootWarn.style.display = 'block';
            rootWarn.innerHTML = '🛑 <b>NOT RUNNING AS ROOT</b> — eBPF programs cannot be loaded, '
                + 'and BCC cannot read tracepoint formats from <code>/sys/kernel/debug</code> to compile them. '
                + 'Every detector will die on a compile error. Restart with '
                + '<code>sudo python3 Sentinel.py</code>';
        } else {
            rootWarn.style.display = 'none';
        }
    }
    const failed = data.detectors.filter(d => d.error && d.status !== 'running');
    const errBox = document.getElementById('detector-errors');
    if (errBox) {
        if (failed.length && data.running_as_root !== false) {
            errBox.style.display = 'block';
            errBox.innerHTML = failed.map(d =>
                `<div class="det-err"><b>${escapeHtml(d.name.toUpperCase())}</b> — ${escapeHtml(d.error)}</div>`
            ).join('');
        } else {
            errBox.style.display = 'none';
        }
    }
}
function formatUptime(s) {
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s/60)}m`;
    if (s < 86400) return `${Math.floor(s/3600)}h${Math.floor((s%3600)/60)}m`;
    return `${Math.floor(s/86400)}d`;
}
function refreshHealth() {
    fetch('/api/health').then(r=>r.json()).then(renderHealth).catch(e=>console.error(e));
}
function renderTimeline(data) {
    const ctx = document.getElementById('timelineChart');
    if (!ctx) return;
    const order = ['process','module','file','network','syscall'];
    const datasets = order.map(det => ({
        label: det.toUpperCase(),
        data: data.series[det] || [],
        borderColor: TIMELINE_COLORS[det],
        backgroundColor: TIMELINE_COLORS[det] + '33',
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 4,
        tension: 0.3,
        fill: true,
    }));
    if (timelineChart) {
        timelineChart.data.labels = data.labels;
        timelineChart.data.datasets.forEach((ds, i) => { ds.data = datasets[i].data; });
        timelineChart.update('none');
    } else {
        timelineChart = new Chart(ctx.getContext('2d'), {
            type: 'line',
            data: { labels: data.labels, datasets: datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: { labels: { color: '#00d9ff', boxWidth: 12, font: { family: 'JetBrains Mono', size: 11 } } },
                    tooltip: { titleFont: { family: 'JetBrains Mono' }, bodyFont: { family: 'JetBrains Mono' } }
                },
                scales: {
                    y: { stacked: true, beginAtZero: true, grid: { color: 'rgba(0,217,255,0.1)' }, ticks: { color: '#00d9ff', precision: 0, font: { family: 'JetBrains Mono', size: 10 } } },
                    x: { stacked: true, grid: { color: 'rgba(0,217,255,0.05)' }, ticks: { color: '#6c93a4', maxTicksLimit: 12, font: { family: 'JetBrains Mono', size: 10 } } }
                }
            }
        });
    }
    const note = document.getElementById('timeline-note');
    if (note) note.textContent = data.truncated ? '⚠️ in-memory buffer full — older alerts dropped' : '';
}
function refreshTimeline() {
    const mins = document.getElementById('timeline-range').value;
    const bucket = mins <= 15 ? 30 : (mins <= 60 ? 60 : 300);
    fetch(`/api/timeline?minutes=${mins}&bucket=${bucket}`)
        .then(r=>r.json()).then(renderTimeline).catch(e=>console.error(e));
}
function renderCorrelations(data) {
    const container = document.getElementById('corr-container');
    const badge = document.getElementById('corr-count');
    if (badge) badge.innerText = data.count;
    const statEl = document.getElementById('correlated-threats');
    if (statEl) statEl.innerText = data.count;
    if (!container) return;
    if (!data.correlations.length) {
        container.innerHTML = '<div class="no-alerts">🔒 No correlated findings — no two detectors have agreed within a rule window</div>';
        return;
    }
    let html = '';
    for (let i = data.correlations.length - 1; i >= 0; i--) {
        const c = data.correlations[i];
        const band = c.severity === 'CRITICAL' ? '' : ' sev-high-band';
        html += `<div class="corr-item${band}">`
             +  `<div class="corr-head">`
             +    `<span class="sev-badge sev-${c.severity}">${c.severity}</span>`
             +    `<span class="corr-title">${escapeHtml(c.title)}</span>`
             +    `<span class="corr-rule">${escapeHtml(c.rule)}</span>`
             +    `<span class="corr-time">${escapeHtml(c.time)}</span>`
             +  `</div>`
             +  `<div class="corr-explain">${escapeHtml(c.explain)}</div>`;
        if (c.contributors.length) {
            html += `<div class="corr-contrib-label">Contributing evidence</div>`;
            for (const ct of c.contributors) {
                html += `<div class="corr-contrib"><b>${escapeHtml(ct.detector.toUpperCase())}</b> · ${escapeHtml(ct.time)} · ${escapeHtml(ct.type)} — ${escapeHtml(ct.details)}</div>`;
            }
        }
        html += `</div>`;
    }
    container.innerHTML = html;
}
function refreshCorrelations() {
    fetch('/api/correlations').then(r=>r.json()).then(renderCorrelations).catch(e=>console.error(e));
}
function updateDashboard(data) {
    for (let detector in data.counts) {
        const el = document.getElementById(`stat-${detector}`);
        if (el) el.innerText = data.counts[detector];
        const miniEl = document.getElementById(`mini-${detector}`);
        if (miniEl) miniEl.innerText = data.counts[detector];
    }
    const total = Object.values(data.counts).reduce((a,b)=>a+b,0);
    const critical = data.severity_counts.CRITICAL;
    const high = data.severity_counts.HIGH;
    const medium = data.severity_counts.MEDIUM;
    document.getElementById('total-threats').innerText = total;
    document.getElementById('critical-threats').innerText = critical;
    document.getElementById('high-threats').innerText = high;
    document.getElementById('medium-threats').innerText = medium;
    const fr = document.getElementById('filter-result');
    if (fr) {
        const grand = Object.values(data.total_counts).reduce((a,b)=>a+b,0);
        if (data.filtered) {
            fr.textContent = `Showing ${total} of ${grand} alerts matching the current filter.`;
            fr.className = 'filter-result active';
        } else {
            fr.textContent = `Showing all ${grand} alerts.`;
            fr.className = 'filter-result';
        }
    }
    const barCtx = document.getElementById('alertChart').getContext('2d');
    if (alertChart) {
        alertChart.data.datasets[0].data = [data.counts.process, data.counts.module, data.counts.file, data.counts.network, data.counts.syscall];
        alertChart.update();
    } else {
        alertChart = new Chart(barCtx, {
            type: 'bar',
            data: { labels: ['PROCESS', 'MODULE', 'FILE', 'NETWORK', 'SYSCALL'], datasets: [{ label: 'Alert Count', data: [0,0,0,0,0], backgroundColor: '#00d9ff', borderRadius: 8, barPercentage: 0.6 }] },
            options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { labels: { color: '#00d9ff', font: { family: 'JetBrains Mono' } } } }, scales: { y: { grid: { color: 'rgba(0,217,255,0.1)' }, ticks: { color: '#00d9ff' } }, x: { ticks: { color: '#00d9ff', font: { family: 'JetBrains Mono' } } } } }
        });
    }
    const pieCtx = document.getElementById('severityChart').getContext('2d');
    if (severityChart) {
        severityChart.data.datasets[0].data = [critical, high, medium];
        severityChart.update();
    } else {
        severityChart = new Chart(pieCtx, {
            type: 'doughnut',
            data: { labels: ['Critical (Network/Syscall)', 'High (Process/Module)', 'Medium (File)'], datasets: [{ data: [0,0,0], backgroundColor: ['#ff0000', '#ff8c00', '#ffdd44'], borderWidth: 0 }] },
            options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { labels: { color: '#00d9ff', font: { family: 'JetBrains Mono' } } } } }
        });
    }
    for (let detector of ['process', 'module', 'file', 'network', 'syscall']) {
        const container = document.getElementById(`alerts-${detector}`);
        const alerts = data.alerts[detector];
        if (container) {
            if (alerts.length === 0) {
                container.innerHTML = data.filtered
                    ? '<div class="no-alerts">🔍 No alerts match the current filter</div>'
                    : '<div class="no-alerts">🔒 No threats detected</div>';
            } else {
                let html = '';
                for (let i = alerts.length-1; i >= 0; i--) {
                    const a = alerts[i];
                    const sev = a.severity || 'MEDIUM';
                    const tags = (a.correlated || []).map(r => `<span class="corr-tag">🔗 ${escapeHtml(r)}</span>`).join('');
                    html += `<div class="alert-item"><div class="alert-time">⚠️ ${escapeHtml(a.time)}</div>`
                         +  `<div class="alert-message">🚨 <span class="sev-badge sev-${sev}">${sev}</span>`
                         +  `<span class="alert-badge">${escapeHtml(a.type)}</span> ${escapeHtml(a.details)}${tags}</div></div>`;
                }
                container.innerHTML = html;
            }
        }
    }
}
function escapeHtml(text) { return String(text == null ? '' : text).replace(/[&<>"]/g, function(m){if(m==='&') return '&amp;'; if(m==='<') return '&lt;'; if(m==='>') return '&gt;'; if(m==='"') return '&quot;'; return m;}); }
function refresh() {
    const qs = filterQueryString();
    fetch('/api/alerts' + (qs ? '?' + qs : ''))
        .then(r=>r.json()).then(data=>updateDashboard(data)).catch(e=>console.error(e));
}
function refreshAll() { refresh(); refreshHealth(); refreshCorrelations(); refreshTimeline(); }
setInterval(refresh, 2000);
setInterval(refreshHealth, 5000);
setInterval(refreshCorrelations, 5000);
setInterval(refreshTimeline, 10000);
window.addEventListener('DOMContentLoaded', refreshAll);
