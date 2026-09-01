/**
 * dashboard.js - SIEM Mini Platform Frontend Logic
 *
 * All data displayed here comes from the FastAPI backend.
 * Nothing is hardcoded - every number, chart, and table row
 * is fetched from real API endpoints backed by the SQLite database.
 */

const API = '';  // Same origin - FastAPI serves both API and frontend

// ── Chart instances (kept so we can destroy/recreate on refresh) ──────────────
let charts = {};

// ── In-memory data cache ──────────────────────────────────────────────────────
let allAlerts = [];
let allEvents = [];

// ═══════════════════════════════════════════════════════════════════════════════
// INITIALISATION
// ═══════════════════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  updateClock();
  setInterval(updateClock, 1000);
  refreshDashboard();
});

function updateClock() {
  const el = document.getElementById('headerTime');
  if (el) el.textContent = new Date().toUTCString().replace('GMT', 'UTC');
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOAST NOTIFICATIONS
// ═══════════════════════════════════════════════════════════════════════════════
let toastTimer = null;

function showToast(message, type = 'success') {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.className = `toast ${type}`;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = 'toast hidden'; }, 4000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// API HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
async function apiFetch(path, options = {}) {
  const res = await fetch(API + path, options);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOOLBAR ACTIONS
// ═══════════════════════════════════════════════════════════════════════════════
async function collectLogs() {
  setButtonsDisabled(true);
  showToast('Collecting logs...', 'warning');
  try {
    const data = await apiFetch('/api/collect', { method: 'POST' });
    showToast(
      `✓ Collected ${data.events_collected} events from ${data.files_processed} files.`,
      'success'
    );
    await refreshDashboard();
  } catch (e) {
    showToast(`✗ Collection failed: ${e.message}`, 'error');
  } finally {
    setButtonsDisabled(false);
  }
}

async function runDetection() {
  setButtonsDisabled(true);
  showToast('Running detection rules...', 'warning');
  try {
    const data = await apiFetch('/api/detect', { method: 'POST' });
    showToast(
      `✓ ${data.rules_executed} rules executed. ${data.alerts_created} alerts created, ${data.alerts_updated} updated.`,
      'success'
    );
    await refreshDashboard();
  } catch (e) {
    showToast(`✗ Detection failed: ${e.message}`, 'error');
  } finally {
    setButtonsDisabled(false);
  }
}

async function refreshDashboard() {
  try {
    const [stats, alerts, events] = await Promise.all([
      apiFetch('/api/stats'),
      apiFetch('/api/alerts'),
      apiFetch('/api/events'),
    ]);
    allAlerts = alerts;
    allEvents = events;
    renderStats(stats);
    renderCharts(stats);
    renderAlertsTable(alerts);
    renderEventsTable(events);
    document.getElementById('lastUpdated').textContent =
      'Last updated: ' + new Date().toLocaleTimeString();
  } catch (e) {
    showToast(`✗ Refresh failed: ${e.message}`, 'error');
  }
}

function confirmReset() {
  if (!confirm('⚠ This will permanently delete ALL events and alerts.\n\nAre you sure you want to reset the database?')) return;
  resetDatabase();
}

async function resetDatabase() {
  setButtonsDisabled(true);
  try {
    await apiFetch('/api/reset', { method: 'POST' });
    showToast('✓ Database reset. Ready for fresh demonstration.', 'success');
    await refreshDashboard();
  } catch (e) {
    showToast(`✗ Reset failed: ${e.message}`, 'error');
  } finally {
    setButtonsDisabled(false);
  }
}

function setButtonsDisabled(disabled) {
  document.querySelectorAll('.toolbar .btn').forEach(b => b.disabled = disabled);
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATS CARDS
// ═══════════════════════════════════════════════════════════════════════════════
function renderStats(stats) {
  setText('statTotalEvents', stats.total_events);
  setText('statTotalAlerts', stats.total_alerts);
  setText('statCritical',    stats.critical_alerts);
  setText('statHigh',        stats.high_alerts);
  setText('statMedium',      stats.medium_alerts);
  setText('statOpen',        stats.open_alerts);
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val ?? '0';
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHARTS  (Chart.js)
// ═══════════════════════════════════════════════════════════════════════════════
const CHART_DEFAULTS = {
  plugins: { legend: { labels: { color: '#8899b4', font: { size: 11 } } } },
  scales: {
    x: { ticks: { color: '#8899b4', font: { size: 10 } }, grid: { color: '#1e2d4a' } },
    y: { ticks: { color: '#8899b4', font: { size: 10 } }, grid: { color: '#1e2d4a' }, beginAtZero: true },
  },
};

function destroyChart(id) {
  if (charts[id]) { charts[id].destroy(); delete charts[id]; }
}

function renderCharts(stats) {
  renderSeverityChart(stats);
  renderSourceChart(stats);
  renderAlertTypesChart(stats);
  renderTimelineChart();
}

function renderSeverityChart(stats) {
  destroyChart('severity');
  const ctx = document.getElementById('chartSeverity').getContext('2d');
  charts['severity'] = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [stats.critical_alerts, stats.high_alerts, stats.medium_alerts, stats.low_alerts],
        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e'],
        borderColor: '#131d35',
        borderWidth: 2,
      }],
    },
    options: {
      plugins: { legend: { position: 'right', labels: { color: '#8899b4', font: { size: 11 }, padding: 12 } } },
      cutout: '65%',
    },
  });
}

function renderSourceChart(stats) {
  destroyChart('source');
  const src = stats.event_count_by_source || {};
  const ctx = document.getElementById('chartSource').getContext('2d');
  charts['source'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: Object.keys(src).map(k => k.charAt(0).toUpperCase() + k.slice(1)),
      datasets: [{
        label: 'Events',
        data: Object.values(src),
        backgroundColor: ['#3b82f6', '#8b5cf6', '#06b6d4'],
        borderRadius: 4,
      }],
    },
    options: { ...CHART_DEFAULTS, plugins: { legend: { display: false } } },
  });
}

function renderAlertTypesChart(stats) {
  destroyChart('alertTypes');
  const types = stats.alert_count_by_type || {};
  const labelMap = {
    BRUTE_FORCE_ATTACK: 'Brute Force',
    PORT_SCAN_DETECTED: 'Port Scan',
    REPEATED_AUTH_FAILURE: 'Repeated Auth Fail',
    UNAUTHORIZED_ADMIN_ACCESS: 'Admin Access',
    POSSIBLE_ACCOUNT_COMPROMISE: 'Acct Compromise',
  };
  // Build ordered labels/data so chart always shows all 5 rule types
  const ORDER = ['BRUTE_FORCE_ATTACK','PORT_SCAN_DETECTED','REPEATED_AUTH_FAILURE','UNAUTHORIZED_ADMIN_ACCESS','POSSIBLE_ACCOUNT_COMPROMISE'];
  const labels = ORDER.map(k => labelMap[k]);
  const data   = ORDER.map(k => types[k] || 0);
  const ctx = document.getElementById('chartAlertTypes').getContext('2d');
  charts['alertTypes'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Alerts',
        data,
        backgroundColor: ['#ef4444','#f97316','#eab308','#f97316','#dc2626'],
        borderRadius: 4,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          ticks: { color: '#8899b4', font: { size: 10 }, stepSize: 1 },
          grid: { color: '#1e2d4a' },
          beginAtZero: true,
        },
        y: {
          ticks: { color: '#8899b4', font: { size: 10 } },
          grid: { color: '#1e2d4a' },
        },
      },
    },
  });
}

function renderTimelineChart() {
  destroyChart('timeline');
  // Group events by minute so all sample log activity (10:00-10:11) shows as distinct points
  const minuteCounts = {};
  allEvents.forEach(e => {
    // Normalise both "2026-08-24T10:01:15" and "2026-08-24 10:01:15" to "HH:MM"
    const ts = e.timestamp.replace('T', ' ');
    const minute = ts.substring(11, 16);  // "HH:MM"
    minuteCounts[minute] = (minuteCounts[minute] || 0) + 1;
  });
  const sortedMinutes = Object.keys(minuteCounts).sort();
  const ctx = document.getElementById('chartTimeline').getContext('2d');
  charts['timeline'] = new Chart(ctx, {
    type: 'line',
    data: {
      labels: sortedMinutes,
      datasets: [{
        label: 'Events',
        data: sortedMinutes.map(m => minuteCounts[m]),
        borderColor: '#06b6d4',
        backgroundColor: 'rgba(6,182,212,0.1)',
        fill: true,
        tension: 0.3,
        pointRadius: 4,
        pointBackgroundColor: '#06b6d4',
      }],
    },
    options: {
      ...CHART_DEFAULTS,
      scales: {
        x: { ticks: { color: '#8899b4', font: { size: 10 }, maxRotation: 45 }, grid: { color: '#1e2d4a' } },
        y: { ticks: { color: '#8899b4', font: { size: 10 } }, grid: { color: '#1e2d4a' }, beginAtZero: true },
      },
    },
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ALERTS TABLE
// ═══════════════════════════════════════════════════════════════════════════════
function renderAlertsTable(alerts) {
  const tbody = document.getElementById('alertsBody');
  if (!alerts.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-row">No alerts generated yet. Click "Run Detection".</td></tr>';
    return;
  }
  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td class="mono">#${a.id}</td>
      <td class="mono">${formatTime(a.last_seen)}</td>
      <td>${formatAlertType(a.alert_type)}</td>
      <td class="mono">${esc(a.source_ip || '—')}</td>
      <td><span class="badge badge-${a.severity}">${a.severity}</span></td>
      <td>${a.event_count}</td>
      <td><span class="status-${a.status}">${a.status.replace('_', ' ')}</span></td>
      <td>
        <div class="actions">
          <button class="btn btn-secondary btn-sm" onclick="viewAlert(${a.id})">View</button>
          ${a.status === 'OPEN' ? `<button class="btn btn-warning btn-sm" onclick="quickStatus(${a.id},'INVESTIGATING')">Investigate</button>` : ''}
          ${a.status !== 'RESOLVED' && a.status !== 'FALSE_POSITIVE' ? `<button class="btn btn-primary btn-sm" onclick="quickStatus(${a.id},'RESOLVED')">Resolve</button>` : ''}
          ${a.status === 'OPEN' ? `<button class="btn btn-danger btn-sm" onclick="quickStatus(${a.id},'FALSE_POSITIVE')">FP</button>` : ''}
        </div>
      </td>
    </tr>
  `).join('');
}

function filterAlerts() {
  const sev = document.getElementById('filterAlertSeverity').value;
  const st  = document.getElementById('filterAlertStatus').value;
  const filtered = allAlerts.filter(a =>
    (!sev || a.severity === sev) &&
    (!st  || a.status === st)
  );
  renderAlertsTable(filtered);
}

function formatAlertType(t) {
  const map = {
    BRUTE_FORCE_ATTACK: '🔨 Brute Force Attack',
    PORT_SCAN_DETECTED: '🔍 Port Scan Detected',
    REPEATED_AUTH_FAILURE: '🔑 Repeated Auth Failure',
    UNAUTHORIZED_ADMIN_ACCESS: '🚫 Unauthorized Admin Access',
    POSSIBLE_ACCOUNT_COMPROMISE: '💀 Account Compromise',
  };
  return map[t] || t;
}

// ═══════════════════════════════════════════════════════════════════════════════
// EVENTS TABLE
// ═══════════════════════════════════════════════════════════════════════════════
function renderEventsTable(events) {
  const tbody = document.getElementById('eventsBody');
  if (!events.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-row">No events collected yet. Click "Collect Logs".</td></tr>';
    return;
  }
  tbody.innerHTML = events.map(e => `
    <tr>
      <td class="mono">${formatTime(e.timestamp)}</td>
      <td><span class="source-tag source-${e.source}">${e.source}</span></td>
      <td>${esc(e.event_type)}</td>
      <td class="mono">${esc(e.source_ip || '—')}</td>
      <td>${esc(e.username || '—')}</td>
      <td>${esc(e.status || '—')}</td>
      <td><span class="badge badge-${e.severity}">${e.severity}</span></td>
    </tr>
  `).join('');
}

function filterEvents() {
  const src  = document.getElementById('filterSource').value;
  const type = document.getElementById('filterEventType').value;
  const sev  = document.getElementById('filterSeverity').value;
  const ip   = document.getElementById('filterIP').value.trim().toLowerCase();

  const filtered = allEvents.filter(e =>
    (!src  || e.source === src) &&
    (!type || e.event_type === type) &&
    (!sev  || e.severity === sev) &&
    (!ip   || (e.source_ip || '').toLowerCase().includes(ip))
  );
  renderEventsTable(filtered);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ALERT DETAIL MODAL
// ═══════════════════════════════════════════════════════════════════════════════
async function viewAlert(alertId) {
  try {
    const [alert, relatedEvents] = await Promise.all([
      apiFetch(`/api/alerts/${alertId}`),
      apiFetch(`/api/alerts/${alertId}/events`),
    ]);
    showAlertModal(alert, relatedEvents);
  } catch (e) {
    showToast(`✗ Could not load alert: ${e.message}`, 'error');
  }
}

function showAlertModal(alert, relatedEvents) {
  document.getElementById('modalTitle').textContent = `Alert #${alert.id} — ${formatAlertType(alert.alert_type)}`;

  const eventsHtml = relatedEvents.length
    ? relatedEvents.map(e => `
        <tr>
          <td class="mono">${formatTime(e.timestamp)}</td>
          <td><span class="source-tag source-${e.source}">${e.source}</span></td>
          <td>${esc(e.event_type)}</td>
          <td class="mono">${esc(e.source_ip || '—')}</td>
          <td><span class="badge badge-${e.severity}">${e.severity}</span></td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="toggleRawLog('raw-${e.id}')">Raw Log</button>
            <div id="raw-${e.id}" class="raw-log" style="display:none">${esc(e.raw_log)}</div>
          </td>
        </tr>
      `).join('')
    : '<tr><td colspan="6" class="empty-row">No related events found in time window.</td></tr>';

  document.getElementById('modalBody').innerHTML = `
    <div class="detail-grid">
      <div class="detail-item"><label>ALERT ID</label><span>#${alert.id}</span></div>
      <div class="detail-item"><label>RULE ID</label><span class="mono">${esc(alert.rule_id)}</span></div>
      <div class="detail-item"><label>SEVERITY</label><span><span class="badge badge-${alert.severity}">${alert.severity}</span></span></div>
      <div class="detail-item"><label>STATUS</label><span class="status-${alert.status}">${alert.status.replace('_', ' ')}</span></div>
      <div class="detail-item"><label>SOURCE IP</label><span class="mono">${esc(alert.source_ip || '—')}</span></div>
      <div class="detail-item"><label>EVENT COUNT</label><span>${alert.event_count}</span></div>
      <div class="detail-item"><label>FIRST SEEN</label><span class="mono">${formatTime(alert.first_seen)}</span></div>
      <div class="detail-item"><label>LAST SEEN</label><span class="mono">${formatTime(alert.last_seen)}</span></div>
    </div>

    <div class="section-title">DESCRIPTION</div>
    <div class="detail-description">${esc(alert.description)}</div>

    <div class="section-title">RELATED EVENTS</div>
    <div class="table-wrap" style="margin-bottom:16px">
      <table>
        <thead>
          <tr>
            <th>TIME</th><th>SOURCE</th><th>TYPE</th><th>SOURCE IP</th><th>SEVERITY</th><th>RAW LOG</th>
          </tr>
        </thead>
        <tbody>${eventsHtml}</tbody>
      </table>
    </div>

    <div class="status-update-row">
      <label>UPDATE STATUS:</label>
      <select id="modalStatusSelect">
        <option value="OPEN"           ${alert.status==='OPEN'?'selected':''}>OPEN</option>
        <option value="INVESTIGATING"  ${alert.status==='INVESTIGATING'?'selected':''}>INVESTIGATING</option>
        <option value="RESOLVED"       ${alert.status==='RESOLVED'?'selected':''}>RESOLVED</option>
        <option value="FALSE_POSITIVE" ${alert.status==='FALSE_POSITIVE'?'selected':''}>FALSE POSITIVE</option>
      </select>
      <button class="btn btn-primary btn-sm" onclick="updateStatusFromModal(${alert.id})">Update</button>
    </div>
  `;

  document.getElementById('alertModal').classList.remove('hidden');
}

function toggleRawLog(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

function closeModal() {
  document.getElementById('alertModal').classList.add('hidden');
}

// Close modal on overlay click
document.getElementById('alertModal').addEventListener('click', function(e) {
  if (e.target === this) closeModal();
});

async function updateStatusFromModal(alertId) {
  const newStatus = document.getElementById('modalStatusSelect').value;
  await quickStatus(alertId, newStatus);
  closeModal();
}

async function quickStatus(alertId, newStatus) {
  try {
    await apiFetch(`/api/alerts/${alertId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus }),
    });
    showToast(`✓ Alert #${alertId} → ${newStatus.replace('_', ' ')}`, 'success');
    await refreshDashboard();
  } catch (e) {
    showToast(`✗ Status update failed: ${e.message}`, 'error');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/** Escape HTML to prevent XSS when rendering raw log content */
function esc(str) {
  if (str == null) return '—';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatTime(isoStr) {
  if (!isoStr) return '—';
  // Handle both "2026-08-24T10:01:15" and "2026-08-24 10:01:15" formats
  return isoStr.replace('T', ' ').substring(0, 19);
}
