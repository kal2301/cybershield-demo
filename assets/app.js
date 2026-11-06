'use strict';
/* CyberShield (demo statis) - logika antarmuka; data lewat assets/mock-api.js */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const num = v => Number(v || 0).toLocaleString('en-US');
const PORT_NAMES = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 8080: 'HTTP-Alt' };
const portLabel = p => (PORT_NAMES[p] ? `${p} (${PORT_NAMES[p]})` : String(p));
const badge = s => (s === 'ALLOWED' ? '<span class="badge ok">Diizinkan</span>' : '<span class="badge bad">Diblokir</span>');
const PAGES = { dashboard: 'Dashboard', firewall: 'Manajemen Aturan Firewall', traffic: 'Simulasi Traffic & Serangan', logs: 'Log Keamanan', blacklist: 'Blacklist IP' };

let currentPage = 'dashboard';
let autoTimer = null;
const feed = [];
const simStats = { allowed: 0, blocked: 0 };

/* ---------------- util ---------------- */
async function api(action, { method = 'GET', body = null, params = {} } = {}) {
    // Versi statis: data diproses di browser (lihat assets/mock-api.js), tanpa PHP/MySQL
    return window.mockApi(action, { method, body, params });
}

function toast(msg, type = 'ok') {
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = msg;
    $('#toasts').appendChild(t);
    setTimeout(() => t.remove(), 3400);
}

const guard = fn => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, 'err'); } };

/* ---------------- navigasi ---------------- */
function go(page) {
    if (!PAGES[page]) page = 'dashboard';
    if (page !== 'traffic') stopAuto();
    currentPage = page;
    $$('.page').forEach(p => p.classList.toggle('active', p.id === `page-${page}`));
    $$('nav a').forEach(a => a.classList.toggle('active', a.dataset.page === page));
    $('#page-title').textContent = PAGES[page];
    refresh(false);
}

async function refresh(silent = true) {
    try {
        if (currentPage === 'dashboard') await loadDashboard();
        else if (currentPage === 'firewall') await loadRules();
        else if (currentPage === 'logs') await loadLogs();
        else if (currentPage === 'blacklist') await loadBlacklist();
        else await loadSideStats();
    } catch (e) {
        if (!silent) toast(e.message, 'err');
    }
}

async function loadSideStats() {
    const d = await api('stats');
    $('#side-rules').textContent = d.active_rules;
    $('#side-bl').textContent = d.blacklist;
}

/* ---------------- 1. dashboard ---------------- */
async function loadDashboard() {
    let d = await api('stats');
    if (d.empty) { // pertama kali dibuka: isi data simulasi awal
        await api('seed_demo', { method: 'POST' });
        d = await api('stats');
    }
    $('#st-packets').textContent = num(d.packets);
    $('#st-allowed').textContent = num(d.allowed);
    $('#st-blocked').textContent = num(d.blocked);
    $('#st-rules').textContent = num(d.active_rules);
    $('#side-rules').textContent = d.active_rules;
    $('#side-bl').textContent = d.blacklist;
    drawChart(d.chart);

    const max = Math.max(1, ...d.top_ports.map(p => +p.c));
    $('#top-ports').innerHTML = d.top_ports.length
        ? d.top_ports.map(p => `<div class="bar-row"><div class="bar-top"><span>${esc(portLabel(p.dest_port))}</span><span>${num(p.c)} blokir</span></div>
            <div class="bar"><div style="width:${(p.c / max) * 100}%"></div></div></div>`).join('')
        : '<div class="empty">Belum ada koneksi yang diblokir.</div>';

    $('#alerts').innerHTML = d.alerts.length
        ? d.alerts.map(a => `<tr><td class="mono">${esc(a.t)}</td><td class="mono">${esc(a.source_ip)}</td><td>${esc(portLabel(a.dest_port))}</td>
            <td>${esc(a.activity_type)}</td><td>${badge(a.action_taken)}</td></tr>`).join('')
        : '<tr><td colspan="5" class="empty">Belum ada peringatan.</td></tr>';
}

function shortNum(v) { return v >= 1000 ? (v / 1000).toFixed(v >= 10000 ? 0 : 1) + 'k' : String(Math.round(v)); }

function drawChart(c) {
    const cv = $('#chart');
    const dpr = window.devicePixelRatio || 1;
    const w = cv.clientWidth, h = cv.clientHeight;
    if (!w) return;
    cv.width = w * dpr; cv.height = h * dpr;
    const g = cv.getContext('2d');
    g.scale(dpr, dpr);
    const pad = { l: 46, r: 12, t: 10, b: 26 };
    const iw = w - pad.l - pad.r, ih = h - pad.t - pad.b;
    const max = Math.max(10, ...c.allowed, ...c.blocked) * 1.1;
    const x = i => pad.l + (iw * i) / (c.labels.length - 1);
    const y = v => pad.t + ih * (1 - v / max);

    g.font = '11px "Segoe UI", sans-serif';
    g.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const gy = pad.t + (ih * i) / 4;
        g.strokeStyle = '#1f2a48';
        g.beginPath(); g.moveTo(pad.l, gy); g.lineTo(w - pad.r, gy); g.stroke();
        g.fillStyle = '#7f8bb0'; g.textAlign = 'right';
        g.fillText(shortNum((max * (4 - i)) / 4), pad.l - 8, gy + 4);
    }
    const line = (arr, color) => {
        g.beginPath();
        arr.forEach((v, i) => (i ? g.lineTo(x(i), y(v)) : g.moveTo(x(i), y(v))));
        g.strokeStyle = color; g.lineWidth = 2.2; g.stroke();
        g.lineTo(x(arr.length - 1), pad.t + ih); g.lineTo(x(0), pad.t + ih); g.closePath();
        g.fillStyle = color + '22'; g.fill();
    };
    line(c.allowed, '#34d399');
    line(c.blocked, '#f87171');
    g.fillStyle = '#7f8bb0'; g.textAlign = 'center';
    c.labels.forEach((l, i) => { if (i % 2 === 0 || i === c.labels.length - 1) g.fillText(l, x(i), h - 8); });
}

/* ---------------- 2. firewall ---------------- */
async function loadRules() {
    const d = await api('rules');
    $('#rules-body').innerHTML = d.rules.length
        ? d.rules.map(r => `<tr>
            <td>${r.id}</td><td>${esc(r.rule_name)}</td><td class="mono">${esc(r.ip_address === '*' ? '* (semua)' : r.ip_address)}</td>
            <td>${+r.port === 0 ? '0 (semua)' : esc(portLabel(r.port))}</td><td>${esc(r.protocol)}</td>
            <td><span class="badge ${r.action === 'BLOCK' ? 'bad' : 'ok'}">${r.action}</span></td>
            <td><label class="switch"><input type="checkbox" data-toggle="${r.id}" ${+r.is_active ? 'checked' : ''}><span></span></label></td>
            <td><button class="btn danger btn-sm" data-del-rule="${r.id}">Hapus</button></td></tr>`).join('')
        : '<tr><td colspan="8" class="empty">Belum ada aturan.</td></tr>';
    loadSideStats().catch(() => {});
}

$('#rule-form').addEventListener('submit', guard(async e => {
    e.preventDefault();
    const body = Object.fromEntries(new FormData(e.target));
    await api('add_rule', { method: 'POST', body });
    toast('Aturan firewall ditambahkan');
    e.target.reset();
    await loadRules();
}));

$('#rules-body').addEventListener('change', guard(async e => {
    const id = e.target.dataset.toggle;
    if (!id) return;
    await api('toggle_rule', { method: 'POST', body: { id } });
    toast(e.target.checked ? 'Aturan diaktifkan' : 'Aturan dinonaktifkan');
    loadSideStats().catch(() => {});
}));

$('#rules-body').addEventListener('click', guard(async e => {
    const id = e.target.dataset.delRule;
    if (!id || !confirm('Hapus aturan ini?')) return;
    await api('delete_rule', { method: 'POST', body: { id } });
    toast('Aturan dihapus');
    await loadRules();
}));

/* ---------------- 3. simulasi ---------------- */
function renderFeed() {
    $('#feed').innerHTML = feed.length
        ? feed.map(e => `<li class="${e.status === 'ALLOWED' ? 'ok' : 'bad'}"><span class="t">${esc(e.time)}</span>
            <span class="ip">${esc(e.ip)}:${esc(e.port)}</span><span class="act">${esc(e.activity)}</span>${badge(e.status)}
            <span class="why">${esc(e.reason)}</span></li>`).join('')
        : '<li class="empty">Belum ada traffic. Jalankan simulasi di atas.</li>';
    $('#sim-allowed').textContent = num(simStats.allowed);
    $('#sim-blocked').textContent = num(simStats.blocked);
}

async function runSim(type) {
    const d = await api('simulate', { method: 'POST', body: { type } });
    const a = d.events.filter(e => e.status === 'ALLOWED').length;
    const b = d.events.length - a;
    simStats.allowed += a; simStats.blocked += b;
    d.events.slice().reverse().forEach(e => feed.unshift(e));
    feed.length = Math.min(feed.length, 40);

    const banner = $('#sim-banner');
    if (type === 'normal') {
        banner.className = 'banner ok';
        banner.textContent = `${d.label}: ${d.events.length} koneksi - ${a} diizinkan, ${b} diblokir.`;
    } else if (a > 0) {
        banner.className = 'banner warn';
        banner.textContent = `Serangan ${d.label}: ${a} dari ${d.events.length} koneksi LOLOS. Tambahkan aturan firewall atau blacklist IP penyerang!`;
    } else {
        banner.className = 'banner bad';
        banner.textContent = `Serangan ${d.label} berhasil digagalkan: ${b} koneksi diblokir.`;
    }
    const last = d.events[0];
    $('#last-status').innerHTML = `${esc(last.ip)}:${esc(last.port)} ${badge(last.status)}`;
    renderFeed();
}

$$('[data-sim]').forEach(btn => btn.addEventListener('click', guard(async () => {
    btn.disabled = true;
    try { await runSim(btn.dataset.sim); } finally { btn.disabled = false; }
})));

function stopAuto() {
    if (!autoTimer) return;
    clearInterval(autoTimer);
    autoTimer = null;
    $('#btn-auto').innerHTML = '&#8635; Auto Traffic: OFF';
}

$('#btn-auto').addEventListener('click', () => {
    if (autoTimer) return stopAuto();
    $('#btn-auto').innerHTML = '&#8635; Auto Traffic: ON';
    autoTimer = setInterval(() => runSim('normal').catch(e => { toast(e.message, 'err'); stopAuto(); }), 2500);
});

$('#test-form').addEventListener('submit', guard(async e => {
    e.preventDefault();
    const body = Object.fromEntries(new FormData(e.target));
    const d = await api('test_connection', { method: 'POST', body });
    const box = $('#test-result');
    box.className = `result ${d.status === 'ALLOWED' ? 'ok' : 'bad'}`;
    box.innerHTML = `<b>${d.status === 'ALLOWED' ? 'KONEKSI DIIZINKAN' : 'KONEKSI DIBLOKIR'}</b><br>
        ${esc(d.ip)}:${esc(d.port)}<br><small>${esc(d.reason)} - tercatat di Log Keamanan</small>`;
}));

/* ---------------- 4. log ---------------- */
async function loadLogs() {
    const d = await api('logs', { params: { status: $('#log-status').value, q: $('#log-q').value.trim(), limit: 150 } });
    $('#logs-body').innerHTML = d.logs.length
        ? d.logs.map(l => `<tr><td class="mono">${esc(l.logged_at)}</td><td class="mono">${esc(l.source_ip)}</td><td>${esc(portLabel(l.dest_port))}</td>
            <td>${esc(l.activity_type)}</td><td>${num(l.packets)}</td><td>${badge(l.action_taken)}</td><td>${esc(l.detail)}</td></tr>`).join('')
        : '<tr><td colspan="7" class="empty">Tidak ada log yang cocok.</td></tr>';
}

let qTimer;
$('#log-status').addEventListener('change', () => refresh(false));
$('#log-q').addEventListener('input', () => { clearTimeout(qTimer); qTimer = setTimeout(() => refresh(false), 300); });
$('#btn-seed').addEventListener('click', guard(async () => {
    const d = await api('seed_demo', { method: 'POST' });
    toast(`${d.inserted} log simulasi ditambahkan`);
    await loadLogs();
}));
$('#btn-clear').addEventListener('click', guard(async () => {
    if (!confirm('Hapus SEMUA log keamanan?')) return;
    await api('clear_logs', { method: 'POST' });
    toast('Log dihapus');
    await loadLogs();
}));

/* ---------------- 5. blacklist ---------------- */
async function loadBlacklist() {
    const d = await api('blacklist');
    $('#bl-count').textContent = `${d.items.length} IP terdaftar`;
    $('#bl-body').innerHTML = d.items.length
        ? d.items.map(i => `<tr><td>${i.id}</td><td class="mono">${esc(i.ip_address)}</td><td>${esc(i.reason)}</td><td>${esc(i.added_at)}</td>
            <td><button class="btn danger btn-sm" data-del-bl="${i.id}">Hapus</button></td></tr>`).join('')
        : '<tr><td colspan="5" class="empty">Blacklist kosong.</td></tr>';
    loadSideStats().catch(() => {});
}

$('#bl-form').addEventListener('submit', guard(async e => {
    e.preventDefault();
    await api('add_blacklist', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) });
    toast('IP ditambahkan ke blacklist');
    e.target.reset();
    await loadBlacklist();
}));

$('#bl-body').addEventListener('click', guard(async e => {
    const id = e.target.dataset.delBl;
    if (!id || !confirm('Hapus IP ini dari blacklist?')) return;
    await api('delete_blacklist', { method: 'POST', body: { id } });
    toast('IP dihapus dari blacklist');
    await loadBlacklist();
}));

/* ---------------- start ---------------- */
window.addEventListener('hashchange', () => go(location.hash.slice(1)));
window.addEventListener('resize', () => { if (currentPage === 'dashboard') refresh(); });
setInterval(() => { $('#clock').textContent = new Date().toLocaleString('id-ID'); }, 1000);
setInterval(() => { if (currentPage === 'dashboard') refresh(); }, 5000);
renderFeed();
go(location.hash.slice(1));
