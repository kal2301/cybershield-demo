'use strict';
/*
 * CyberShield - API tiruan untuk demo statis (GitHub Pages).
 * Menggantikan api.php + MySQL: data disimpan di localStorage browser.
 * Logika mesin firewall sama persis dengan versi PHP.
 */
(function () {
    const KEY = 'cybershield_demo_v1';
    const MAX_LOGS = 1500;
    const ATTACKERS = ['185.220.101.34', '45.155.205.233', '103.77.192.18', '198.51.100.77', '203.0.113.45', '91.240.118.172'];
    const PORT_NAMES = {
        21: 'Akses FTP', 22: 'Sesi SSH', 23: 'Akses Telnet', 25: 'Kirim Email SMTP', 53: 'Query DNS', 80: 'Akses HTTP',
        443: 'Akses HTTPS', 445: 'Akses SMB', 3306: 'Akses MySQL', 3389: 'Akses Remote Desktop', 8080: 'Akses Web Proxy',
    };
    const SCEN = {
        normal:     { label: 'Traffic Normal',  count: [8, 12], ports: [80, 443, 443, 53, 8080, 22], pkts: [1, 40],     src: 'lan',      activity: null },
        portscan:   { label: 'Port Scan',       count: [8, 10], ports: [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080], pkts: [20, 60], src: 'attacker', activity: 'Port Scan' },
        bruteforce: { label: 'Brute Force SSH', count: [6, 9],  ports: [22],       pkts: [40, 120],   src: 'attacker', activity: 'Brute Force SSH' },
        synflood:   { label: 'DDoS SYN Flood',  count: [6, 9],  ports: [80, 443],  pkts: [500, 2000], src: 'botnet',   activity: 'DDoS SYN Flood' },
        sqli:       { label: 'SQL Injection',   count: [5, 8],  ports: [80, 3306], pkts: [10, 50],    src: 'attacker', activity: 'SQL Injection' },
    };

    const rnd = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
    const pick = a => a[Math.floor(Math.random() * a.length)];
    const p2 = n => String(n).padStart(2, '0');
    const hms = ms => { const d = new Date(ms); return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`; };
    const ymd = ms => { const d = new Date(ms); return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}`; };
    const fail = msg => { throw new Error(msg); };

    function initial() {
        const now = Date.now();
        const r = (id, rule_name, ip_address, port, action, is_active) =>
            ({ id, rule_name, ip_address, port, protocol: 'TCP', action, is_active, created_at: ymd(now) });
        return {
            rules: [
                r(1, 'Blokir Telnet', '*', 23, 'BLOCK', 1), r(2, 'Blokir Remote Desktop', '*', 3389, 'BLOCK', 1),
                r(3, 'Blokir SMB', '*', 445, 'BLOCK', 1), r(4, 'Izinkan HTTPS', '*', 443, 'ALLOW', 1),
                r(5, 'Izinkan HTTP', '*', 80, 'ALLOW', 1), r(6, 'Izinkan SSH admin', '192.168.1.10', 22, 'ALLOW', 1),
                r(7, 'Blokir MySQL dari luar', '*', 3306, 'BLOCK', 0),
            ],
            blacklist: [
                { id: 1, ip_address: '185.220.101.34', reason: 'Sumber brute force SSH berulang', t: now },
                { id: 2, ip_address: '45.155.205.233', reason: 'Terdeteksi port scanning massal', t: now },
            ],
            logs: [], rid: 8, bid: 3, lid: 1,
        };
    }

    let db;
    function load() {
        if (db) return;
        try { db = JSON.parse(localStorage.getItem(KEY)); } catch (e) { db = null; }
        if (!db || !Array.isArray(db.rules)) db = initial();
    }
    function save() { try { localStorage.setItem(KEY, JSON.stringify(db)); } catch (e) { /* penyimpanan penuh/diblokir: data tetap di memori */ } }

    const validIp = ip => {
        const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
        if (m) return m.slice(1).every(n => +n <= 255);
        return /^[0-9a-f:]+$/i.test(ip) && (ip.match(/:/g) || []).length >= 2;
    };
    const validPort = (v, min) => /^\d+$/.test(String(v).trim()) && +v >= min && +v <= 65535;

    /* ---- mesin firewall: blacklist -> aturan aktif (BLOCK dulu) -> default izinkan ---- */
    function evaluate(ip, port) {
        if (db.blacklist.some(b => b.ip_address === ip)) return ['BLOCKED', 'IP ada di blacklist'];
        const hit = db.rules
            .filter(r => +r.is_active === 1 && (r.ip_address === '*' || r.ip_address === ip) && (+r.port === 0 || +r.port === port))
            .sort((a, b) => (b.action === 'BLOCK') - (a.action === 'BLOCK') || a.id - b.id)[0];
        if (hit) return [hit.action === 'BLOCK' ? 'BLOCKED' : 'ALLOWED', `Aturan #${hit.id}: ${hit.rule_name}`];
        return ['ALLOWED', 'Kebijakan default: izinkan'];
    }

    function logEvent(ip, port, activity, action, packets, detail, secAgo = 0) {
        db.logs.push({ id: db.lid++, t: Date.now() - secAgo * 1000, ip, port, activity, action, packets, detail });
        if (db.logs.length > MAX_LOGS) db.logs.splice(0, db.logs.length - MAX_LOGS);
    }

    function runSim(type, secAgo = 0) {
        const sc = SCEN[type];
        if (!sc) fail('Jenis simulasi tidak dikenal');
        const n = rnd(sc.count[0], sc.count[1]);
        const attacker = pick(ATTACKERS);
        const events = [];
        for (let i = 0; i < n; i++) {
            const ip = sc.src === 'lan' ? `192.168.1.${rnd(2, 60)}` : sc.src === 'botnet' ? pick(ATTACKERS) : attacker;
            const port = pick(sc.ports);
            const pk = rnd(sc.pkts[0], sc.pkts[1]);
            const activity = sc.activity || PORT_NAMES[port] || 'Koneksi Umum';
            const [verdict, why] = evaluate(ip, port);
            const offset = secAgo + (n - i);
            logEvent(ip, port, activity, verdict, pk, why, offset);
            events.push({ time: hms(Date.now() - offset * 1000), ip, port, activity, status: verdict, reason: why, packets: pk });
        }
        return { ok: true, label: sc.label, type, events: events.reverse() };
    }

    function seedDemo() {
        const types = ['normal', 'normal', 'normal', 'portscan', 'bruteforce', 'synflood', 'sqli'];
        let count = 0;
        for (let i = 0; i < 45; i++) count += runSim(pick(types), rnd(30, 3500)).events.length;
        return count;
    }

    function stats() {
        const now = Date.now();
        let packets = 0, allowed = 0, blocked = 0;
        const A = Array(12).fill(0), B = Array(12).fill(0), ports = {};
        for (const l of db.logs) {
            packets += l.packets;
            if (l.action === 'ALLOWED') allowed++; else { blocked++; ports[l.port] = (ports[l.port] || 0) + 1; }
            const mins = Math.floor((now - l.t) / 60000);
            if (mins < 60) {
                const idx = 11 - Math.floor(mins / 5);
                if (idx >= 0 && idx < 12) (l.action === 'ALLOWED' ? A : B)[idx] += l.packets;
            }
        }
        const labels = [];
        for (let i = 11; i >= 0; i--) labels.push(i === 0 ? 'sekarang' : `-${i * 5}m`);
        const sorted = db.logs.slice().sort((a, b) => b.t - a.t || b.id - a.id);
        return {
            ok: true, empty: db.logs.length === 0, packets, allowed, blocked,
            active_rules: db.rules.filter(r => +r.is_active === 1).length, blacklist: db.blacklist.length,
            chart: { labels, allowed: A, blocked: B },
            top_ports: Object.entries(ports).map(([p, c]) => ({ dest_port: +p, c })).sort((a, b) => b.c - a.c).slice(0, 5),
            alerts: sorted.filter(l => l.action === 'BLOCKED').slice(0, 6)
                .map(l => ({ t: hms(l.t), source_ip: l.ip, dest_port: l.port, activity_type: l.activity, action_taken: l.action })),
        };
    }

    async function mockApi(action, { body = null, params = {} } = {}) {
        load();
        const inp = body || {};
        let out;
        switch (action) {
            case 'stats': out = stats(); break;

            case 'rules': out = { ok: true, rules: db.rules.slice().sort((a, b) => a.id - b.id) }; break;
            case 'add_rule': {
                const name = String(inp.rule_name || '').trim().slice(0, 100) || 'Aturan baru';
                const ip = String(inp.ip_address || '').trim().slice(0, 45) || '*';
                if (ip !== '*' && !validIp(ip)) fail('Alamat IP tidak valid (isi IPv4/IPv6 atau * untuk semua IP)');
                const port = inp.port === undefined ? 0 : inp.port;
                if (!validPort(port, 0)) fail('Port harus angka 0-65535 (0 = semua port)');
                let proto = String(inp.protocol || '').toUpperCase();
                if (!['TCP', 'UDP', 'ANY'].includes(proto)) proto = 'ANY';
                const act = String(inp.action || '').toUpperCase();
                if (!['ALLOW', 'BLOCK'].includes(act)) fail('Tindakan harus ALLOW atau BLOCK');
                const id = db.rid++;
                db.rules.push({ id, rule_name: name, ip_address: ip, port: +port, protocol: proto, action: act, is_active: 1, created_at: ymd(Date.now()) });
                out = { ok: true, id };
                break;
            }
            case 'toggle_rule': {
                const r = db.rules.find(x => x.id === Number(inp.id));
                if (r) r.is_active = +r.is_active ? 0 : 1;
                out = { ok: true };
                break;
            }
            case 'delete_rule': db.rules = db.rules.filter(x => x.id !== Number(inp.id)); out = { ok: true }; break;

            case 'blacklist':
                out = { ok: true, items: db.blacklist.slice().sort((a, b) => b.id - a.id)
                    .map(b => ({ id: b.id, ip_address: b.ip_address, reason: b.reason, added_at: `${ymd(b.t)} ${hms(b.t).slice(0, 5)}` })) };
                break;
            case 'add_blacklist': {
                const ip = String(inp.ip_address || '').trim().slice(0, 45);
                if (!validIp(ip)) fail('Alamat IP tidak valid');
                if (db.blacklist.some(b => b.ip_address === ip)) fail('IP sudah ada di daftar blacklist');
                db.blacklist.push({ id: db.bid++, ip_address: ip, reason: String(inp.reason || '').trim().slice(0, 255) || 'Ditambahkan manual', t: Date.now() });
                out = { ok: true };
                break;
            }
            case 'delete_blacklist': db.blacklist = db.blacklist.filter(b => b.id !== Number(inp.id)); out = { ok: true }; break;

            case 'logs': {
                const status = String(params.status || 'ALL').toUpperCase();
                const q = String(params.q || '').trim().toLowerCase();
                const limit = Math.max(1, Math.min(500, Number(params.limit) || 100));
                let list = db.logs.slice().sort((a, b) => b.t - a.t || b.id - a.id);
                if (status === 'ALLOWED' || status === 'BLOCKED') list = list.filter(l => l.action === status);
                if (q) list = list.filter(l => l.ip.includes(q) || l.activity.toLowerCase().includes(q) || String(l.port) === q);
                out = { ok: true, logs: list.slice(0, limit).map(l => ({
                    id: l.id, logged_at: `${ymd(l.t)} ${hms(l.t)}`, source_ip: l.ip, dest_port: l.port,
                    activity_type: l.activity, action_taken: l.action, packets: l.packets, detail: l.detail })) };
                break;
            }
            case 'clear_logs': db.logs = []; out = { ok: true }; break;
            case 'seed_demo': out = { ok: true, inserted: seedDemo() }; break;

            case 'simulate': out = runSim(String(inp.type || 'normal')); break;
            case 'test_connection': {
                const ip = String(inp.ip || '').trim();
                if (!validIp(ip)) fail('Alamat IP tidak valid');
                if (!validPort(inp.port ?? '', 1)) fail('Port harus angka 1-65535');
                const port = Number(inp.port);
                const [verdict, why] = evaluate(ip, port);
                logEvent(ip, port, 'Uji Koneksi Manual', verdict, 1, why);
                out = { ok: true, ip, port, status: verdict, reason: why };
                break;
            }
            default: fail('Aksi tidak dikenal');
        }
        save();
        return JSON.parse(JSON.stringify(out));
    }

    window.mockApi = mockApi;

    if (typeof document !== 'undefined') {
        const btn = document.getElementById('btn-reset-demo');
        if (btn) btn.addEventListener('click', e => {
            e.preventDefault();
            if (!confirm('Reset semua data demo ke kondisi awal?')) return;
            try { localStorage.removeItem(KEY); } catch (err) { /* abaikan */ }
            location.reload();
        });
    }
})();
