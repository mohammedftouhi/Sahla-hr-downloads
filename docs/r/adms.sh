#!/usr/bin/env bash
# Sahla HR — ADMS relay installer (run as root on the Sahla server)
set -e
command -v node >/dev/null 2>&1 || { apt-get update -y && apt-get install -y nodejs; }
mkdir -p /opt/sahla-adms
cat > /opt/sahla-adms/adms-relay.js <<'JS'
#!/usr/bin/env node
// Sahla HR — ADMS relay. ZKTeco devices push attendance here over the internet (ADMS / iClock protocol);
// the customer's Sahla HR server pulls the records with a secret key. No dependencies (Node 16+).
//   node adms-relay.js            config: ./relay.json  {"port":8099,"key":"<secret>","allow":["SN1"],"tz":3}
//   allow = [] → learning mode: every device is accepted and listed in /status (lock it down after the first punch).
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const DIR = __dirname, CFG_FILE = path.join(DIR, 'relay.json'), LOG = path.join(DIR, 'punches.jsonl'), SEEN = path.join(DIR, 'devices.json');
const cfg = Object.assign({ port: 8099, key: '', allow: [], tz: 3 }, fs.existsSync(CFG_FILE) ? JSON.parse(fs.readFileSync(CFG_FILE, 'utf8')) : {});
if (!cfg.key) { cfg.key = crypto.randomBytes(18).toString('hex'); fs.writeFileSync(CFG_FILE, JSON.stringify(cfg, null, 2)); }

let lastId = 0; const recent = new Set();
if (fs.existsSync(LOG)) for (const l of fs.readFileSync(LOG, 'utf8').split('\n')) { if (!l) continue; try { const r = JSON.parse(l); lastId = Math.max(lastId, r.id); recent.add(`${r.sn}|${r.pin}|${r.time}`); } catch { /* skip */ } }
const seen = fs.existsSync(SEEN) ? JSON.parse(fs.readFileSync(SEEN, 'utf8')) : {};
const saveSeen = () => fs.writeFile(SEEN, JSON.stringify(seen, null, 2), () => {});
const log = m => console.log(new Date().toISOString(), m);
// Several customers on one relay: relay.json "clients": [{ "name": "...", "key": "...", "sns": ["SN1", ...] }].
// The master "key" sees everything; a client key sees only its own devices. A device is accepted if it is in "allow"
// or in any client's "sns"; with both empty the relay is in learning mode and accepts every device.
const clients = () => Array.isArray(cfg.clients) ? cfg.clients : [];
const allSns = () => [...cfg.allow, ...clients().flatMap(c => c.sns || [])];
const allowed = sn => sn && (!allSns().length || allSns().includes(sn));
const scopeOf = key => { if (key && key === cfg.key) return null; const c = clients().find(c => c.key && c.key === key); return c ? new Set(c.sns || []) : false; };
fs.watchFile(CFG_FILE, { interval: 5000 }, () => { try { Object.assign(cfg, JSON.parse(fs.readFileSync(CFG_FILE, 'utf8'))); log('relay.json reloaded'); } catch (e) { log('relay.json reload failed ' + e.message); } });
const touch = (sn, ip, what) => { seen[sn] = Object.assign(seen[sn] || { first: new Date().toISOString() }, { last: new Date().toISOString(), ip, what, allowed: allowed(sn) }); saveSeen(); };

function send(res, code, body, type = 'text/plain') { res.writeHead(code, { 'Content-Type': type + '; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(body); }

function attlog(sn, body) {
  const out = [];
  for (const line of body.split(/\r?\n/)) {
    const f = line.split('\t'); if (f.length < 2) continue;
    const pin = f[0].trim(), time = f[1].trim();
    if (!pin || !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(time)) continue;
    const k = `${sn}|${pin}|${time}`; if (recent.has(k)) continue; recent.add(k);
    out.push({ id: ++lastId, sn, pin, time, state: f[2] || null, verify: f[3] || null, at: new Date().toISOString() });
  }
  if (out.length) fs.appendFileSync(LOG, out.map(r => JSON.stringify(r)).join('\n') + '\n');
  return out.length;
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x'), sn = (u.searchParams.get('SN') || '').trim(), ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString();
  let body = '';
  req.on('data', c => { body += c; if (body.length > 5e6) req.destroy(); });
  req.on('end', () => {
    try {
      const p = u.pathname.replace(/\/+$/, '');
      // ---- pull API for Sahla HR (secret key) ----
      if (p === '/pull' || p === '/status') {
        const scope = scopeOf(req.headers['x-key'] || u.searchParams.get('key'));
        if (scope === false) return send(res, 403, 'forbidden');
        const mine = sn => !scope || scope.has(sn);
        if (p === '/status') return send(res, 200, JSON.stringify({ ok: true, lastId, devices: Object.fromEntries(Object.entries(seen).filter(([k]) => mine(k))), allow: scope ? [...scope] : cfg.allow }), 'application/json');
        const after = Number(u.searchParams.get('after') || 0), lim = Math.min(Number(u.searchParams.get('limit') || 5000), 20000);
        const rows = [];
        if (fs.existsSync(LOG)) for (const l of fs.readFileSync(LOG, 'utf8').split('\n')) { if (!l) continue; const r = JSON.parse(l); if (r.id > after && mine(r.sn)) { rows.push(r); if (rows.length >= lim) break; } }
        return send(res, 200, JSON.stringify({ ok: true, rows, lastId }), 'application/json');
      }
      // ---- ADMS / iClock protocol ----
      if (!p.startsWith('/iclock')) return send(res, 404, 'not found');
      if (sn) touch(sn, ip, p);
      if (!allowed(sn)) { log(`rejected SN=${sn} ${p}`); return send(res, 200, 'OK'); }
      if (p === '/iclock/cdata' && req.method === 'GET') {
        return send(res, 200, [`GET OPTION FROM: ${sn}`, 'ATTLOGStamp=None', 'OPERLOGStamp=9999', 'ATTPHOTOStamp=None', 'ErrorDelay=30', 'Delay=10',
          'TransTimes=00:00;14:05', 'TransInterval=1', 'TransFlag=TransData AttLog', `TimeZone=${cfg.tz}`, 'Realtime=1', 'Encrypt=None'].join('\n'));
      }
      if (p === '/iclock/cdata' && req.method === 'POST') {
        const table = (u.searchParams.get('table') || '').toUpperCase();
        if (table === 'ATTLOG') { const n = attlog(sn, body); if (n) log(`SN=${sn} +${n} punches`); return send(res, 200, `OK: ${n}`); }
        return send(res, 200, 'OK');
      }
      if (p === '/iclock/registry') return send(res, 200, 'RegistryCode=sahla');
      if (p === '/iclock/push') return send(res, 200, 'ServerVersion=3.0\nServerName=SahlaRelay\nPushVersion=3.0\nErrorDelay=30\nRequestDelay=10\nTransTimes=00:00;14:00\nTransInterval=1\nTransTables=User Transaction\nRealtime=1\nSessionID=1\nTimeoutSec=10');
      return send(res, 200, 'OK'); // getrequest, devicecmd, ping, rtdata...
    } catch (e) { log('error ' + e.message); send(res, 200, 'OK'); }
  });
});
server.listen(cfg.port, () => log(`ADMS relay on :${cfg.port} — devices=${allSns().length ? allSns().join(',') : 'ALL (learning)'}; clients=${clients().length}`));
JS
[ -f /opt/sahla-adms/relay.json ] || echo "{\"port\":8099,\"key\":\"$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')\",\"allow\":[],\"tz\":3}" > /opt/sahla-adms/relay.json
NODE=$(command -v node)
cat > /etc/systemd/system/sahla-adms.service <<UNIT
[Unit]
Description=Sahla HR ADMS relay
After=network.target
[Service]
WorkingDirectory=/opt/sahla-adms
ExecStart=$NODE /opt/sahla-adms/adms-relay.js
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now sahla-adms
command -v ufw >/dev/null 2>&1 && ufw status | grep -q active && ufw allow 8099/tcp || true
sleep 2
curl -s -o /dev/null -w "relay http %{http_code}\n" "http://127.0.0.1:8099/iclock/getrequest?SN=check" || true
echo "SERVER_IP=$(curl -s -4 ifconfig.me || hostname -I | awk '{print $1}')"
echo "KEY=$(grep -o "\"key\":\"[^\"]*" /opt/sahla-adms/relay.json | cut -d\" -f4)"
echo DONE
