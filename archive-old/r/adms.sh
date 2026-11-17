#!/usr/bin/env bash
# Sahla HR — ADMS relay installer (run as root on the Sahla server)
set -e
command -v node >/dev/null 2>&1 || { apt-get update -y && apt-get install -y nodejs; }
mkdir -p /opt/sahla-adms
cat > /opt/sahla-adms/adms-relay.js <<'JS'
#!/usr/bin/env node
// Sahla HR — ADMS relay. ZKTeco devices push attendance here over the internet (ADMS / iClock protocol);
// the customer's Sahla HR server pulls the records with a secret key (header x-key only). No dependencies (Node 16+).
//   node adms-relay.js                 config: ./relay.json  {"port":8099,"key":"<secret>","allow":["SN1"],"tz":3}
// Adding a device (preferred): "discover & approve". From Sahla HR the customer presses «إضافة جهاز جديد», which calls
//   POST /discover/start with its own key: a 10-minute window opens for THAT customer only. A device that is not
//   registered yet and connects during the window is listed (GET /discover) but still refused, so it keeps its punches;
//   POST /discover/approve {"sn"} adds it to that customer's devices in relay.json, after which its punches are accepted.
//   POST /discover/reject {"sn"} ignores it for the rest of the window, POST /discover/stop closes the window.
//   The master "key" (single-customer / legacy mode) is the default customer and approves into "allow".
//   Pending devices are kept in ./discover.json (survives restarts). Nobody ever types a serial number.
// Legacy (kept for backward compatibility, not recommended — it accepts ANY device for everyone):
//   node adms-relay.js --learn[=MIN]   opens learning mode for MIN minutes (default 60): unknown devices are accepted
//                                      and listed in /status. Same as setting relay.json "learnUntil": "<ISO time>".
// Outside a learning window an unknown device gets an error reply, so it keeps its punches until it is approved.
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const DIR = __dirname, CFG_FILE = path.join(DIR, 'relay.json'), LOG = path.join(DIR, 'punches.jsonl'), SEEN = path.join(DIR, 'devices.json'), DISC = path.join(DIR, 'discover.json');
const log = m => console.log(new Date().toISOString(), m);
const readCfg = () => (fs.existsSync(CFG_FILE) ? JSON.parse(fs.readFileSync(CFG_FILE, 'utf8').replace(/^﻿/, '')) : {});
const cfg = Object.assign({ port: 8099, key: '', allow: [], tz: 3 }, readCfg());
// write-then-rename: a crash mid-write never leaves a half-written relay.json behind
function writeAtomic(file, data) { const tmp = `${file}.${process.pid}.tmp`; fs.writeFileSync(tmp, data); fs.renameSync(tmp, file); }
const saveCfg = () => writeAtomic(CFG_FILE, JSON.stringify(cfg, null, 2));
let dirty = false;
if (!cfg.key) { cfg.key = crypto.randomBytes(18).toString('hex'); dirty = true; }
const learnArg = process.argv.find(a => /^--learn(=\d+)?$/.test(a));
if (learnArg) { cfg.learnUntil = new Date(Date.now() + (Number(learnArg.split('=')[1]) || 60) * 60e3).toISOString(); dirty = true; }

// Punch log: one JSON object per line. Broken lines (e.g. a crash mid-write) are skipped, never fatal.
function readLog() {
  const out = [];
  if (!fs.existsSync(LOG)) return out;
  for (const l of fs.readFileSync(LOG, 'utf8').split('\n')) {
    if (!l.trim()) continue;
    try { const r = JSON.parse(l); if (r && Number.isFinite(r.id)) out.push(r); } catch { /* skip a corrupt line */ }
  }
  return out;
}
let lastId = 0; const recent = new Set();
const existing = readLog();
for (const r of existing) { lastId = Math.max(lastId, r.id); recent.add(`${r.sn}|${r.pin}|${r.time}`); }
// epoch identifies this punch log; a new/empty log gets a new epoch so pulling servers restart their counter.
if (!cfg.epoch || (!existing.length && lastId === 0)) { cfg.epoch = crypto.randomBytes(8).toString('hex'); dirty = true; }
if (dirty) saveCfg();

let seen = {}; try { seen = fs.existsSync(SEEN) ? JSON.parse(fs.readFileSync(SEEN, 'utf8')) : {}; } catch { seen = {}; }
// devices.json: one atomic write at a time, batched (1 s) — concurrent fs.writeFile calls could interleave and corrupt the file
let seenTimer = null;
function saveSeen(now) {
  const write = () => { seenTimer = null; try { writeAtomic(SEEN, JSON.stringify(seen, null, 2)); } catch (e) { log('devices.json save failed ' + e.message); } };
  if (now) { if (seenTimer) clearTimeout(seenTimer); return write(); }
  if (!seenTimer) { seenTimer = setTimeout(write, 1000); if (seenTimer.unref) seenTimer.unref(); }
}
// Several customers on one relay: relay.json "clients": [{ "name": "...", "key": "...", "sns": ["SN1", ...] }].
// The master "key" sees everything; a client key sees only its own devices. A device is accepted if it is in "allow"
// or in any client's "sns", or (any device) while a learning window ("learnUntil") is open.
const clients = () => (Array.isArray(cfg.clients) ? cfg.clients : []);
const allSns = () => [...(Array.isArray(cfg.allow) ? cfg.allow : []), ...clients().flatMap(c => c.sns || [])];
const learning = () => !!cfg.learnUntil && Date.parse(cfg.learnUntil) > Date.now();
const allowed = sn => !!sn && (allSns().includes(sn) || learning());
const digest = s => crypto.createHash('sha256').update(String(s || '')).digest();
const sameKey = (a, b) => !!a && !!b && crypto.timingSafeEqual(digest(a), digest(b));
// Who is calling: the master key is the "default" customer (its devices are "allow"); a client key is that client.
const cidOf = key => crypto.createHash('sha256').update('sahla-client:' + key).digest('hex').slice(0, 16);
const whoIs = key => {
  if (!key) return null;
  if (sameKey(key, cfg.key)) return { id: 'default', master: true };
  let hit = null; for (const c of clients()) if (c.key && sameKey(key, c.key) && !hit) hit = c; // check all, constant work
  return hit ? { id: cidOf(hit.key), client: hit } : null;
};
const scopeOf = key => { const w = whoIs(key); return !w ? false : w.master ? null : new Set(w.client.sns || []); };
fs.watchFile(CFG_FILE, { interval: 5000 }, () => { try { const nc = readCfg(); for (const k of Object.keys(cfg)) if (!(k in nc)) delete cfg[k]; Object.assign(cfg, nc); log('relay.json reloaded'); } catch (e) { log('relay.json reload failed ' + e.message); } });
// ---- discovery: per-customer windows and pending (seen but not yet approved) devices ----
const DISCOVER_MIN = 10, MAX_PENDING = 20, PENDING_TTL = 24 * 3600e3, SN_RE = /^[A-Za-z0-9]{1,32}$/;
let disc = {}; // { [customerId]: { until: ISO|null, pending: { [sn]: {...} }, rejected: [sn] } }
try { const d = fs.existsSync(DISC) ? JSON.parse(fs.readFileSync(DISC, 'utf8')) : {}; if (d && typeof d === 'object' && !Array.isArray(d)) disc = d; } catch { disc = {}; }
let discTimer = null;
function saveDisc(now) {
  const write = () => { discTimer = null; try { writeAtomic(DISC, JSON.stringify(disc, null, 2)); } catch (e) { log('discover.json save failed ' + e.message); } };
  if (now) { if (discTimer) clearTimeout(discTimer); return write(); }
  if (!discTimer) { discTimer = setTimeout(write, 1000); if (discTimer.unref) discTimer.unref(); }
}
const dstate = id => {
  const st = disc[id] || (disc[id] = {});
  if (!st.pending || typeof st.pending !== 'object') st.pending = {};
  if (!Array.isArray(st.rejected)) st.rejected = [];
  return st;
};
const windowOpen = st => !!st && !!st.until && Date.parse(st.until) > Date.now();
const owned = sn => allSns().includes(sn);
const identities = () => [{ id: 'default' }, ...clients().filter(c => c.key).map(c => ({ id: cidOf(c.key) }))];
function prune(st) {
  for (const [sn, d] of Object.entries(st.pending)) if (owned(sn) || !(Date.parse(d.lastSeen) > Date.now() - PENDING_TTL)) delete st.pending[sn];
}
const clean = v => String(v == null ? '' : v).replace(/[^\x20-\x7E]/g, '').trim().slice(0, 64);
// What the device tells about itself: ?pushver=&DeviceType=, ?INFO=<firmware>,users,fps,logs,<ip>,... and the
// "~DeviceName=...,FirmVer=..." key/values some firmwares post to /iclock/registry or table=options.
function deviceMeta(u, p, body) {
  const m = {}, q = k => u.searchParams.get(k);
  if (q('pushver')) m.pushver = clean(q('pushver'));
  if (q('DeviceType')) m.deviceType = clean(q('DeviceType'));
  const info = q('INFO');
  if (info) { const f = info.split(','); if (clean(f[0])) m.firmware = clean(f[0]); if (/^\d{1,3}(\.\d{1,3}){3}$/.test((f[4] || '').trim())) m.localIp = f[4].trim(); }
  const table = (q('table') || '').toUpperCase();
  if (body && (p === '/iclock/registry' || table === 'OPTIONS' || table === 'INFO')) {
    for (const part of body.slice(0, 8192).split(/[,\r\n&]/)) {
      const i = part.indexOf('='); if (i < 1) continue;
      const k = part.slice(0, i).replace(/^~/, '').trim().toLowerCase(), v = clean(part.slice(i + 1)); if (!v) continue;
      if (k === 'devicename') m.model = v; else if (k === 'firmver') m.firmware = v; else if (k === 'devicetype') m.deviceType = v; else if (k === 'pushversion') m.pushver = v;
    }
  }
  return m;
}
// An unregistered device knocked: list it for every customer whose window is open (never its punches).
function noteUnknown(sn, ip, u, p, body) {
  if (!SN_RE.test(sn) || owned(sn)) return;
  const meta = deviceMeta(u, p, body), now = new Date().toISOString();
  let changed = false, added = false;
  // A knocking device is not shown to every customer whose window happens to be open: only to those already holding it,
  // else the only open window, else the windows opened from the device's own public IP (same site).
  const ids = identities().map(x => x.id).filter(id => disc[id] && disc[id].pending);
  let owners = ids.filter(id => disc[id].pending[sn]);
  if (!owners.length) {
    const open = ids.filter(id => windowOpen(disc[id]) && !disc[id].rejected.includes(sn));
    owners = open.length === 1 ? open : open.filter(id => disc[id].startIp && disc[id].startIp === clean(ip));
  }
  for (const id of owners) {
    const st = disc[id];
    const had = st.pending[sn], open = windowOpen(st);
    if (!had && (!open || st.rejected.includes(sn) || Object.keys(st.pending).length >= MAX_PENDING)) continue;
    st.pending[sn] = Object.assign(had || { sn, firstSeen: now }, meta, { ip: clean(ip), lastSeen: now });
    changed = true; added = added || !had;
  }
  if (changed) saveDisc(added); // a new device is written at once; lastSeen refreshes are batched
}
function discoverApi(req, res, p, who, body, ip) {
  const st = dstate(who.id); prune(st);
  // looked up again on every call: relay.json may have been reloaded/rewritten since the key was checked
  const myList = () => { if (who.master) return Array.isArray(cfg.allow) ? cfg.allow : []; const c = clients().find(x => x.key && sameKey(x.key, who.client.key)); return (c && c.sns) || []; };
  const view = extra => {
    const open = windowOpen(st);
    return json(res, 200, Object.assign({ ok: true, open, discoverUntil: open ? st.until : null, secondsLeft: open ? Math.max(0, Math.round((Date.parse(st.until) - Date.now()) / 1000)) : 0,
      pending: Object.values(st.pending).sort((a, b) => String(a.firstSeen).localeCompare(String(b.firstSeen))),
      devices: myList().map(sn => ({ sn, lastSeen: (seen[sn] && seen[sn].last) || null })) }, extra || {}));
  };
  if (p === '/discover') return req.method === 'GET' ? view() : json(res, 405, { ok: false, error: 'method' });
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'method' });
  if (p === '/discover/start') { st.until = new Date(Date.now() + DISCOVER_MIN * 60e3).toISOString(); st.rejected = []; st.startIp = clean(ip); saveDisc(true); log(`discovery opened for ${who.id}`); return view(); }
  if (p === '/discover/stop') { st.until = null; saveDisc(true); return view(); }
  if (p !== '/discover/approve' && p !== '/discover/reject') return json(res, 404, { ok: false, error: 'not_found' });
  let sn = '';
  try { sn = String((JSON.parse(body || '{}') || {}).sn || '').trim(); } catch { return json(res, 400, { ok: false, error: 'bad_json' }); }
  if (!SN_RE.test(sn)) return json(res, 400, { ok: false, error: 'bad_sn' });
  if (p === '/discover/reject') {
    delete st.pending[sn]; if (!st.rejected.includes(sn)) st.rejected = [...st.rejected, sn].slice(-100);
    saveDisc(true); return view();
  }
  if (owned(sn)) { for (const { id } of identities()) if (disc[id] && disc[id].pending) delete disc[id].pending[sn]; saveDisc(true); return json(res, 409, { ok: false, error: 'already_registered' }); }
  if (!st.pending[sn]) return json(res, 404, { ok: false, error: 'not_pending' });
  // re-read relay.json so a manual edit made since the last reload is not overwritten
  const fresh = readCfg();
  const freshSns = [...(Array.isArray(fresh.allow) ? fresh.allow : []), ...(Array.isArray(fresh.clients) ? fresh.clients : []).flatMap(c => c.sns || [])];
  if (freshSns.includes(sn)) { Object.assign(cfg, fresh); delete st.pending[sn]; saveDisc(true); return json(res, 409, { ok: false, error: 'already_registered' }); }
  if (who.master) fresh.allow = [...(Array.isArray(fresh.allow) ? fresh.allow : []), sn];
  else {
    const c = (Array.isArray(fresh.clients) ? fresh.clients : []).find(x => x.key && sameKey(x.key, who.client.key));
    if (!c) return json(res, 409, { ok: false, error: 'client_gone' });
    c.sns = [...(Array.isArray(c.sns) ? c.sns : []), sn];
  }
  writeAtomic(CFG_FILE, JSON.stringify(fresh, null, 2));
  Object.assign(cfg, fresh);
  for (const { id } of identities()) if (disc[id] && disc[id].pending) delete disc[id].pending[sn];
  saveDisc(true);
  if (seen[sn]) { seen[sn].allowed = true; saveSeen(); }
  log(`device ${sn} approved for ${who.id}`);
  return view({ approved: sn });
}
const MAX_UNKNOWN_SEEN = 50;
const touch = (sn, ip, what) => {
  if (!allowed(sn) && !seen[sn]) { // never let unknown devices grow the file without bound
    const unk = Object.keys(seen).filter(k => !seen[k].allowed);
    if (unk.length >= MAX_UNKNOWN_SEEN) { unk.sort((x, y) => String(seen[x].last).localeCompare(String(seen[y].last))); delete seen[unk[0]]; }
  }
  seen[sn] = Object.assign(seen[sn] || { first: new Date().toISOString() }, { last: new Date().toISOString(), ip, what, allowed: allowed(sn) }); saveSeen(); };

function send(res, code, body, type = 'text/plain') { res.writeHead(code, { 'Content-Type': type + '; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(body); }
const json = (res, code, obj) => send(res, code, JSON.stringify(obj), 'application/json');

// Appends records; every append starts on a fresh line even if the previous write was cut off.
function append(rows) {
  let lead = '';
  try { const st = fs.statSync(LOG); if (st.size) { const fd = fs.openSync(LOG, 'r'); const b = Buffer.alloc(1); fs.readSync(fd, b, 0, 1, st.size - 1); fs.closeSync(fd); if (b[0] !== 10) lead = '\n'; } } catch { /* no file yet */ }
  fs.appendFileSync(LOG, lead + rows.map(r => JSON.stringify(r)).join('\n') + '\n');
}
function attlog(sn, body) {
  const out = [];
  for (const line of body.split(/\r?\n/)) {
    const f = line.split('\t'); if (f.length < 2) continue;
    const pin = f[0].trim(), time = f[1].trim();
    if (!pin || !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(time)) continue;
    const k = `${sn}|${pin}|${time}`; if (recent.has(k)) continue; recent.add(k);
    out.push({ id: lastId + out.length + 1, sn, pin, time, state: f[2] || null, verify: f[3] || null, at: new Date().toISOString() });
  }
  if (out.length) {
    try { append(out); } catch (e) { for (const r of out) recent.delete(`${r.sn}|${r.pin}|${r.time}`); throw e; }
    lastId += out.length;
  }
  return out.length;
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x'), sn = (u.searchParams.get('SN') || '').trim(), ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString();
  const p = u.pathname.replace(/\/+$/, '');
  const api = p === '/pull' || p === '/status' || p === '/discover' || p.startsWith('/discover/');
  let body = '';
  req.on('data', c => { body += c; if (body.length > 5e6) req.destroy(); });
  req.on('end', () => {
    try {
      // ---- pull API for Sahla HR (secret key in the x-key header) ----
      if (p === '/discover' || p.startsWith('/discover/')) {
        const who = whoIs(req.headers['x-key']);
        if (!who) return json(res, 403, { ok: false, error: 'forbidden' });
        return discoverApi(req, res, p, who, body, ip);
      }
      if (api) {
        const scope = scopeOf(req.headers['x-key']);
        if (scope === false) return json(res, 403, { ok: false, error: 'forbidden' });
        const mine = s => !scope || scope.has(s);
        if (p === '/status') return json(res, 200, { ok: true, epoch: cfg.epoch, lastId, learning: learning(), learnUntil: learning() ? cfg.learnUntil : null, devices: Object.fromEntries(Object.entries(seen).filter(([k]) => mine(k))), allow: scope ? [...scope] : cfg.allow });
        const after = Number(u.searchParams.get('after') || 0) || 0, lim = Math.max(1, Math.min(Number(u.searchParams.get('limit') || 5000) || 5000, 20000));
        const rows = [];
        for (const r of readLog()) { if (r.id > after && mine(r.sn)) { rows.push(r); if (rows.length >= lim) break; } }
        return json(res, 200, { ok: true, epoch: cfg.epoch, rows, lastId });
      }
      // ---- ADMS / iClock protocol ----
      if (!p.startsWith('/iclock')) return send(res, 404, 'not found');
      if (sn && (SN_RE.test(sn) || allowed(sn))) touch(sn, ip, p);
      // A device that is not registered gets an error, so it keeps its punches and retries later; while a customer's
      // discovery window is open it is listed for approval (its punches are still NOT stored).
      if (!allowed(sn)) { noteUnknown(sn, ip, u, p, body); log(`rejected SN=${sn.slice(0, 40)} ${p}`); return send(res, 403, 'UNKNOWN DEVICE'); }
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
    } catch (e) {
      log('error ' + e.message);
      // never answer "OK" on failure: the device must keep (and resend) its punches, the server must see an error
      if (api) json(res, 500, { ok: false, error: e.message }); else send(res, 500, 'ERROR');
    }
  });
});
server.on('close', () => { if (discTimer) saveDisc(true); if (seenTimer) saveSeen(true); });
if (require.main === module) {
  server.listen(cfg.port, () => log(`ADMS relay on :${cfg.port} — devices=${allSns().join(',') || '(none)'}${learning() ? ` + learning until ${cfg.learnUntil}` : ''}; clients=${clients().length}; epoch=${cfg.epoch}`));
}
module.exports = { server, cfg, attlog, readLog, disc: () => disc };
JS
# fresh install: no device is accepted until the customer adds it from Sahla HR («إضافة جهاز جديد» → «اعتماد»).
# An existing relay.json (keys, clients, devices) is never touched; re-running this script only upgrades the program.
[ -f /opt/sahla-adms/relay.json ] || echo "{\"port\":8099,\"key\":\"$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')\",\"allow\":[],\"tz\":3}" > /opt/sahla-adms/relay.json
# upgrade from the old relay (empty "allow" used to accept every device): keep devices that were sending in the last 30 days
node -e '
const fs=require("fs"),d="/opt/sahla-adms/";let c,s;try{c=JSON.parse(fs.readFileSync(d+"relay.json","utf8"));s=JSON.parse(fs.readFileSync(d+"devices.json","utf8"))}catch{process.exit(0)}
const owned=new Set([...(c.allow||[]),...(c.clients||[]).flatMap(x=>x.sns||[])]);if(owned.size)process.exit(0);
const keep=Object.entries(s).filter(([sn,v])=>/^[A-Za-z0-9]{1,32}$/.test(sn)&&v&&v.last&&Date.now()-Date.parse(v.last)<30*864e5).map(([sn])=>sn);
if(!keep.length)process.exit(0);c.allow=keep;fs.writeFileSync(d+"relay.json.tmp",JSON.stringify(c,null,2));fs.renameSync(d+"relay.json.tmp",d+"relay.json");
console.log("kept existing devices: "+keep.join(", "));' || true
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
systemctl daemon-reload && systemctl enable sahla-adms && systemctl restart sahla-adms
command -v ufw >/dev/null 2>&1 && ufw status | grep -q active && ufw allow 8099/tcp || true
sleep 2
curl -s -o /dev/null -w "relay http %{http_code}\n" "http://127.0.0.1:8099/iclock/getrequest?SN=check" || true
echo "SERVER_IP=$(curl -s -4 ifconfig.me || hostname -I | awk '{print $1}')"
echo "KEY=$(grep -o "\"key\":\"[^\"]*" /opt/sahla-adms/relay.json | cut -d\" -f4)"
echo DONE
