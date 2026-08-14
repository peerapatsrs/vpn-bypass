'use strict';

const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const { hostnameUsesVpnDns, isUsableDnsIp, uniqueIps, normalizeSuffixes } = require('./dns');
const { isIpv4 } = require('./net');

const MAX_PACKET = 4096;
const MAX_PENDING = 256;
const UPSTREAM_TIMEOUT_MS = 2500;

function parseServer(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  const m = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(s);
  if (m) {
    const host = m[1];
    const port = Number(m[2]);
    if (!isIpv4(host) || !Number.isInteger(port) || port < 1 || port > 65535) return null;
    if (host === '0.0.0.0') return null;
    return { host, port };
  }
  if (!isIpv4(s) || !isUsableDnsIp(s)) return null;
  return { host: s, port: 53 };
}

function decodeQname(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 13) return null;
  const labels = [];
  let pos = 12;
  let hops = 0;
  while (hops < 128) {
    hops += 1;
    if (pos >= buf.length) return null;
    const len = buf[pos];
    if (len === 0) {
      return labels.join('.');
    }
    if ((len & 0xc0) === 0xc0) return null;
    if (len > 63) return null;
    pos += 1;
    if (pos + len > buf.length) return null;
    labels.push(buf.slice(pos, pos + len).toString('ascii').toLowerCase());
    pos += len;
  }
  return null;
}

function pickUpstream(qname, cfg) {
  const suffixes = cfg.suffixes || [];
  const vpn = cfg.vpnServers || [];
  const lan = cfg.lanServers || [];
  if (hostnameUsesVpnDns(qname, suffixes) && vpn.length) return vpn[0];
  return lan[0] || vpn[0] || null;
}

function createForwarder(opts = {}) {
  const listen = opts.listen || '127.0.0.1';
  if (listen !== '127.0.0.1' && listen !== '::1') {
    throw new Error('DNS forwarder must bind loopback only');
  }
  const port = opts.port == null ? 53 : Number(opts.port);
  const lanServers = (opts.lanServers || []).map(parseServer).filter(Boolean);
  const vpnServers = (opts.vpnServers || []).map(parseServer).filter(Boolean);
  const suffixes = normalizeSuffixes(opts.suffixes || []);
  const makeDgram = typeof opts.dgram === 'function' ? opts.dgram : () => dgram.createSocket(opts.udpType || 'udp4');
  const timeoutMs = opts.timeoutMs == null ? UPSTREAM_TIMEOUT_MS : opts.timeoutMs;

  let incoming = null;
  let outgoing = null;
  let nextId = 1;
  const pending = new Map();
  const cfg = { lanServers, vpnServers, suffixes };

  function clearPending(id) {
    const row = pending.get(id);
    if (!row) return;
    if (row.timer) clearTimeout(row.timer);
    pending.delete(id);
  }

  function onUpstream(msg) {
    if (!Buffer.isBuffer(msg) || msg.length < 12 || msg.length > MAX_PACKET) return;
    const id = msg.readUInt16BE(0);
    const row = pending.get(id);
    if (!row || !incoming) return;
    clearPending(id);
    const out = Buffer.from(msg);
    out[0] = row.origId >> 8;
    out[1] = row.origId & 0xff;
    incoming.send(out, row.port, row.address);
  }

  function onQuery(msg, rinfo) {
    if (!rinfo || rinfo.address !== '127.0.0.1') return;
    if (!Buffer.isBuffer(msg) || msg.length < 13 || msg.length > MAX_PACKET) return;
    const qname = decodeQname(msg);
    if (qname == null) return;
    const upstream = pickUpstream(qname, cfg);
    if (!upstream || !outgoing) return;
    if (pending.size >= MAX_PENDING) {
      const oldest = pending.keys().next().value;
      clearPending(oldest);
    }
    const origId = msg.readUInt16BE(0);
    let outId = nextId & 0xffff;
    nextId = (nextId + 1) & 0xffff;
    if (nextId === 0) nextId = 1;
    while (pending.has(outId)) {
      outId = nextId & 0xffff;
      nextId = (nextId + 1) & 0xffff;
      if (nextId === 0) nextId = 1;
    }
    const copy = Buffer.from(msg);
    copy[0] = outId >> 8;
    copy[1] = outId & 0xff;
    const timer = setTimeout(() => clearPending(outId), timeoutMs);
    if (timer.unref) timer.unref();
    pending.set(outId, {
      address: rinfo.address,
      port: rinfo.port,
      origId,
      timer,
    });
    outgoing.send(copy, upstream.port, upstream.host);
  }

  function start() {
    return new Promise((resolve, reject) => {
      incoming = makeDgram();
      outgoing = makeDgram();
      const fail = (err) => {
        stop();
        reject(err);
      };
      incoming.once('error', fail);
      outgoing.once('error', fail);
      incoming.on('message', onQuery);
      outgoing.on('message', onUpstream);
      outgoing.bind(0, () => {
        incoming.bind(port, listen, () => {
          incoming.removeListener('error', fail);
          outgoing.removeListener('error', fail);
          incoming.on('error', () => {});
          outgoing.on('error', () => {});
          const addr = typeof incoming.address === 'function' ? incoming.address() : { port };
          resolve({ host: listen, port: addr && addr.port != null ? addr.port : port });
        });
      });
    });
  }

  function stop() {
    for (const id of [...pending.keys()]) clearPending(id);
    const close = (sock) => {
      if (!sock) return;
      try { sock.close(); } catch { /* ignore */ }
    };
    close(incoming);
    close(outgoing);
    incoming = null;
    outgoing = null;
  }

  function address() {
    if (!incoming || typeof incoming.address !== 'function') return null;
    try { return incoming.address(); } catch { return null; }
  }

  return {
    start,
    stop,
    address,
    pickUpstream: (name) => pickUpstream(name, cfg),
    cfg,
  };
}

function loadConfig(file) {
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  const lanServers = uniqueIps(raw.lanServers || []);
  const vpnServers = uniqueIps(raw.vpnServers || []);
  if (!lanServers.length) throw new Error('forwarder config missing lanServers');
  return {
    listen: raw.listen || '127.0.0.1',
    port: raw.port == null ? 53 : Number(raw.port),
    lanServers,
    vpnServers,
    suffixes: normalizeSuffixes(raw.suffixes || []),
  };
}

function spawnDetached(configPath, opts = {}) {
  const { spawn } = opts.spawnImpl ? { spawn: opts.spawnImpl } : require('child_process');
  const execPath = opts.execPath || process.execPath;
  const scriptPath = opts.scriptPath || path.join(__dirname, 'dnsForwarder.js');
  const child = spawn(execPath, [scriptPath, configPath], {
    detached: true,
    stdio: 'ignore',
    env: {
      PATH: '/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin',
      HOME: process.env.HOME || '',
      LANG: process.env.LANG || 'C',
    },
  });
  child.unref();
  return child.pid;
}

function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function main(argv) {
  const file = argv[2];
  if (!file) {
    process.stderr.write('usage: dnsForwarder.js <config.json>\n');
    process.exit(2);
  }
  const cfg = loadConfig(file);
  const fwd = createForwarder(cfg);
  await fwd.start();
  const stop = () => {
    try { fwd.stop(); } catch { /* ignore */ }
    process.exit(0);
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

if (require.main === module) {
  main(process.argv).catch((err) => {
    process.stderr.write(`${err && err.message ? err.message : err}\n`);
    process.exit(1);
  });
}

module.exports = {
  createForwarder,
  decodeQname,
  parseServer,
  pickUpstream,
  loadConfig,
  spawnDetached,
  pidAlive,
};
