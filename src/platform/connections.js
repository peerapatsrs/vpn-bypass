'use strict';

const { isIpv4 } = require('../core/net');

const WEB_PORTS = new Set([80, 443, 8080, 8443]);
const TCP_PAIR = /(\d+\.\d+\.\d+\.\d+):(\d+)->(\d+\.\d+\.\d+\.\d+):(\d+)/;
const ADDR_PORT = /(\d+\.\d+\.\d+\.\d+):(\d+)/;

function asPort(value) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : null;
}

function pushConn(out, row) {
  if (!row || !isIpv4(row.ip) || !isIpv4(row.localIp)) return;
  const port = asPort(row.port);
  const localPort = asPort(row.localPort);
  if (port == null || localPort == null) return;
  out.push({
    ip: row.ip,
    port,
    localIp: row.localIp,
    localPort,
    process: row.process || null,
  });
}

function parseLsofFields(text) {
  const out = [];
  let pid = null;
  let process = null;
  for (const raw of String(text || '').split('\n')) {
    if (!raw) continue;
    const key = raw[0];
    const val = raw.slice(1);
    if (key === 'p') {
      pid = val;
      process = null;
      continue;
    }
    if (key === 'c') {
      process = val.trim() || null;
      continue;
    }
    if (key !== 'n') continue;
    const name = val.replace(/^TCP\s+/i, '').replace(/\s*\(.*\)\s*$/, '');
    const m = name.match(TCP_PAIR);
    if (!m) continue;
    pushConn(out, {
      localIp: m[1],
      localPort: m[2],
      ip: m[3],
      port: m[4],
      process,
      pid,
    });
  }
  return out;
}

function parseSs(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    if (!line.trim()) continue;
    const addrs = line.match(/(\d+\.\d+\.\d+\.\d+):(\d+)/g);
    if (!addrs || addrs.length < 2) continue;
    const local = addrs[addrs.length - 2].match(ADDR_PORT);
    const remote = addrs[addrs.length - 1].match(ADDR_PORT);
    if (!local || !remote) continue;
    let process = null;
    const proc = line.match(/users:\(\("([^"]+)"/);
    if (proc) process = proc[1];
    pushConn(out, {
      localIp: local[1],
      localPort: local[2],
      ip: remote[1],
      port: remote[2],
      process,
    });
  }
  return out;
}

function parseNetstatTcp(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    if (!/established/i.test(line)) continue;
    const addrs = line.match(/(\d+\.\d+\.\d+\.\d+):(\d+)/g);
    if (!addrs || addrs.length < 2) continue;
    const local = addrs[0].match(ADDR_PORT);
    const remote = addrs[1].match(ADDR_PORT);
    if (!local || !remote) continue;
    pushConn(out, {
      localIp: local[1],
      localPort: local[2],
      ip: remote[1],
      port: remote[2],
      process: null,
    });
  }
  return out;
}

async function stdoutOrEmpty(exec, file, args) {
  try {
    const r = await exec(file, args, { timeout: 8000 });
    return r.stdout || '';
  } catch (err) {
    if (err && (err.code === 1 || err.status === 1 || err.code === 'ENOENT')) {
      return err.stdout || '';
    }
    return err && err.stdout ? String(err.stdout) : '';
  }
}

module.exports = {
  WEB_PORTS,
  parseLsofFields,
  parseSs,
  parseNetstatTcp,
  stdoutOrEmpty,
};
