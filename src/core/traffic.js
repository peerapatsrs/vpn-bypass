'use strict';

const dns = require('dns').promises;
const { isIpv4, isBlockedIPv4, inCidr } = require('./net');
const { classifyConnection } = require('./match');
const { WEB_PORTS } = require('../platform/connections');

const MAX_LIVE = 60;
const MAX_RECENT = 80;
const MAX_NAMES = 500;

function defaultReverse(ip) {
  return dns.reverse(ip).then((names) => {
    const name = Array.isArray(names) ? names.find(Boolean) : null;
    return name || null;
  }).catch(() => null);
}

function isWebConnection(detect, conn) {
  if (!conn || !isIpv4(conn.ip) || isBlockedIPv4(conn.ip)) return false;
  if (!WEB_PORTS.has(Number(conn.port))) return false;
  const lan = (detect && detect.lan) || {};
  const vpn = (detect && detect.vpn) || {};
  if (lan.addr && conn.ip === lan.addr) return false;
  if (vpn.addr && conn.ip === vpn.addr) return false;
  if (lan.network && Number.isInteger(lan.prefix) && inCidr(conn.ip, lan.network, lan.prefix)) {
    return false;
  }
  return true;
}

function classifyLive(detect, connections, names = {}) {
  const rows = [];
  const seen = new Map();
  for (const conn of connections || []) {
    if (!isWebConnection(detect, conn)) continue;
    const path = classifyConnection(detect, conn);
    const key = `${conn.ip}|${path.via}`;
    let row = seen.get(key);
    if (!row) {
      row = {
        ip: conn.ip,
        host: names[conn.ip] || null,
        via: path.via,
        iface: path.iface,
        gw: path.gw,
        localIp: conn.localIp || null,
        ports: [],
        processes: [],
      };
      seen.set(key, row);
      rows.push(row);
    }
    if (conn.port && !row.ports.includes(conn.port)) row.ports.push(conn.port);
    if (conn.process && !row.processes.includes(conn.process)) row.processes.push(conn.process);
    if (!row.host && names[conn.ip]) row.host = names[conn.ip];
  }
  rows.sort((a, b) => {
    const ah = a.host || a.ip;
    const bh = b.host || b.ip;
    if (ah !== bh) return ah < bh ? -1 : 1;
    if (a.via !== b.via) return a.via < b.via ? -1 : 1;
    return a.ip < b.ip ? -1 : 1;
  });
  return rows.slice(0, MAX_LIVE).map((row) => ({
    ip: row.ip,
    host: row.host,
    via: row.via,
    iface: row.iface,
    gw: row.gw,
    localIp: row.localIp,
    port: row.ports[0] || null,
    ports: row.ports,
    process: row.processes[0] || null,
    processes: row.processes,
  }));
}

function createTrafficTracker(opts = {}) {
  const recent = [];
  const ipNames = new Map();
  const reverseCache = new Map();
  const reversePending = new Set();
  const reverseDns = opts.reverseDns || defaultReverse;
  const seenVia = new Map();

  function rememberName(ip, name) {
    if (!isIpv4(ip) || !name) return;
    ipNames.set(ip, String(name));
    if (ipNames.size > MAX_NAMES) {
      const first = ipNames.keys().next().value;
      ipNames.delete(first);
    }
  }

  function nameFor(ip) {
    return ipNames.get(ip) || reverseCache.get(ip) || null;
  }

  function namesObject() {
    const out = {};
    for (const [ip, name] of ipNames) out[ip] = name;
    for (const [ip, name] of reverseCache) {
      if (name && !out[ip]) out[ip] = name;
    }
    return out;
  }

  function rememberRecent(row) {
    const prev = seenVia.get(row.ip);
    if (prev === row.via) return;
    seenVia.set(row.ip, row.via);
    recent.unshift({
      ts: new Date().toISOString(),
      ip: row.ip,
      host: row.host || null,
      via: row.via,
      iface: row.iface || null,
      process: row.process || null,
      port: row.port || (row.ports && row.ports[0]) || null,
    });
    if (recent.length > MAX_RECENT) recent.length = MAX_RECENT;
  }

  function requestReverse(ip) {
    if (!isIpv4(ip) || reverseCache.has(ip) || reversePending.has(ip) || ipNames.has(ip)) return;
    reversePending.add(ip);
    Promise.resolve()
      .then(() => reverseDns(ip))
      .then((name) => {
        reversePending.delete(ip);
        reverseCache.set(ip, name || null);
      })
      .catch(() => {
        reversePending.delete(ip);
        reverseCache.set(ip, null);
      });
  }

  function snapshot(detect, connections) {
    const live = classifyLive(detect, connections, namesObject());
    const liveIps = new Set(live.map((row) => row.ip));
    for (const ip of [...seenVia.keys()]) {
      if (!liveIps.has(ip)) seenVia.delete(ip);
    }
    for (const row of live) {
      rememberRecent(row);
      if (!row.host) requestReverse(row.ip);
    }
    return { live, recent: recent.slice() };
  }

  return { snapshot, rememberName, nameFor };
}

module.exports = {
  WEB_PORTS,
  isWebConnection,
  classifyLive,
  createTrafficTracker,
  defaultReverse,
};
