'use strict';

const { fail } = require('./errors');
const { networkAddr, inCidr } = require('./net');

const SPLIT_HALVES = [
  { dest: '0.0.0.0', prefix: 1 },
  { dest: '128.0.0.0', prefix: 1 },
];

const RFC1918 = [
  { dest: '10.0.0.0', prefix: 8 },
  { dest: '172.16.0.0', prefix: 12 },
  { dest: '192.168.0.0', prefix: 16 },
];

function requireLanGw(detect) {
  const gw = detect && detect.lan && detect.lan.gw;
  if (!gw) throw fail('ENOLAN', 'LAN gateway not found');
  return gw;
}

function lanProtectAction(detect, lanGw) {
  const lan = detect.lan || {};
  const prefix = Number.isInteger(lan.prefix) ? lan.prefix : 24;
  const dest = lan.network || (lan.addr ? networkAddr(lan.addr, prefix) : null);
  if (!dest) return null;
  return {
    op: 'addCidr',
    dest,
    prefix,
    gw: lanGw,
    iface: null,
    kind: 'lan-protect',
    domain: null,
  };
}

function skipVpnKeepCidr(detect, dest, prefix) {
  if (!dest || !Number.isInteger(prefix) || prefix <= 0 || prefix >= 32) return true;
  if (inCidr(dest, '224.0.0.0', 4) || inCidr(dest, '127.0.0.0', 8)) return true;
  if (inCidr(dest, '169.254.0.0', 16) || dest === '255.255.255.255') return true;
  const lan = (detect && detect.lan) || {};
  if (lan.network && Number.isInteger(lan.prefix) && dest === lan.network && prefix === lan.prefix) {
    return true;
  }
  return false;
}

function planVpnKeep(detect) {
  const vpn = (detect && detect.vpn) || {};
  if (!vpn.up || (!vpn.iface && !vpn.gw)) return [];
  const seen = new Set();
  const actions = [];
  const candidates = RFC1918.concat(vpn.cidrs || []);
  for (const c of candidates) {
    const dest = c.dest;
    const prefix = Number(c.prefix);
    if (skipVpnKeepCidr(detect, dest, prefix)) continue;
    const key = `${dest}/${prefix}`;
    if (seen.has(key)) continue;
    seen.add(key);
    actions.push({
      op: 'addCidr',
      dest,
      prefix,
      gw: vpn.gw || c.gw || null,
      iface: vpn.iface || c.iface || null,
      kind: 'vpn-keep',
      domain: null,
    });
  }
  return actions;
}

function planInverse(detect, { lanProtect = true } = {}) {
  const lanGw = requireLanGw(detect);
  const actions = SPLIT_HALVES.map((h) => ({
    op: 'addCidr',
    dest: h.dest,
    prefix: h.prefix,
    gw: lanGw,
    iface: null,
    kind: 'split',
    domain: null,
  }));
  actions.push(...planVpnKeep(detect));
  if (lanProtect) {
    const protect = lanProtectAction(detect, lanGw);
    if (protect) actions.push(protect);
  }
  return actions;
}

function planDomains(detect, resolvedHosts) {
  const lanGw = requireLanGw(detect);
  return (resolvedHosts || []).map((h) => ({
    op: 'addHost',
    dest: h.ip,
    prefix: 32,
    gw: lanGw,
    iface: null,
    kind: 'domain',
    domain: h.domain || null,
  }));
}

function planAllowVpn(detect, resolvedHosts) {
  const vpn = detect.vpn || {};
  return (resolvedHosts || []).map((h) => ({
    op: 'addHost',
    dest: h.ip,
    prefix: 32,
    gw: vpn.gw || null,
    iface: vpn.iface || null,
    kind: 'allow-vpn',
    domain: h.domain || h.host || null,
  }));
}

function plan({
  mode,
  detect,
  resolvedDomains = [],
  allowViaVpn = [],
  lanProtect = true,
}) {
  if (mode !== 'inverse' && mode !== 'domains') {
    throw fail('EINVAL', `invalid mode: ${mode}`);
  }
  let actions = [];
  if (mode === 'inverse') {
    actions = actions.concat(planInverse(detect, { lanProtect }));
  } else {
    actions = actions.concat(planDomains(detect, resolvedDomains));
    if (lanProtect) {
      const protect = lanProtectAction(detect, requireLanGw(detect));
      if (protect) actions.push(protect);
    }
  }
  actions = actions.concat(planAllowVpn(detect, allowViaVpn));
  return { mode, actions };
}

module.exports = {
  SPLIT_HALVES,
  RFC1918,
  plan,
  planInverse,
  planVpnKeep,
  planDomains,
  planAllowVpn,
  lanProtectAction,
};
