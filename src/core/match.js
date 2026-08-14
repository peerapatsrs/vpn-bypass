'use strict';

const { isIpv4, inCidr } = require('./net');

function bestRoute(routes, ip) {
  if (!isIpv4(ip)) return null;
  let best = null;
  for (const r of routes || []) {
    if (r.inactive) continue;
    const dest = r.dest;
    const prefix = Number(r.prefix);
    if (!isIpv4(dest) || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) continue;
    if (!inCidr(ip, dest, prefix)) continue;
    if (!best || prefix > best.prefix) best = r;
  }
  return best;
}

function classifyPath(detect, route) {
  const lan = (detect && detect.lan) || {};
  const vpn = (detect && detect.vpn) || {};
  if (!route) {
    return { via: 'unknown', iface: null, gw: null };
  }
  const iface = route.iface || null;
  const gw = route.gw || null;
  let via = 'other';
  if (route.kind === 'allow-vpn' || route.kind === 'vpn-keep') via = 'vpn';
  else if (route.kind === 'split' || route.kind === 'lan-protect' || route.kind === 'domain') via = 'lan';
  else if (iface && lan.iface && iface === lan.iface) via = 'lan';
  else if (iface && vpn.iface && iface === vpn.iface) via = 'vpn';
  else if (gw && lan.gw && gw === lan.gw) via = 'lan';
  else if (gw && vpn.gw && gw === vpn.gw) via = 'vpn';
  return { via, iface, gw };
}

function annotateRoute(detect, route) {
  const path = classifyPath(detect, route);
  return {
    dest: route.dest,
    prefix: route.prefix,
    cidr: `${route.dest}/${route.prefix}`,
    gw: route.gw || path.gw,
    iface: route.iface || path.iface,
    kind: route.kind || null,
    domain: route.domain || null,
    via: path.via,
  };
}

function classifyConnection(detect, conn) {
  const lan = (detect && detect.lan) || {};
  const vpn = (detect && detect.vpn) || {};
  const localIp = conn && conn.localIp;
  if (localIp && lan.addr && localIp === lan.addr) {
    return { via: 'lan', iface: lan.iface || null, gw: lan.gw || null };
  }
  if (localIp && vpn.addr && localIp === vpn.addr) {
    return { via: 'vpn', iface: vpn.iface || null, gw: vpn.gw || null };
  }
  const matched = bestRoute((detect && detect.routes) || [], conn && conn.ip);
  return classifyPath(detect, matched);
}

module.exports = { bestRoute, classifyPath, annotateRoute, classifyConnection };
