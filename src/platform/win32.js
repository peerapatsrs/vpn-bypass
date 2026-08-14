'use strict';

const { isIpv4, inCidr, networkAddr } = require('../core/net');
const { parseWin32RoutePrint, inferTopology, isVpnIface } = require('./common');

function isLikelyHomeLan(ip) {
  return isIpv4(ip) && (
    inCidr(ip, '192.168.0.0', 16)
    || inCidr(ip, '172.16.0.0', 12)
  );
}

function mapWinRoutes(parsed) {
  const { routes, ifaces } = parsed;
  const vpnAdapter = ifaces.find((i) => isVpnIface(i.name));
  const lanAdapter = ifaces.find((i) => i.name && !isVpnIface(i.name) && !/loopback/i.test(i.name));
  const defaults = routes.filter((r) => r.prefix === 0 && r.dest === '0.0.0.0');
  const lanDef = defaults.find((d) => isLikelyHomeLan(d.gw) || isLikelyHomeLan(d.ifaceIp))
    || (defaults.length > 1 ? defaults.reduce((a, b) => ((a.metric || 0) >= (b.metric || 0) ? a : b)) : null);
  const vpnDef = defaults.find((d) => d !== lanDef) || (vpnAdapter ? defaults[0] : null);

  return routes.map((r) => {
    let iface = r.ifaceIp;
    if (lanDef && r.ifaceIp === lanDef.ifaceIp && lanAdapter) iface = lanAdapter.name;
    else if (vpnDef && r.ifaceIp === vpnDef.ifaceIp && vpnAdapter) iface = vpnAdapter.name;
    else if (r.prefix === 0 && r === lanDef && lanAdapter) iface = lanAdapter.name;
    else if (r.prefix === 0 && r === vpnDef && vpnAdapter) iface = vpnAdapter.name;
    return { ...r, iface };
  });
}

function ifaceObjects(parsed, mapped) {
  const defaults = mapped.filter((r) => r.prefix === 0);
  return (parsed.ifaces || []).map((i) => {
    const def = defaults.find((r) => r.iface === i.name);
    const addr = def && def.ifaceIp ? def.ifaceIp : null;
    let prefix = 24;
    const onlink = parsed.routes.find((r) => (
      addr && r.ifaceIp === addr && r.prefix > 0 && r.prefix < 32 && !r.gw
    ));
    if (onlink) prefix = onlink.prefix;
    else if (addr) {
      const host = parsed.routes.find((r) => r.dest === addr && r.prefix === 32);
      if (host) prefix = 32;
    }
    return { name: i.name, addrs: addr ? [{ addr, prefix }] : [] };
  });
}

function detectFromPrint(text) {
  const parsed = parseWin32RoutePrint(text);
  const mapped = mapWinRoutes(parsed);
  return inferTopology(mapped, ifaceObjects(parsed, mapped), 'win32');
}

function create(execImpl, opts = {}) {
  const { createExec } = require('./exec');
  const { ignoreExists, ignoreMissing, winMask } = require('./mutate');
  const { assertSafeIpv4, assertSafePrefix } = require('../core/net');
  const { parseNetstatTcp, stdoutOrEmpty } = require('./connections');
  const exec = createExec(execImpl);

  async function isAdmin() {
    if (typeof opts.isAdmin === 'function') return opts.isAdmin();
    try {
      await exec('net', ['session']);
      return true;
    } catch {
      return false;
    }
  }

  async function listRoutes() {
    const { stdout } = await exec('route', ['print', '-4']);
    return parseWin32RoutePrint(stdout).routes;
  }

  async function detect() {
    let stdout = '';
    try {
      const r = await exec('route', ['print', '-4']);
      stdout = r.stdout;
    } catch {
      stdout = '';
    }
    return detectFromPrint(stdout);
  }

  async function addCidr(route) {
    assertSafeIpv4(route.dest);
    assertSafePrefix(route.prefix);
    if (route.gw) assertSafeIpv4(route.gw);
    await ignoreExists(() => exec('route', ['add', route.dest, 'mask', winMask(route), route.gw || '0.0.0.0']));
  }

  async function addHost(route) {
    assertSafeIpv4(route.dest);
    if (route.gw) assertSafeIpv4(route.gw);
    await ignoreExists(() => exec('route', ['add', route.dest, 'mask', '255.255.255.255', route.gw || '0.0.0.0']));
  }

  async function del(route) {
    assertSafeIpv4(route.dest);
    const prefix = route.prefix == null ? 32 : route.prefix;
    assertSafePrefix(prefix);
    await ignoreMissing(() => exec('route', ['delete', route.dest, 'mask', winMask({ prefix })]));
  }

  async function listConnections() {
    const stdout = await stdoutOrEmpty(exec, 'netstat', ['-n', '-p', 'TCP']);
    return parseNetstatTcp(stdout);
  }

  return { detect, listRoutes, listConnections, addCidr, addHost, del, isAdmin, parseRoutes: (t) => parseWin32RoutePrint(t).routes };
}

module.exports = {
  create,
  parseRoutes: (t) => parseWin32RoutePrint(t).routes,
  parsePrint: parseWin32RoutePrint,
  detectFromPrint,
};
