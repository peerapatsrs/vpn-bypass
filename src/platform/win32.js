'use strict';

const { isIpv4, inCidr, networkAddr } = require('../core/net');
const {
  parseWin32RoutePrint,
  parseWin32Ipconfig,
  inferTopology,
  isVpnIface,
  isWifiIface,
  isLanIface,
} = require('./common');

function isLoopName(name) {
  const n = String(name || '').toLowerCase();
  return n === 'lo' || n === 'lo0' || n.includes('loopback');
}

function isLikelyHomeLan(ip) {
  return isIpv4(ip) && inCidr(ip, '192.168.0.0', 16);
}

function connectedPrefix(routes, ifaceIp) {
  const hits = (routes || []).filter((r) => (
    r.ifaceIp === ifaceIp
    && !r.gw
    && r.prefix > 0
    && r.prefix < 32
    && r.dest !== '127.0.0.0'
    && r.dest !== '224.0.0.0'
  ));
  if (hits.length) return Math.min(...hits.map((r) => r.prefix));
  const hostOnly = (routes || []).some((r) => (
    r.ifaceIp === ifaceIp && r.dest === ifaceIp && r.prefix === 32 && !r.gw
  ));
  return hostOnly ? 32 : null;
}

function vpnScore(d, routes) {
  let s = 0;
  const ip = d.ifaceIp;
  const gw = d.gw;
  if (isLikelyHomeLan(ip) || isLikelyHomeLan(gw)) s -= 10;
  if (ip && inCidr(ip, '100.64.0.0', 10)) s += 6;
  if (gw && inCidr(gw, '100.64.0.0', 10)) s += 4;
  if (ip && inCidr(ip, '10.0.0.0', 8)) s += 3;
  if (gw && inCidr(gw, '10.0.0.0', 8)) s += 2;
  if (ip && inCidr(ip, '172.16.0.0', 12)) s += 2;
  if (gw && inCidr(gw, '172.16.0.0', 12)) s += 1;
  const prefix = connectedPrefix(routes, ip);
  if (prefix === 32) s += 5;
  else if (prefix != null && prefix >= 30) s += 4;
  else if (prefix != null && prefix <= 24) s -= 3;
  if (d.metric != null && d.metric <= 2) s += 2;
  else if (d.metric != null && d.metric >= 200) s -= 2;
  return s;
}

function recoverLanDef(routes, vpnDef, gateways) {
  const skip = vpnDef && vpnDef.ifaceIp;
  const candidates = (routes || []).filter((r) => (
    !r.gw
    && r.prefix >= 8
    && r.prefix <= 28
    && r.ifaceIp
    && r.ifaceIp !== skip
    && r.dest !== '127.0.0.0'
    && r.dest !== '224.0.0.0'
    && !String(r.dest).startsWith('255.')
  ));
  const home = candidates.find((r) => isLikelyHomeLan(r.ifaceIp) || isLikelyHomeLan(r.dest));
  const hit = home || candidates.find((r) => r.prefix <= 24) || null;
  if (!hit) return null;
  const gw = (gateways && hit.ifaceIp && gateways[hit.ifaceIp]) || null;
  return {
    dest: '0.0.0.0',
    prefix: 0,
    gw,
    iface: hit.ifaceIp,
    ifaceIp: hit.ifaceIp,
    metric: hit.metric,
    recovered: true,
  };
}

function pickWinDefaults(routes, gateways) {
  const defaults = (routes || []).filter((r) => r.prefix === 0 && r.dest === '0.0.0.0');
  const ranked = defaults.slice().sort((a, b) => vpnScore(b, routes) - vpnScore(a, routes));

  if (defaults.length === 0) {
    return { defaults, lanDef: recoverLanDef(routes, null, gateways), vpnDef: null };
  }

  if (defaults.length === 1) {
    const only = defaults[0];
    if (vpnScore(only, routes) > 0) {
      return { defaults, lanDef: recoverLanDef(routes, only, gateways), vpnDef: only };
    }
    return { defaults, lanDef: only, vpnDef: null };
  }

  const home = defaults.filter((d) => isLikelyHomeLan(d.gw) || isLikelyHomeLan(d.ifaceIp));
  const rest = defaults.filter((d) => !home.includes(d));
  let lanDef = null;
  let vpnDef = null;
  if (home.length && rest.length) {
    lanDef = home.slice().sort((a, b) => vpnScore(a, routes) - vpnScore(b, routes))[0];
    vpnDef = rest.slice().sort((a, b) => vpnScore(b, routes) - vpnScore(a, routes))[0];
  } else {
    vpnDef = ranked[0];
    lanDef = ranked[ranked.length - 1];
    if (vpnDef === lanDef || vpnScore(vpnDef, routes) <= 0) {
      vpnDef = null;
    }
    if (vpnDef && lanDef && vpnDef.ifaceIp === lanDef.ifaceIp) {
      lanDef = recoverLanDef(routes, vpnDef, gateways);
    }
  }
  if (vpnDef && !lanDef) lanDef = recoverLanDef(routes, vpnDef, gateways);
  if (lanDef && lanDef.recovered && !lanDef.gw && gateways && lanDef.ifaceIp) {
    lanDef.gw = gateways[lanDef.ifaceIp] || null;
  }
  return { defaults, lanDef, vpnDef };
}

function pickLanAdapter(ifaces, preferredName, excludeNames) {
  const list = ifaces || [];
  const skip = new Set((excludeNames || []).filter(Boolean));
  const usable = (i) => i && i.name && !skip.has(i.name) && !isLoopName(i.name) && !isVpnIface(i.name);
  if (preferredName && !skip.has(preferredName) && !isLoopName(preferredName) && !isVpnIface(preferredName)) {
    const hit = list.find((i) => i.name === preferredName);
    if (hit) return hit;
    return { name: preferredName, index: -1 };
  }
  const wifi = list.find((i) => usable(i) && isWifiIface(i.name));
  if (wifi) return wifi;
  const lan = list.find((i) => usable(i) && isLanIface(i.name));
  if (lan) return lan;
  return list.find((i) => usable(i)) || null;
}

function vpnAdapterName(ifaces, vpnDef, ipNames) {
  const named = (ifaces || []).find((i) => isVpnIface(i.name));
  if (named) return named.name;
  const fromIp = vpnDef && vpnDef.ifaceIp ? ipNames[vpnDef.ifaceIp] : null;
  if (fromIp && isVpnIface(fromIp)) return fromIp;
  return vpnDef ? 'vpn' : null;
}

function lanAdapterName(ifaces, lanDef, ipNames, vpnFromIp) {
  const fromIp = lanDef && lanDef.ifaceIp ? ipNames[lanDef.ifaceIp] : null;
  const exclude = vpnFromIp ? [vpnFromIp] : [];
  const picked = pickLanAdapter(ifaces, fromIp, exclude);
  return (picked && picked.name) || fromIp || 'lan';
}

function mapWinRoutes(parsed, ipNames = {}, gateways = {}) {
  const { routes, ifaces } = parsed;
  const { lanDef, vpnDef } = pickWinDefaults(routes, gateways);
  const vpnFromIp = vpnDef && vpnDef.ifaceIp ? ipNames[vpnDef.ifaceIp] : null;
  const lanName = lanDef ? lanAdapterName(ifaces, lanDef, ipNames, vpnFromIp) : null;
  const vpnName = vpnAdapterName(ifaces, vpnDef, ipNames);

  const mapped = routes.map((r) => {
    let iface = r.ifaceIp;
    const fromIp = r.ifaceIp ? ipNames[r.ifaceIp] : null;
    if (vpnDef && r.ifaceIp === vpnDef.ifaceIp && vpnName) iface = vpnName;
    else if (lanDef && r.ifaceIp === lanDef.ifaceIp && lanName) iface = lanName;
    else if (fromIp) iface = fromIp;
    return { ...r, iface };
  });
  if (lanDef && lanDef.recovered && lanDef.gw && lanName) {
    const exists = mapped.some((r) => r.prefix === 0 && r.iface === lanName && r.gw === lanDef.gw);
    if (!exists) {
      mapped.push({
        dest: '0.0.0.0',
        prefix: 0,
        gw: lanDef.gw,
        iface: lanName,
        ifaceIp: lanDef.ifaceIp,
        metric: lanDef.metric,
        flags: '',
        inactive: false,
        host: false,
        family: 'inet',
        recovered: true,
      });
    }
  }
  return mapped;
}

function ifaceObjects(parsed, mapped, ipNames = {}, gateways = {}) {
  const { lanDef, vpnDef } = pickWinDefaults(parsed.routes || [], gateways);
  const defaults = mapped.filter((r) => r.prefix === 0);
  const vpnFromIp = vpnDef && vpnDef.ifaceIp ? ipNames[vpnDef.ifaceIp] : null;
  const rows = (parsed.ifaces || []).map((i) => {
    const def = defaults.find((r) => r.iface === i.name);
    const addrFromIp = Object.keys(ipNames).find((ip) => ipNames[ip] === i.name);
    const addr = (def && def.ifaceIp) || addrFromIp || null;
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
  if (vpnDef && vpnDef.ifaceIp && !rows.some((i) => i.addrs.some((a) => a.addr === vpnDef.ifaceIp))) {
    const name = mapped.find((r) => r.ifaceIp === vpnDef.ifaceIp && r.iface && !isIpv4(r.iface));
    rows.push({
      name: (name && name.iface) || 'vpn',
      addrs: [{ addr: vpnDef.ifaceIp, prefix: 32 }],
    });
  }
  if (lanDef && lanDef.ifaceIp && !rows.some((i) => i.addrs.some((a) => a.addr === lanDef.ifaceIp))) {
    rows.push({
      name: lanAdapterName(parsed.ifaces, lanDef, ipNames, vpnFromIp),
      addrs: [{ addr: lanDef.ifaceIp, prefix: 24 }],
    });
  }
  return rows;
}

function parseIpInfo(text) {
  if (!text) return { names: Object.create(null), gateways: Object.create(null), adapters: [] };
  const parsed = parseWin32Ipconfig(text);
  if (parsed && parsed.names) return parsed;
  return { names: parsed || Object.create(null), gateways: Object.create(null), adapters: [] };
}

function detectFromPrint(text, ipconfigText) {
  const parsed = parseWin32RoutePrint(text);
  const ipinfo = parseIpInfo(ipconfigText);
  const mapped = mapWinRoutes(parsed, ipinfo.names, ipinfo.gateways);
  const topo = inferTopology(mapped, ifaceObjects(parsed, mapped, ipinfo.names, ipinfo.gateways), 'win32');
  const { lanDef } = pickWinDefaults(parsed.routes || [], ipinfo.gateways);
  if (lanDef && lanDef.gw && (!topo.lan || !topo.lan.gw)) {
    const prefix = topo.lan && topo.lan.prefix != null ? topo.lan.prefix : 24;
    topo.lan = {
      ...(topo.lan || {}),
      iface: topo.lan && topo.lan.iface ? topo.lan.iface : lanAdapterName(parsed.ifaces, lanDef, ipinfo.names),
      addr: topo.lan && topo.lan.addr ? topo.lan.addr : lanDef.ifaceIp,
      gw: lanDef.gw,
      prefix,
      network: lanDef.ifaceIp ? networkAddr(lanDef.ifaceIp, prefix) : null,
    };
  }
  return topo;
}

function create(execImpl, opts = {}) {
  const { createExec } = require('./exec');
  const { ignoreExists, ignoreMissing, addOrChange, winMask } = require('./mutate');
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
    let ipconfigText = '';
    try {
      ipconfigText = (await exec('ipconfig')).stdout || '';
    } catch {
      ipconfigText = '';
    }
    return detectFromPrint(stdout, ipconfigText);
  }

  async function addCidr(route) {
    assertSafeIpv4(route.dest);
    assertSafePrefix(route.prefix);
    if (route.gw) assertSafeIpv4(route.gw);
    const gw = route.gw || '0.0.0.0';
    const mask = winMask(route);
    await addOrChange(
      () => exec('route', ['add', route.dest, 'mask', mask, gw]),
      () => exec('route', ['change', route.dest, 'mask', mask, gw]),
    );
  }

  async function addHost(route) {
    assertSafeIpv4(route.dest);
    if (route.gw) assertSafeIpv4(route.gw);
    const gw = route.gw || '0.0.0.0';
    await addOrChange(
      () => exec('route', ['add', route.dest, 'mask', '255.255.255.255', gw]),
      () => exec('route', ['change', route.dest, 'mask', '255.255.255.255', gw]),
    );
  }

  async function changeCidr(route) {
    assertSafeIpv4(route.dest);
    assertSafePrefix(route.prefix == null ? 32 : route.prefix);
    if (route.gw) assertSafeIpv4(route.gw);
    const gw = route.gw || '0.0.0.0';
    const mask = winMask(route);
    try {
      await exec('route', ['change', route.dest, 'mask', mask, gw]);
    } catch (err) {
      await ignoreExists(() => exec('route', ['add', route.dest, 'mask', mask, gw]));
    }
  }

  async function changeHost(route) {
    return changeCidr({ ...route, prefix: 32 });
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

  const dns = require('./dnsWin32').create({ exec });

  return {
    detect, listRoutes, listConnections, addCidr, addHost, changeCidr, changeHost, del, isAdmin,
    parseRoutes: (t) => parseWin32RoutePrint(t).routes,
    readDns: dns.readDns,
    applyDns: dns.applyDns,
    restoreDns: dns.restoreDns,
    inspectDns: dns.inspectDns,
    dnsStatus: dns.dnsStatus,
  };
}

module.exports = {
  create,
  parseRoutes: (t) => parseWin32RoutePrint(t).routes,
  parsePrint: parseWin32RoutePrint,
  detectFromPrint,
};
