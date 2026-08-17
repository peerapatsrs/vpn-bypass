'use strict';

const { isIpv4, networkAddr } = require('../core/net');
const {
  parseWin32RoutePrint,
  parseWin32Ipconfig,
  parseWin32NetRoute,
  inferTopology,
  isVpnIface,
  isWifiIface,
  isLanIface,
  isLoopName,
  pickIpv4Defaults,
} = require('./common');

const PS_NETROUTE_CMD = [
  '$a = @{}',
  'Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { if (-not $a.ContainsKey($_.InterfaceIndex)) { $a[$_.InterfaceIndex] = $_.IPAddress } }',
  'Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $ip = $a[$_.InterfaceIndex]; if (-not $ip) { $ip = "0.0.0.0" }; Write-Output ($_.DestinationPrefix + " " + $_.NextHop + " " + $ip + " " + $_.RouteMetric) }',
].join('; ');

function ipv4Defaults(parsed) {
  return (parsed && parsed.routes || []).filter((r) => r.prefix === 0 && r.dest === '0.0.0.0');
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
  const fromIp = vpnDef && vpnDef.ifaceIp ? ipNames[vpnDef.ifaceIp] : null;
  if (fromIp) return fromIp;
  if (vpnDef && vpnDef.iface && !isIpv4(vpnDef.iface) && !isLoopName(vpnDef.iface)) {
    return vpnDef.iface;
  }
  if (vpnDef && vpnDef.ifaceIp && isIpv4(vpnDef.ifaceIp)) return vpnDef.ifaceIp;
  const named = (ifaces || []).find((i) => isVpnIface(i.name));
  if (named) return named.name;
  return vpnDef ? 'vpn' : null;
}

function lanAdapterName(ifaces, lanDef, ipNames, vpnFromIp) {
  const fromIp = lanDef && lanDef.ifaceIp ? ipNames[lanDef.ifaceIp] : null;
  const exclude = vpnFromIp ? [vpnFromIp] : [];
  const picked = pickLanAdapter(ifaces, fromIp, exclude);
  return (picked && picked.name) || fromIp || (lanDef && lanDef.ifaceIp) || 'lan';
}

function mapWinRoutes(parsed, ipNames = {}, gateways = {}) {
  const { routes, ifaces } = parsed;
  const { lanDef, vpnDef } = pickIpv4Defaults(routes, { gateways });
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
  const { lanDef, vpnDef } = pickIpv4Defaults(parsed.routes || [], { gateways });
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

function detectFromParsed(parsed, ipconfigText) {
  const ipinfo = parseIpInfo(ipconfigText);
  const mapped = mapWinRoutes(parsed, ipinfo.names, ipinfo.gateways);
  const ifaces = ifaceObjects(parsed, mapped, ipinfo.names, ipinfo.gateways);
  const topo = inferTopology(mapped, ifaces, 'win32', { gateways: ipinfo.gateways });
  const { lanDef } = pickIpv4Defaults(parsed.routes || [], { gateways: ipinfo.gateways });
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

function detectFromPrint(text, ipconfigText) {
  return detectFromParsed(parseWin32RoutePrint(text), ipconfigText);
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

  async function stdoutOf(file, args) {
    try {
      const r = await exec(file, args);
      return (r && r.stdout) || '';
    } catch (err) {
      return (err && err.stdout) || '';
    }
  }

  async function collectParsedRoutes() {
    let parsed = parseWin32RoutePrint(await stdoutOf('route', ['print', '-4']));
    if (!ipv4Defaults(parsed).length) {
      const parsedAll = parseWin32RoutePrint(await stdoutOf('route', ['print']));
      const betterDefaults = ipv4Defaults(parsedAll).length > ipv4Defaults(parsed).length;
      const betterRoutes = parsedAll.routes.length > parsed.routes.length;
      if (betterDefaults || betterRoutes) parsed = parsedAll;
    }
    if (!parsed.routes.length) {
      const psArgs = [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        PS_NETROUTE_CMD,
      ];
      let parsedPs = parseWin32NetRoute(await stdoutOf('powershell', psArgs));
      if (!parsedPs.routes.length) {
        parsedPs = parseWin32NetRoute(await stdoutOf('powershell.exe', psArgs));
      }
      if (parsedPs.routes.length) parsed = parsedPs;
    }
    return parsed;
  }

  async function listRoutes() {
    return (await collectParsedRoutes()).routes;
  }

  async function detect() {
    const parsed = await collectParsedRoutes();
    const ipconfigText = await stdoutOf('ipconfig', []);
    return detectFromParsed(parsed, ipconfigText);
  }

  async function addCidr(route) {
    assertSafeIpv4(route.dest);
    assertSafePrefix(route.prefix);
    if (route.gw) assertSafeIpv4(route.gw);
    const gw = route.gw || '0.0.0.0';
    const mask = winMask(route);
    const argsAdd = ['add', route.dest, 'mask', mask, gw];
    const argsChange = ['change', route.dest, 'mask', mask, gw];
    await addOrChange(
      () => exec('route', argsAdd),
      () => exec('route', argsChange),
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
  detectFromParsed,
};
