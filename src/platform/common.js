'use strict';

const { isIpv4, maskToPrefix } = require('../core/net');

function isVpnIface(name) {
  const n = String(name || '').toLowerCase();
  if (!n) return false;
  if (n === 'lo' || n === 'lo0' || n.startsWith('loopback')) return false;
  if (/^(utun|tun|tap|ppp|ipsec|wg)\d*$/i.test(n)) return true;
  if (n.startsWith('utun') || n.startsWith('tun') || n.startsWith('tap')) return true;
  if (n.startsWith('ppp') || n.startsWith('ipsec') || n.startsWith('wg')) return true;
  if (n.includes('gpd') || n.includes('pangp') || n.includes('globalprotect')) return true;
  if (n.includes('wintun') || n.includes('wireguard')) return true;
  if (n.includes('anyconnect') || n.includes('cscotun') || n.includes('fortissl')) return true;
  if (n.includes('vpn')) return true;
  return false;
}

function expandPartialIpv4(raw) {
  const parts = String(raw).split('.').filter(Boolean);
  while (parts.length < 4) parts.push('0');
  return parts.join('.');
}

function parseDarwinDest(raw) {
  if (raw === 'default') return { dest: '0.0.0.0', prefix: 0 };
  if (raw.includes(':')) return null;
  if (raw.includes('/')) {
    const [d, p] = raw.split('/');
    const prefix = Number(p);
    if (!Number.isInteger(prefix)) return null;
    return { dest: expandPartialIpv4(d), prefix };
  }
  const dots = (raw.match(/\./g) || []).length;
  if (dots === 3 && isIpv4(raw)) return { dest: raw, prefix: 32 };
  if (dots === 2) return { dest: expandPartialIpv4(raw), prefix: 24 };
  if (dots === 1) return { dest: expandPartialIpv4(raw), prefix: 16 };
  if (dots === 0 && /^\d+$/.test(raw)) return { dest: `${raw}.0.0.0`, prefix: 8 };
  return null;
}

function looksLikeIface(token) {
  return /^[A-Za-z][A-Za-z0-9._-]*$/.test(token) && !/^\d+$/.test(token);
}

function parseDarwinNetstat(text) {
  const routes = [];
  for (const line of String(text).split(/\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (/^(Routing tables|Internet:|Destination|Internet6:)/i.test(trimmed)) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 4) continue;
    const destInfo = parseDarwinDest(parts[0]);
    if (!destInfo) continue;
    const gw = parts[1];
    const flags = parts[2] || '';
    let iface = null;
    for (let i = parts.length - 1; i >= 3; i -= 1) {
      if (/^\d+$/.test(parts[i]) || parts[i] === '!') continue;
      if (looksLikeIface(parts[i])) {
        iface = parts[i];
        break;
      }
    }
    routes.push({
      dest: destInfo.dest,
      prefix: destInfo.prefix,
      gw: isIpv4(gw) ? gw : null,
      gwRaw: gw,
      flags,
      iface,
      inactive: flags.includes('I'),
      host: destInfo.prefix === 32 || flags.includes('H'),
    });
  }
  return routes;
}

function parseIfconfig(text) {
  const ifaces = [];
  let current = null;
  for (const line of String(text).split(/\n/)) {
    const head = /^([A-Za-z0-9._-]+):\s/.exec(line);
    if (head) {
      current = { name: head[1], addrs: [] };
      ifaces.push(current);
      continue;
    }
    if (!current) continue;
    const inet = /^\s+inet\s+(\d+\.\d+\.\d+\.\d+)(?:\s+-->\s+\S+)?\s+netmask\s+(\S+)/i.exec(line);
    if (inet) {
      const prefix = maskToPrefix(inet[2]);
      current.addrs.push({ addr: inet[1], prefix: prefix == null ? 24 : prefix });
    }
  }
  return ifaces;
}

function parseLinuxIpRoute(text) {
  const routes = [];
  for (const line of String(text).split(/\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    let dest = null;
    let prefix = null;
    if (parts[0] === 'default') {
      dest = '0.0.0.0';
      prefix = 0;
    } else if (parts[0].includes('/')) {
      const [d, p] = parts[0].split('/');
      dest = d;
      prefix = Number(p);
    } else if (isIpv4(parts[0])) {
      dest = parts[0];
      prefix = 32;
    } else {
      continue;
    }
    let gw = null;
    let iface = null;
    let src = null;
    let metric = null;
    for (let i = 0; i < parts.length; i += 1) {
      if (parts[i] === 'via' && parts[i + 1]) gw = parts[i + 1];
      if (parts[i] === 'dev' && parts[i + 1]) iface = parts[i + 1];
      if (parts[i] === 'src' && parts[i + 1]) src = parts[i + 1];
      if (parts[i] === 'metric' && parts[i + 1]) metric = Number(parts[i + 1]);
    }
    routes.push({ dest, prefix, gw, iface, src, metric, flags: '', inactive: false, host: prefix === 32 });
  }
  return routes;
}

function parseLinuxIpAddr(text) {
  const ifaces = [];
  let current = null;
  for (const line of String(text).split(/\n/)) {
    const head = /^\d+:\s+([A-Za-z0-9._-]+):/.exec(line);
    if (head) {
      current = { name: head[1], addrs: [] };
      ifaces.push(current);
      continue;
    }
    if (!current) continue;
    const inet = /^\s+inet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)/.exec(line);
    if (inet) {
      current.addrs.push({ addr: inet[1], prefix: Number(inet[2]) });
    }
  }
  return ifaces;
}

function parseWinMask(mask) {
  const p = maskToPrefix(mask);
  return p == null ? 32 : p;
}

function parseWin32RoutePrint(text) {
  const ifaces = [];
  const routes = [];
  const lines = String(text).replace(/\r\n/g, '\n').split('\n');
  let section = 'start';
  for (const line of lines) {
    if (/Interface List/i.test(line)) {
      section = 'ifaces';
      continue;
    }
    if (/IPv4 Route Table/i.test(line) || /Active Routes:/i.test(line)) {
      section = section === 'ifaces' && /IPv4 Route Table/i.test(line) ? 'table' : 'routes';
      if (/Active Routes:/i.test(line)) section = 'routes';
      continue;
    }
    if (/Persistent Routes:/i.test(line)) {
      section = 'persistent';
      continue;
    }
    if (section === 'ifaces') {
      const m = /^\s*(\d+)\.{2,}(.*)$/.exec(line);
      if (m) {
        let rest = m[2].trim();
        rest = rest.replace(/^(?:[0-9a-f]{2}[- ]){5}[0-9a-f]{2}\s*/i, '');
        rest = rest.replace(/^\.{2,}\s*/, '').trim();
        if (rest) ifaces.push({ index: Number(m[1]), name: rest, addrs: [] });
      }
      continue;
    }
    if (section === 'routes') {
      if (/Network Destination/i.test(line) || /Default Gateway/i.test(line)) continue;
      const parts = line.trim().split(/\s+/);
      if (parts.length < 5) continue;
      if (!isIpv4(parts[0]) || !isIpv4(parts[1])) continue;
      const dest = parts[0];
      const prefix = parseWinMask(parts[1]);
      const gwRaw = parts[2];
      const gw = gwRaw === 'On-link' || gwRaw === 'on-link' ? null : gwRaw;
      const ifaceIp = isIpv4(parts[3]) ? parts[3] : null;
      const metric = Number(parts[4]);
      routes.push({
        dest,
        prefix,
        gw: isIpv4(gw) ? gw : null,
        iface: ifaceIp,
        ifaceIp,
        metric: Number.isFinite(metric) ? metric : null,
        flags: '',
        inactive: false,
        host: prefix === 32,
      });
    }
  }
  return { routes, ifaces };
}

function firstAddr(ifaces, name) {
  const found = (ifaces || []).find((i) => i.name === name);
  return found && found.addrs && found.addrs[0] ? found.addrs[0] : null;
}

function inferTopology(routes, ifaces, osName) {
  const ifaceList = ifaces || [];
  const vpnNames = new Set(
    ifaceList.filter((i) => isVpnIface(i.name)).map((i) => i.name),
  );
  for (const r of routes) {
    if (r.iface && isVpnIface(r.iface)) vpnNames.add(r.iface);
  }

  const isLoop = (name) => {
    const n = String(name || '').toLowerCase();
    return n === 'lo' || n === 'lo0' || n.includes('loopback');
  };

  const defaults = routes.filter((r) => r.prefix === 0 && r.dest === '0.0.0.0');
  const vpnDef = defaults.find((r) => r.iface && vpnNames.has(r.iface));
  const lanDef = defaults.find((r) => (
    r.iface
    && !isLoop(r.iface)
    && !vpnNames.has(r.iface)
    && isIpv4(r.gw)
  ));

  let vpnIface = vpnDef && vpnDef.iface
    ? vpnDef.iface
    : [...vpnNames][0] || null;
  if (!vpnIface) {
    const hit = routes.find((r) => r.iface && isVpnIface(r.iface));
    vpnIface = hit ? hit.iface : null;
  }

  const vpnAddrInfo = firstAddr(ifaceList, vpnIface);
  const lanIface = lanDef && lanDef.iface ? lanDef.iface : null;
  const lanAddrInfo = firstAddr(ifaceList, lanIface);

  const vpnCidrs = routes.filter((r) => (
    r.iface
    && vpnIface
    && r.iface === vpnIface
    && r.prefix > 0
    && r.prefix < 32
    && r.dest !== '0.0.0.0'
    && r.dest !== '127.0.0.0'
  )).map((r) => ({ dest: r.dest, prefix: r.prefix, gw: r.gw, iface: r.iface }));

  const vpnUp = Boolean(vpnIface) && defaults.some((r) => r.iface === vpnIface || vpnNames.has(r.iface));
  const prefix = lanAddrInfo && lanAddrInfo.prefix != null ? lanAddrInfo.prefix : 24;
  const lanAddr = lanAddrInfo ? lanAddrInfo.addr : null;

  const outIfaces = ifaceList.map((i) => {
    let role = 'other';
    if (isLoop(i.name)) role = 'loopback';
    else if (vpnIface && i.name === vpnIface) role = 'vpn';
    else if (lanIface && i.name === lanIface) role = 'lan';
    else if (isVpnIface(i.name)) role = 'vpn';
    return {
      name: i.name,
      role,
      addr: i.addrs && i.addrs[0] ? i.addrs[0].addr : null,
      prefix: i.addrs && i.addrs[0] ? i.addrs[0].prefix : null,
    };
  });

  if (vpnIface && !outIfaces.some((i) => i.name === vpnIface)) {
    outIfaces.push({
      name: vpnIface,
      role: 'vpn',
      addr: vpnAddrInfo ? vpnAddrInfo.addr : null,
      prefix: vpnAddrInfo ? vpnAddrInfo.prefix : null,
    });
  }
  if (lanIface && !outIfaces.some((i) => i.name === lanIface)) {
    outIfaces.push({
      name: lanIface,
      role: 'lan',
      addr: lanAddr,
      prefix,
      gw: lanDef ? lanDef.gw : null,
    });
  } else if (lanIface) {
    const row = outIfaces.find((i) => i.name === lanIface);
    if (row) row.gw = lanDef ? lanDef.gw : null;
  }

  return {
    os: osName,
    vpn: {
      up: Boolean(vpnUp || (vpnIface && vpnAddrInfo)),
      iface: vpnIface || null,
      addr: vpnAddrInfo ? vpnAddrInfo.addr : null,
      gw: vpnDef && vpnDef.gw ? vpnDef.gw : null,
      cidrs: vpnCidrs,
    },
    lan: {
      iface: lanIface,
      addr: lanAddr,
      gw: lanDef ? lanDef.gw : null,
      prefix,
      network: lanAddr ? require('../core/net').networkAddr(lanAddr, prefix) : null,
    },
    ifaces: outIfaces,
    routes,
  };
}

module.exports = {
  isVpnIface,
  parseDarwinDest,
  parseDarwinNetstat,
  parseIfconfig,
  parseLinuxIpRoute,
  parseLinuxIpAddr,
  parseWin32RoutePrint,
  inferTopology,
};
