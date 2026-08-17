'use strict';

const { isIpv4, isIpv6, maskToPrefix, withZone } = require('../core/net');

function normIfaceName(name) {
  return String(name || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function isVpnIface(name) {
  const n = normIfaceName(name);
  if (!n) return false;
  if (n === 'lo' || n === 'lo0' || n.startsWith('loopback')) return false;
  if (/^(utun|tun|tap|ppp|ipsec|wg)\d*$/i.test(n)) return true;
  if (n.startsWith('utun') || n.startsWith('tun') || n.startsWith('tap')) return true;
  if (n.startsWith('ppp') || n.startsWith('ipsec') || n.startsWith('wg')) return true;
  if (n.includes('gpd') || n.includes('pangp') || n.includes('globalprotect') || n.includes('global protect')) return true;
  if (n.includes('palo alto') || n.includes('paloalto') || /\bpan\s*gp\b/.test(n)) return true;
  if (n.includes('wintun') || n.includes('wireguard')) return true;
  if (n.includes('anyconnect') || n.includes('cscotun') || n.includes('fortissl') || n.includes('forticlient') || n.includes('fortinet')) return true;
  if (n.includes('tap-windows') || n.includes('tap0901') || n.includes('wan miniport')) return true;
  if (n.includes('zscaler') || n.includes('checkpoint') || n.includes('check point') || n.includes('sonicwall')) return true;
  if (n.includes('openvpn') || n.includes('softether')) return true;
  if (n.includes('vpn')) return true;
  return false;
}

function isIgnoredIface(name) {
  const n = normIfaceName(name);
  if (!n) return true;
  if (n === 'lo' || n === 'lo0' || n.includes('loopback')) return true;
  if (/\bbluetooth\b/.test(n)) return true;
  if (/hyper-v|\bvethernet\b|vmware|virtualbox|\bdocker\b|\bwsl\b/.test(n)) return true;
  if (/\bteredo\b|\bisatap\b|\b6to4\b/.test(n)) return true;
  if (/wi-?fi direct|hosted network|microsoft hosted/.test(n)) return true;
  return false;
}

function isWifiIface(name) {
  const n = normIfaceName(name);
  if (!n || isVpnIface(n) || isIgnoredIface(n)) return false;
  return /\bwi-?fi\b|\bwifi\b|\bwlan\b|\bwireless\b|802\.11|ไร้สาย/.test(n);
}

function isLanIface(name) {
  const n = normIfaceName(name);
  if (!n || isVpnIface(n) || isIgnoredIface(n)) return false;
  if (isWifiIface(n)) return true;
  if (/\bethernet\b/.test(n)) return true;
  if (/local area connection/.test(n)) return true;
  if (/\bgigabit\b/.test(n)) return true;
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
  for (const line of String(text).split(/\r?\n/)) {
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
      family: 'inet',
    });
  }
  return routes;
}

function parseIfconfig(text) {
  const ifaces = [];
  let current = null;
  for (const line of String(text).split(/\r?\n/)) {
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
      current.addrs.push({ addr: inet[1], prefix: prefix == null ? 24 : prefix, family: 'inet' });
    }
    const inet6 = /^\s+inet6\s+(\S+)\s+prefixlen\s+(\d+)/i.exec(line);
    if (inet6 && isIpv6(inet6[1])) {
      current.addrs.push({ addr: inet6[1], prefix: Number(inet6[2]), family: 'inet6' });
    }
  }
  return ifaces;
}

function parseLinuxIpRoute(text) {
  const routes = [];
  for (const line of String(text).split(/\r?\n/)) {
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
    routes.push({ dest, prefix, gw, iface, src, metric, flags: '', inactive: false, host: prefix === 32, family: 'inet' });
  }
  return routes;
}

function parseLinuxIpAddr(text) {
  const ifaces = [];
  let current = null;
  for (const line of String(text).split(/\r?\n/)) {
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

function parseWin32IfaceLine(line) {
  const m = /^\s*(\d+)\.{2,}(.*)$/.exec(line);
  if (!m) return null;
  let rest = m[2].trim();
  rest = rest.replace(/^(?:[0-9a-f]{2}[- ]){5}[0-9a-f]{2}\s*/i, '');
  rest = rest.replace(/^\.{2,}\s*/, '').trim();
  if (!rest) return null;
  return { index: Number(m[1]), name: rest, addrs: [] };
}

function isOnLinkGw(raw) {
  const s = String(raw || '').trim();
  if (!s) return false;
  if (/^on-?link$/i.test(s)) return true;
  if (/^บนลิงก์$/i.test(s)) return true;
  return false;
}

function parseWin32RouteLine(line) {
  if (/Network Destination|Default Gateway|ปลายทาง|เกตเวย์|Netzwerkziel|Destination réseau/i.test(line)) return null;
  const parts = line.trim().split(/\s+/);
  if (parts.length < 5) return null;
  if (!isIpv4(parts[0]) || !isIpv4(parts[1])) return null;
  const dest = parts[0];
  const prefix = parseWinMask(parts[1]);
  const gwRaw = parts[2];
  let gw = null;
  let ifaceIp = null;
  let metric = Number(parts[4]);
  if (isOnLinkGw(gwRaw)) {
    ifaceIp = isIpv4(parts[3]) ? parts[3] : null;
  } else if (isIpv4(gwRaw) && isIpv4(parts[3])) {
    gw = gwRaw;
    ifaceIp = parts[3];
  } else if (isIpv4(parts[3]) && /^\d+$/.test(parts[4])) {
    ifaceIp = parts[3];
    metric = Number(parts[4]);
  } else {
    return null;
  }
  return {
    dest,
    prefix,
    gw: isIpv4(gw) ? gw : null,
    iface: ifaceIp,
    ifaceIp,
    metric: Number.isFinite(metric) ? metric : null,
    flags: '',
    inactive: false,
    host: prefix === 32,
    family: 'inet',
  };
}

function parseWin32RoutePrint(text) {
  const ifaces = [];
  const routes = [];
  const lines = String(text).replace(/\r\n/g, '\n').split('\n');
  let section = 'start';
  for (const line of lines) {
    if (/Interface List|รายการอินเทอร์เฟซ|Schnittstellenliste|Liste des interfaces|Elenco interfacce/i.test(line)) {
      section = 'ifaces';
      continue;
    }
    if (/IPv4 Route Table|ตารางเส้นทาง IPv4|IPv4-Routentabelle|Table de routes IPv4|Tabella route IPv4/i.test(line)) {
      section = 'table';
      continue;
    }
    if (/Active Routes:|เส้นทางที่ใช้งาน|Aktive Routen|Itinéraires actifs|Route attive/i.test(line)) {
      section = 'routes';
      continue;
    }
    if (/Persistent Routes:|เส้นทางถาวร|Persistente Routen|Itinéraires persistants|Route persistenti/i.test(line)) {
      section = 'persistent';
      continue;
    }
    const iface = parseWin32IfaceLine(line);
    if (iface && (section === 'ifaces' || section === 'start')) {
      if (!ifaces.some((i) => i.index === iface.index && i.name === iface.name)) ifaces.push(iface);
      continue;
    }
    if (section === 'persistent') continue;
    const route = parseWin32RouteLine(line);
    if (route && (section === 'routes' || section === 'table' || section === 'start')) {
      routes.push(route);
    }
  }
  return { routes, ifaces };
}

function adapterNameFromHeader(header) {
  const h = String(header || '').trim().replace(/:$/, '');
  if (!h) return null;
  if (/windows ip configuration|ip-konfiguration|configuration ip de windows/i.test(h)) return null;
  const named = /(?:adapter|อะแดปเตอร์|アダプター|어댑터|carte réseau)\s+(.+)$/i.exec(h);
  if (named) return named[1].trim();
  return h;
}

function parseWin32Ipconfig(text) {
  const names = Object.create(null);
  const gateways = Object.create(null);
  const adapters = [];
  let current = null;
  for (const line of String(text).replace(/\r\n/g, '\n').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (!/^\s/.test(line) && /:\s*$/.test(trimmed) && !trimmed.includes('. .')) {
      const name = adapterNameFromHeader(trimmed);
      if (name) {
        current = { name, ips: [], gw: null };
        adapters.push(current);
      } else {
        current = null;
      }
      continue;
    }
    if (!current) continue;
    const ipv4 = /(?:IPv4(?: Address|-Adresse)?|Adresse IPv4|ที่อยู่ IPv4).*?:\s*(\d+\.\d+\.\d+\.\d+)/i.exec(trimmed);
    if (ipv4 && isIpv4(ipv4[1])) {
      names[ipv4[1]] = current.name;
      current.ips.push(ipv4[1]);
      if (current.gw) gateways[ipv4[1]] = current.gw;
      continue;
    }
    const gw = /(?:Default Gateway|Standardgateway|เกตเวย์เริ่มต้น|Passerelle par défaut).*?:\s*(\S+)/i.exec(trimmed);
    if (gw && isIpv4(gw[1])) {
      current.gw = gw[1];
      for (const ip of current.ips) gateways[ip] = gw[1];
    }
  }
  return { names, gateways, adapters };
}

function firstAddr(ifaces, name) {
  const found = (ifaces || []).find((i) => i.name === name);
  if (!found || !found.addrs || !found.addrs.length) return null;
  const v4 = found.addrs.find((a) => a.family !== 'inet6' && isIpv4(a.addr));
  return v4 || found.addrs[0] || null;
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

function parseDarwinInet6Dest(raw) {
  if (raw === 'default') return { dest: '::', prefix: 0 };
  if (raw.includes('/')) {
    const [d, p] = raw.split('/');
    const prefix = Number(p);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return null;
    if (!isIpv6(d)) return null;
    return { dest: d, prefix };
  }
  if (isIpv6(raw)) return { dest: raw, prefix: 128 };
  return null;
}

function parseDarwinNetstat6(text) {
  const routes = [];
  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (/^(Routing tables|Internet:|Internet6:|Destination)/i.test(trimmed)) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 4) continue;
    const destInfo = parseDarwinInet6Dest(parts[0]);
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
      gw: isIpv6(gw) ? gw : null,
      gwRaw: gw,
      flags,
      iface,
      inactive: flags.includes('I'),
      host: destInfo.prefix === 128 || flags.includes('H'),
      family: 'inet6',
    });
  }
  return routes;
}

function parseLinuxIpRoute6(text) {
  const routes = [];
  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    let dest = null;
    let prefix = null;
    if (parts[0] === 'default') {
      dest = '::';
      prefix = 0;
    } else if (parts[0].includes('/')) {
      const [d, p] = parts[0].split('/');
      dest = d;
      prefix = Number(p);
      if (!isIpv6(dest) || !Number.isInteger(prefix)) continue;
    } else if (isIpv6(parts[0])) {
      dest = parts[0];
      prefix = 128;
    } else {
      continue;
    }
    let gw = null;
    let iface = null;
    let metric = null;
    for (let i = 0; i < parts.length; i += 1) {
      if (parts[i] === 'via' && parts[i + 1]) gw = parts[i + 1];
      if (parts[i] === 'dev' && parts[i + 1]) iface = parts[i + 1];
      if (parts[i] === 'metric' && parts[i + 1]) metric = Number(parts[i + 1]);
    }
    routes.push({
      dest,
      prefix,
      gw: gw && isIpv6(gw) ? gw : null,
      iface,
      metric,
      flags: '',
      inactive: false,
      host: prefix === 128,
      family: 'inet6',
    });
  }
  return routes;
}

function inferIpv6(routes6, topo) {
  const lanIface = topo && topo.lan && topo.lan.iface;
  const vpnIface = topo && topo.vpn && topo.vpn.iface;
  const defaults = (routes6 || []).filter((r) => r.prefix === 0 && (r.dest === '::' || r.dest === '0:0:0:0:0:0:0:0'));
  let lanDef = defaults.find((r) => lanIface && r.iface === lanIface && r.gw && isIpv6(r.gw) && !r.inactive);
  if (!lanDef) {
    lanDef = defaults.find((r) => lanIface && r.iface === lanIface && r.gw && isIpv6(r.gw));
  }
  const vpnDef = defaults.find((r) => vpnIface && r.iface === vpnIface);
  const rawGw6 = lanDef && lanDef.gw ? lanDef.gw : null;
  const gw6 = rawGw6 && topo && topo.os === 'darwin' ? withZone(rawGw6, lanIface) : rawGw6;
  return {
    ...topo,
    routes6: routes6 || [],
    lan: { ...(topo.lan || {}), gw6: gw6 || null },
    vpn: { ...(topo.vpn || {}), gw6: vpnDef && vpnDef.gw ? vpnDef.gw : null },
  };
}

module.exports = {
  isVpnIface,
  isWifiIface,
  isLanIface,
  parseWin32Ipconfig,
  parseDarwinDest,
  parseDarwinInet6Dest,
  parseDarwinNetstat,
  parseDarwinNetstat6,
  parseIfconfig,
  parseLinuxIpRoute,
  parseLinuxIpRoute6,
  parseLinuxIpAddr,
  parseWin32RoutePrint,
  inferTopology,
  inferIpv6,
};
