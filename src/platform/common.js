'use strict';

const { isIpv4, isIpv6, maskToPrefix, withZone, inCidr, networkAddr } = require('../core/net');
const { decodeExecOutput } = require('./exec');

function normIfaceName(name) {
  return String(name || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function isVpnIface(name) {
  const n = normIfaceName(name);
  if (!n) return false;
  if (n === 'lo' || n === 'lo0' || n.startsWith('loopback')) return false;
  if (/^(utun|tun|tap|ppp|ipsec|wg|gpd|tailscale|zt|cfd)\d*$/i.test(n)) return true;
  if (n.startsWith('utun') || n.startsWith('tun') || n.startsWith('tap')) return true;
  if (n.startsWith('ppp') || n.startsWith('ipsec') || n.startsWith('wg')) return true;
  if (n.startsWith('tailscale')) return true;
  if (/\b(vpn|tunnel|tun)\b/.test(n) || n.includes('vpn')) return true;
  const markers = [
    'gpd', 'pangp', 'globalprotect', 'global protect', 'palo alto', 'paloalto', 'prisma access',
    'wintun', 'wireguard', 'nordlynx', 'amnezia',
    'anyconnect', 'cscotun', 'acvpn', 'cisco secure client',
    'fortissl', 'forticlient', 'fortinet', 'fortitray',
    'tap-windows', 'tap0901', 'openvpn', 'ovpn', 'softether',
    'wan miniport', 'sstp', 'l2tp', 'pptp', 'ikev2',
    'zscaler', 'ztap', 'checkpoint', 'check point', 'sonicwall', 'netextender',
    'pulse secure', 'pulsesecure', 'juniper', 'network connect', 'ivanti',
    'f5vpn', 'big-ip', 'array networks',
    'mullvad', 'proton', 'surfshark', 'expressvpn', 'windscribe',
    'cyberghost', 'tunnelbear', 'vypr', 'private internet access', 'adguard vpn',
    'cloudflare warp', 'warp', 'zerotier', 'hamachi', 'netbird', 'nebula', 'innernet',
    'outline', 'shadowsocks', 'tun2socks', 'clash', 'sing-box', 'singbox', 'hysteria',
    'v2ray', 'xray', 'openconnect', 'ocserv', 'strongswan', 'libreswan', 'tinc',
    'meraki', 'aruba', 'citrix', 'netscaler', 'always on vpn',
  ];
  return markers.some((m) => n.includes(m));
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
  const lines = decodeExecOutput(text).replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
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

function parseWin32NetRoute(text) {
  const routes = [];
  for (const line of decodeExecOutput(text).replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || /destinationprefix|nexthop|interface/i.test(trimmed)) continue;
    const m = /^(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s*$/.exec(trimmed);
    if (!m) continue;
    const dest = m[1];
    const prefix = m[2] != null ? Number(m[2]) : (dest === '0.0.0.0' ? 0 : 32);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) continue;
    const next = m[3];
    const ifaceIp = m[4];
    const metric = Number(m[5]);
    if (!isIpv4(dest) || !isIpv4(ifaceIp) || ifaceIp === '0.0.0.0') continue;
    const onlink = next === '0.0.0.0' || isOnLinkGw(next);
    const gw = onlink ? null : (isIpv4(next) ? next : null);
    if (!onlink && !gw) continue;
    routes.push({
      dest,
      prefix,
      gw,
      iface: ifaceIp,
      ifaceIp,
      metric: Number.isFinite(metric) ? metric : null,
      flags: '',
      inactive: false,
      host: prefix === 32,
      family: 'inet',
    });
  }
  return { routes, ifaces: [] };
}

function parseWin32Ipconfig(text) {
  const names = Object.create(null);
  const gateways = Object.create(null);
  const adapters = [];
  let current = null;
  for (const line of decodeExecOutput(text).replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n')) {
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

function isLoopName(name) {
  const n = String(name || '').toLowerCase();
  return n === 'lo' || n === 'lo0' || n.includes('loopback');
}

function firstAddr(ifaces, name) {
  const found = (ifaces || []).find((i) => i.name === name);
  if (!found || !found.addrs || !found.addrs.length) return null;
  const v4 = found.addrs.find((a) => a.family !== 'inet6' && isIpv4(a.addr));
  return v4 || found.addrs[0] || null;
}

function addrByIp(ifaces, ip) {
  if (!ip || !isIpv4(ip)) return null;
  for (const i of ifaces || []) {
    const hit = (i.addrs || []).find((a) => a.addr === ip);
    if (hit) return hit;
  }
  return null;
}

function endpointIp(d, ifaces) {
  if (!d) return null;
  if (d.ifaceIp && isIpv4(d.ifaceIp)) return d.ifaceIp;
  if (d.src && isIpv4(d.src)) return d.src;
  if (d.iface && isIpv4(d.iface)) return d.iface;
  const fromName = firstAddr(ifaces, d.iface);
  if (fromName && isIpv4(fromName.addr)) return fromName.addr;
  return null;
}

function isHypervisorLan(ip) {
  if (!isIpv4(ip)) return false;
  if (inCidr(ip, '10.211.55.0', 24)) return true;
  if (inCidr(ip, '10.37.129.0', 24)) return true;
  if (inCidr(ip, '10.0.2.0', 24)) return true;
  return false;
}

function isLikelyHomeLan(ip) {
  if (!isIpv4(ip)) return false;
  if (inCidr(ip, '192.168.0.0', 16)) return true;
  return isHypervisorLan(ip);
}

function isHomeLanDefault(d, ifaces) {
  if (!d) return false;
  if (d.iface && isVpnIface(d.iface)) return false;
  const ip = endpointIp(d, ifaces);
  return Boolean(isLikelyHomeLan(d.gw) || isLikelyHomeLan(ip));
}

function recoveredLooksLikeHome(recovered, vpnIfaceIp, ifaces) {
  if (!recovered) return false;
  const ip = endpointIp(recovered, ifaces);
  if (vpnIfaceIp && ip && ip === vpnIfaceIp) return false;
  if (recovered.iface && isVpnIface(recovered.iface)) return false;
  return Boolean(
    isLikelyHomeLan(ip)
    || isLikelyHomeLan(recovered.dest)
    || isLikelyHomeLan(recovered.gw)
  );
}

function connectedPrefix(routes, iface, ifaceIp) {
  const hits = (routes || []).filter((r) => {
    const same = (iface && r.iface === iface)
      || (ifaceIp && (r.ifaceIp === ifaceIp || r.src === ifaceIp || r.iface === ifaceIp));
    return (
      same
      && !r.gw
      && r.prefix > 0
      && r.prefix < 32
      && r.dest !== '127.0.0.0'
      && r.dest !== '224.0.0.0'
    );
  });
  if (hits.length) return Math.min(...hits.map((r) => r.prefix));
  const hostOnly = (routes || []).some((r) => {
    const same = (iface && r.iface === iface)
      || (ifaceIp && (r.ifaceIp === ifaceIp || r.src === ifaceIp || r.iface === ifaceIp));
    return same && ifaceIp && r.dest === ifaceIp && r.prefix === 32 && !r.gw;
  });
  return hostOnly ? 32 : null;
}

function vpnScore(d, routes, ifaces) {
  let s = 0;
  const ip = endpointIp(d, ifaces);
  const gw = d.gw;
  if (d.iface && isVpnIface(d.iface)) s += 12;
  if (d.iface && isIgnoredIface(d.iface)) s -= 8;
  if (isLikelyHomeLan(ip) || isLikelyHomeLan(gw)) s -= 10;
  if (ip && inCidr(ip, '100.64.0.0', 10)) s += 6;
  if (gw && inCidr(gw, '100.64.0.0', 10)) s += 4;
  if (ip && inCidr(ip, '10.0.0.0', 8)) s += 3;
  if (gw && inCidr(gw, '10.0.0.0', 8)) s += 2;
  if (ip && inCidr(ip, '172.16.0.0', 12)) s += 2;
  if (gw && inCidr(gw, '172.16.0.0', 12)) s += 1;
  const fromIface = firstAddr(ifaces, d.iface);
  const prefix = connectedPrefix(routes, d.iface, ip)
    ?? (fromIface && fromIface.prefix != null ? fromIface.prefix : null);
  if (prefix === 32) s += 5;
  else if (prefix != null && prefix >= 30) s += 4;
  else if (prefix != null && prefix <= 24) s -= 3;
  if (d.metric != null && d.metric <= 2) s += 2;
  else if (d.metric != null && d.metric >= 200) s -= 2;
  return s;
}

function recoverLanDef(routes, vpnDef, gateways, ifaces) {
  const skipIp = vpnDef ? endpointIp(vpnDef, ifaces) : null;
  const skipIface = vpnDef && vpnDef.iface ? vpnDef.iface : null;
  const candidates = (routes || []).filter((r) => (
    !r.gw
    && r.prefix >= 8
    && r.prefix <= 28
    && r.dest !== '127.0.0.0'
    && r.dest !== '224.0.0.0'
    && !String(r.dest).startsWith('255.')
    && !(skipIface && r.iface === skipIface)
    && !(skipIp && (r.ifaceIp === skipIp || r.src === skipIp || r.iface === skipIp))
  ));
  const home = candidates.find((r) => {
    const ip = endpointIp(r, ifaces);
    return isLikelyHomeLan(ip) || isLikelyHomeLan(r.dest);
  });
  const hit = home || candidates.find((r) => r.prefix <= 24) || null;
  if (!hit) return null;
  const ifaceIp = endpointIp(hit, ifaces);
  let gw = (gateways && ifaceIp && gateways[ifaceIp]) || null;
  if (!gw && hit.iface) {
    const row = (ifaces || []).find((i) => i.name === hit.iface);
    if (row && row.gw && isIpv4(row.gw)) gw = row.gw;
  }
  if (!gw) {
    const gwHit = (routes || []).find((r) => (
      r.iface === hit.iface
      && r.prefix === 32
      && r.dest
      && r.dest !== ifaceIp
      && r.dest !== '255.255.255.255'
      && !String(r.dest).startsWith('255.')
      && (isLikelyHomeLan(r.dest) || (hit.prefix && hit.dest && inCidr(r.dest, hit.dest, hit.prefix)))
      && !r.gw
    ));
    if (gwHit) gw = gwHit.dest;
  }
  return {
    dest: '0.0.0.0',
    prefix: 0,
    gw,
    iface: hit.iface,
    ifaceIp,
    metric: hit.metric,
    recovered: true,
  };
}

function pickIpv4Defaults(routes, opts = {}) {
  const ifaces = opts.ifaces || [];
  const gateways = opts.gateways || Object.create(null);
  const defaults = (routes || []).filter((r) => (
    r.prefix === 0
    && r.dest === '0.0.0.0'
    && !isLoopName(r.iface)
  ));
  const score = (d) => vpnScore(d, routes, ifaces);
  const ranked = defaults.slice().sort((a, b) => score(b) - score(a));

  if (defaults.length === 0) {
    return { defaults, lanDef: recoverLanDef(routes, null, gateways, ifaces), vpnDef: null };
  }

  if (defaults.length === 1) {
    const only = defaults[0];
    const recovered = recoverLanDef(routes, only, gateways, ifaces);
    const recoveredHome = recoveredLooksLikeHome(recovered, endpointIp(only, ifaces), ifaces);
    const namedVpn = Boolean(only.iface && isVpnIface(only.iface));
    if (!isHomeLanDefault(only, ifaces) && (namedVpn || score(only) > 0 || recoveredHome)) {
      return { defaults, lanDef: recovered, vpnDef: only };
    }
    return { defaults, lanDef: only, vpnDef: null };
  }

  const home = defaults.filter((d) => isHomeLanDefault(d, ifaces));
  const rest = defaults.filter((d) => !home.includes(d));
  let lanDef = null;
  let vpnDef = null;
  if (home.length && rest.length) {
    lanDef = home.slice().sort((a, b) => score(a) - score(b))[0];
    vpnDef = rest.slice().sort((a, b) => score(b) - score(a))[0];
  } else {
    vpnDef = ranked[0];
    lanDef = ranked[ranked.length - 1];
    if (vpnDef === lanDef || score(vpnDef) <= 0) {
      vpnDef = null;
      lanDef = home[0] || defaults.find((d) => d.gw && isIpv4(d.gw)) || defaults[0];
    }
    if (vpnDef && lanDef && vpnDef.iface && lanDef.iface && vpnDef.iface === lanDef.iface) {
      lanDef = recoverLanDef(routes, vpnDef, gateways, ifaces);
    }
    if (vpnDef && lanDef && endpointIp(vpnDef, ifaces) && endpointIp(vpnDef, ifaces) === endpointIp(lanDef, ifaces)) {
      lanDef = recoverLanDef(routes, vpnDef, gateways, ifaces);
    }
  }
  if (vpnDef && !lanDef) lanDef = recoverLanDef(routes, vpnDef, gateways, ifaces);
  if (lanDef && lanDef.recovered && !lanDef.gw && gateways && lanDef.ifaceIp) {
    lanDef.gw = gateways[lanDef.ifaceIp] || null;
  }
  return { defaults, lanDef, vpnDef };
}

function addrInfoFor(ifaces, name, ifaceIp) {
  const byName = firstAddr(ifaces, name);
  if (byName) return byName;
  const byIp = addrByIp(ifaces, ifaceIp);
  if (byIp) return byIp;
  if (ifaceIp && isIpv4(ifaceIp)) return { addr: ifaceIp, prefix: 32 };
  if (name && isIpv4(name)) return { addr: name, prefix: 32 };
  return null;
}

function inferTopology(routes, ifaces, osName, opts = {}) {
  const ifaceList = ifaces || [];
  const gateways = opts.gateways || Object.create(null);
  const { lanDef, vpnDef } = pickIpv4Defaults(routes, { ifaces: ifaceList, gateways });

  const vpnIface = vpnDef && vpnDef.iface ? vpnDef.iface : null;
  const lanIface = lanDef && lanDef.iface ? lanDef.iface : null;
  const vpnIp = endpointIp(vpnDef, ifaceList);
  const lanIp = endpointIp(lanDef, ifaceList);
  const vpnAddrInfo = addrInfoFor(ifaceList, vpnIface, vpnIp);
  const lanAddrInfo = addrInfoFor(ifaceList, lanIface, lanIp);

  const vpnCidrs = (routes || []).filter((r) => (
    r.iface
    && vpnIface
    && r.iface === vpnIface
    && r.prefix > 0
    && r.prefix < 32
    && r.dest !== '0.0.0.0'
    && r.dest !== '127.0.0.0'
  )).map((r) => ({ dest: r.dest, prefix: r.prefix, gw: r.gw, iface: r.iface }));

  const prefix = lanAddrInfo && lanAddrInfo.prefix != null
    ? lanAddrInfo.prefix
    : (lanDef && lanDef.prefix && lanDef.prefix > 0 && lanDef.prefix < 32 ? lanDef.prefix : 24);
  const lanAddr = lanAddrInfo ? lanAddrInfo.addr : lanIp;
  const vpnAddr = vpnAddrInfo ? vpnAddrInfo.addr : vpnIp;
  const vpnUp = Boolean(vpnIface);

  const outIfaces = ifaceList.map((i) => {
    let role = 'other';
    if (isLoopName(i.name)) role = 'loopback';
    else if (vpnIface && i.name === vpnIface) role = 'vpn';
    else if (lanIface && i.name === lanIface) role = 'lan';
    else if (isVpnIface(i.name) && vpnIface && i.name !== vpnIface) role = 'other';
    else if (isVpnIface(i.name) && !vpnIface) role = 'vpn';
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
      addr: vpnAddr || null,
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

  let outRoutes = routes || [];
  if (lanDef && lanDef.recovered && lanDef.gw && lanIface) {
    const exists = outRoutes.some((r) => r.prefix === 0 && r.iface === lanIface && r.gw === lanDef.gw);
    if (!exists) {
      outRoutes = outRoutes.concat([{
        dest: '0.0.0.0',
        prefix: 0,
        gw: lanDef.gw,
        iface: lanIface,
        ifaceIp: lanDef.ifaceIp || lanIp,
        metric: lanDef.metric,
        flags: '',
        inactive: false,
        host: false,
        family: 'inet',
        recovered: true,
      }]);
    }
  }

  return {
    os: osName,
    vpn: {
      up: vpnUp,
      iface: vpnIface || null,
      addr: vpnAddr || null,
      gw: vpnDef && vpnDef.gw ? vpnDef.gw : null,
      cidrs: vpnCidrs,
    },
    lan: {
      iface: lanIface || null,
      addr: lanAddr || null,
      gw: lanDef ? lanDef.gw : null,
      prefix,
      network: lanAddr ? networkAddr(lanAddr, prefix) : null,
    },
    ifaces: outIfaces,
    routes: outRoutes,
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
  isLoopName,
  isLikelyHomeLan,
  isHypervisorLan,
  pickIpv4Defaults,
  parseWin32Ipconfig,
  parseWin32NetRoute,
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
