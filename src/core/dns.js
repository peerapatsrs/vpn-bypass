'use strict';

const { isIpv4, inCidr, uniqueKeep, isBlockedIPv4 } = require('./net');

const LOOPBACK = new Set(['127.0.0.1', '::1', '0.0.0.0']);

function rfc1918PtrZones() {
  const zones = ['10.in-addr.arpa', '168.192.in-addr.arpa'];
  for (let i = 16; i <= 31; i += 1) zones.push(`${i}.172.in-addr.arpa`);
  return zones;
}

const RFC1918_PTR_ZONES = rfc1918PtrZones();

function normalizeName(name) {
  return String(name || '').trim().toLowerCase().replace(/\.+$/, '');
}

function normalizeSuffixes(list) {
  const out = [];
  const seen = new Set();
  for (const raw of list || []) {
    const s = normalizeName(raw).replace(/^\.+/, '');
    if (!s) continue;
    if (s === 'local' || s.endsWith('.local')) continue;
    if (s === 'arpa' || s === 'in-addr.arpa' || s === 'ip6.arpa') continue;
    if (!/^[a-z0-9.-]+$/.test(s)) continue;
    if (s.includes('..')) continue;
    const labels = s.split('.');
    if (labels.length < 2) continue;
    if (labels.some((l) => !l || l.length > 63 || l.startsWith('-') || l.endsWith('-'))) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}

function isSafeResolverName(name) {
  const s = normalizeName(name);
  return Boolean(s) && /^[A-Za-z0-9._-]+$/.test(s) && !s.includes('..');
}

function isUsableDnsIp(ip) {
  return isIpv4(ip) && !LOOPBACK.has(ip) && !isBlockedIPv4(ip);
}

function uniqueIps(list) {
  return uniqueKeep((list || []).filter((ip) => isIpv4(ip) && !LOOPBACK.has(ip)));
}

function ptrToIpv4(name) {
  const n = normalizeName(name);
  const parts = n.split('.');
  if (parts.length < 6) return null;
  if (parts[parts.length - 1] !== 'arpa' || parts[parts.length - 2] !== 'in-addr') return null;
  const a = parts[parts.length - 3];
  const b = parts[parts.length - 4];
  const c = parts[parts.length - 5];
  const d = parts[parts.length - 6];
  const ip = `${a}.${b}.${c}.${d}`;
  return isIpv4(ip) ? ip : null;
}

function isRfc1918Ptr(name) {
  const n = normalizeName(name);
  if (!n) return false;
  const ip = ptrToIpv4(n);
  if (ip) {
    return inCidr(ip, '10.0.0.0', 8)
      || inCidr(ip, '172.16.0.0', 12)
      || inCidr(ip, '192.168.0.0', 16);
  }
  for (const zone of RFC1918_PTR_ZONES) {
    if (n === zone || n.endsWith(`.${zone}`)) return true;
  }
  return false;
}

function hostnameUsesVpnDns(name, suffixes) {
  const n = normalizeName(name);
  if (!n) return false;
  if (isRfc1918Ptr(n)) return true;
  for (const suffix of suffixes || []) {
    const s = normalizeName(suffix);
    if (!s || s.endsWith('.arpa')) continue;
    if (n === s || n.endsWith(`.${s}`)) return true;
  }
  return false;
}

function parseScutilDns(text) {
  const resolvers = [];
  let scopedSection = false;
  let current = null;

  function flush() {
    if (current) resolvers.push(current);
    current = null;
  }

  for (const line of String(text || '').split(/\r?\n/)) {
    if (/DNS configuration \(for scoped queries\)/i.test(line)) {
      flush();
      scopedSection = true;
      continue;
    }
    if (/^DNS configuration\b/i.test(line.trim())) continue;
    const head = /^resolver #(\d+)/i.exec(line.trim());
    if (head) {
      flush();
      current = {
        n: Number(head[1]),
        nameservers: [],
        domains: [],
        search: [],
        flags: '',
        iface: null,
        scoped: scopedSection,
        mdns: false,
        supplemental: false,
      };
      continue;
    }
    if (!current) continue;
    const ns = /nameserver\[\d+\]\s*:\s*(\S+)/i.exec(line);
    if (ns) {
      let ip = ns[1].replace(/^\[/, '').replace(/\]$/, '');
      if (ip.includes('%')) ip = ip.split('%')[0];
      if (isIpv4(ip)) current.nameservers.push(ip);
      continue;
    }
    const domain = /^\s*domain\s*:\s*(\S+)/i.exec(line);
    if (domain) {
      current.domains.push(normalizeName(domain[1]));
      continue;
    }
    const search = /search domain\[\d+\]\s*:\s*(\S+)/i.exec(line);
    if (search) {
      current.search.push(normalizeName(search[1]));
      continue;
    }
    const flags = /^\s*flags\s*:\s*(.*)$/i.exec(line);
    if (flags) {
      current.flags = flags[1];
      if (/Scoped/i.test(flags[1])) current.scoped = true;
      if (/Supplemental/i.test(flags[1])) current.supplemental = true;
      continue;
    }
    const ifn = /if_index\s*:\s*\d+\s*\((\S+)\)/i.exec(line);
    if (ifn) {
      current.iface = ifn[1];
      continue;
    }
    if (/multicast dns/i.test(line) || /\bmdns\b/i.test(line)) current.mdns = true;
  }
  flush();
  return resolvers;
}

function parseServiceOrder(text) {
  const services = [];
  const lines = String(text || '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const m = /^\((\d+)\)\s+(\*\s+)?(.*)$/.exec(lines[i].trim());
    if (!m) continue;
    const name = (m[3] || '').trim();
    if (!name) continue;
    let device = null;
    const next = lines[i + 1] || '';
    const d = /Device:\s*([^)\s]+)/i.exec(next);
    if (d) device = d[1].trim();
    services.push({
      index: Number(m[1]),
      name,
      device,
      disabled: Boolean(m[2]),
    });
  }
  return services;
}

function parseDnsServersOutput(stdout) {
  const text = String(stdout || '').trim();
  if (!text || /there aren't any dns servers/i.test(text)) {
    return { servers: [], empty: true };
  }
  const servers = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (isIpv4(t)) servers.push(t);
  }
  return { servers, empty: servers.length === 0 };
}

function parseSearchDomainsOutput(stdout) {
  const text = String(stdout || '').trim();
  if (!text || /there aren't any search domains/i.test(text)) {
    return { search: [], empty: true };
  }
  const search = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (t && !/search domain/i.test(t)) search.push(t);
  }
  const normalized = normalizeSuffixes(search);
  return { search: normalized, empty: normalized.length === 0 };
}

function defaultUnicastServers(resolvers) {
  for (const r of resolvers || []) {
    if (r.scoped || r.mdns) continue;
    if (r.supplemental || (r.domains && r.domains.length)) continue;
    const ns = uniqueIps(r.nameservers);
    if (ns.length) return ns;
  }
  return [];
}

function classifyDns(resolvers, detect) {
  const lanIface = detect && detect.lan && detect.lan.iface;
  const vpnIface = detect && detect.vpn && detect.vpn.iface;
  const lanGw = detect && detect.lan && detect.lan.gw;
  const lanNet = detect && detect.lan && detect.lan.network;
  const lanPrefix = detect && detect.lan && Number.isInteger(detect.lan.prefix)
    ? detect.lan.prefix
    : null;

  const lanServers = [];
  const vpnServers = [];
  const suffixRaw = [];
  const searchRaw = [];

  function inHomeLan(ip) {
    if (lanGw && ip === lanGw) return true;
    if (lanNet && lanPrefix != null && isIpv4(ip) && isIpv4(lanNet)) {
      return inCidr(ip, lanNet, lanPrefix);
    }
    return false;
  }

  for (const r of resolvers || []) {
    if (r.mdns) continue;
    const ns = uniqueIps(r.nameservers);
    suffixRaw.push(...(r.domains || []));
    searchRaw.push(...(r.search || []));
    if (r.iface && lanIface && r.iface === lanIface) {
      lanServers.push(...ns);
      continue;
    }
    if (r.iface && vpnIface && r.iface === vpnIface) {
      vpnServers.push(...ns);
      suffixRaw.push(...(r.domains || []));
      continue;
    }
    if (r.supplemental) {
      vpnServers.push(...ns);
      continue;
    }
  }

  const unscoped = defaultUnicastServers(resolvers);
  for (const ip of unscoped) {
    if (inHomeLan(ip)) lanServers.push(ip);
    else vpnServers.push(ip);
  }

  const lans = uniqueIps(lanServers).filter((ip) => !isBlockedIPv4(ip) || inHomeLan(ip));
  const usableLan = lans.filter(isUsableDnsIp);
  if (!usableLan.length && lanGw && isUsableDnsIp(lanGw)) usableLan.push(lanGw);

  const vpns = uniqueIps(vpnServers).filter((ip) => !usableLan.includes(ip) && isUsableDnsIp(ip));
  const suffixes = normalizeSuffixes(suffixRaw.concat(searchRaw));
  const search = normalizeSuffixes(searchRaw);

  return {
    lanServers: uniqueKeep(usableLan),
    vpnServers: uniqueKeep(vpns),
    suffixes,
    search,
    resolvers: resolvers || [],
    defaultServers: unscoped,
  };
}

function buildSplitDnsPlan(detect, snapshot) {
  const classified = snapshot && snapshot.lanServers
    ? snapshot
    : classifyDns((snapshot && snapshot.resolvers) || [], detect);
  let lanServers = uniqueKeep((classified.lanServers || []).filter(isUsableDnsIp));
  if (!lanServers.length && detect && detect.lan && isUsableDnsIp(detect.lan.gw)) {
    lanServers = [detect.lan.gw];
  }
  if (!lanServers.length) {
    return {
      ok: false,
      mode: 'skipped',
      warning: 'no LAN DNS servers found; system DNS unchanged',
    };
  }
  const vpnServers = uniqueKeep((classified.vpnServers || []).filter((ip) => (
    isUsableDnsIp(ip) && !lanServers.includes(ip)
  )));
  const suffixes = normalizeSuffixes(classified.suffixes || classified.search || []);
  const search = normalizeSuffixes(classified.search || suffixes);
  const warning = vpnServers.length
    ? null
    : (suffixes.length ? 'VPN DNS servers not found; corp suffixes will use LAN DNS' : 'no corp suffixes detected; intranet DNS may fail');
  return {
    ok: true,
    mode: 'split',
    listen: '127.0.0.1',
    port: 53,
    lanServers,
    vpnServers,
    suffixes,
    search,
    warning,
  };
}

function inferDnsMode(servers, owned) {
  const list = (servers || []).filter(Boolean);
  if (!list.length) return 'none';
  if (list.every((s) => s === '127.0.0.1' || s === '::1')) return 'split';
  const lan = new Set((owned && owned.lanServers) || []);
  const vpn = new Set((owned && owned.vpnServers) || []);
  if (vpn.size && list.some((s) => vpn.has(s))) return 'vpn';
  if (lan.size && list.every((s) => lan.has(s))) return 'lan';
  if (list.some((s) => s === '127.0.0.1')) return 'split';
  return 'unknown';
}

function restoreServerArgs(previous) {
  const prev = previous || {};
  const servers = uniqueIps(prev.servers || []).filter((s) => s !== '127.0.0.1');
  if (prev.empty || !servers.length) return ['Empty'];
  return servers;
}

function restoreSearchArgs(previous) {
  const prev = previous || {};
  const search = normalizeSuffixes(prev.search || []);
  if (prev.searchEmpty || !search.length) return ['Empty'];
  return search;
}

function sanitizePreviousService(raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const name = String(src.service || src.name || '');
  if (!name || name.length > 200) return null;
  return {
    service: name,
    device: src.device == null ? null : String(src.device),
    servers: uniqueIps(src.servers || []),
    empty: Boolean(src.empty) || !(src.servers && src.servers.length),
    search: normalizeSuffixes(src.search || []),
    searchEmpty: src.searchEmpty != null ? Boolean(src.searchEmpty) : !(src.search && src.search.length),
  };
}

function sanitizeOwnedDns(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const mode = ['split', 'lan', 'vpn', 'unsupported', 'skipped'].includes(raw.mode)
    ? raw.mode
    : 'split';
  const previous = Array.isArray(raw.previous)
    ? raw.previous.map(sanitizePreviousService).filter(Boolean)
    : [];
  const resolverFiles = Array.isArray(raw.resolverFiles)
    ? raw.resolverFiles.filter((f) => {
      const s = String(f);
      return s.startsWith('/etc/resolver/') || s.includes(`${require('path').sep}resolver${require('path').sep}`);
    }).map(String)
    : [];
  const pid = Number.isInteger(raw.pid) ? raw.pid : (Number.isInteger(Number(raw.pid)) ? Number(raw.pid) : null);
  return {
    mode,
    method: raw.method == null ? null : String(raw.method),
    os: raw.os == null ? null : String(raw.os),
    pid: pid && pid > 1 ? pid : null,
    listen: raw.listen == null ? null : String(raw.listen),
    port: Number.isInteger(raw.port) ? raw.port : 53,
    lanServers: uniqueIps(raw.lanServers || []),
    vpnServers: uniqueIps(raw.vpnServers || []),
    suffixes: normalizeSuffixes(raw.suffixes || []),
    search: normalizeSuffixes(raw.search || []),
    previous,
    resolverFiles,
    ifaces: Array.isArray(raw.ifaces) ? raw.ifaces.map(String).filter(Boolean) : [],
    configPath: raw.configPath == null ? null : String(raw.configPath),
    warning: raw.warning == null ? null : String(raw.warning),
  };
}

function publicDnsStatus(owned, live) {
  const liveMode = live && live.mode ? live.mode : null;
  const ownedMode = owned && owned.mode ? owned.mode : null;
  let mode = liveMode || ownedMode || 'none';
  if (ownedMode === 'unsupported' || ownedMode === 'skipped') {
    mode = liveMode && liveMode !== 'none' ? liveMode : ownedMode;
  }
  return {
    mode,
    method: (owned && owned.method) || (live && live.method) || null,
    lanServers: (owned && owned.lanServers) || (live && live.lanServers) || [],
    vpnServers: (owned && owned.vpnServers) || (live && live.vpnServers) || [],
    suffixes: (owned && owned.suffixes) || (live && live.suffixes) || [],
    listen: (owned && owned.listen) || null,
    warning: (owned && owned.warning) || (live && live.warning) || null,
    hijacked: Boolean(live && live.ok === false),
  };
}

module.exports = {
  RFC1918_PTR_ZONES,
  rfc1918PtrZones,
  normalizeName,
  normalizeSuffixes,
  isSafeResolverName,
  isUsableDnsIp,
  uniqueIps,
  isRfc1918Ptr,
  hostnameUsesVpnDns,
  parseScutilDns,
  parseServiceOrder,
  parseDnsServersOutput,
  parseSearchDomainsOutput,
  defaultUnicastServers,
  classifyDns,
  buildSplitDnsPlan,
  inferDnsMode,
  restoreServerArgs,
  restoreSearchArgs,
  sanitizeOwnedDns,
  publicDnsStatus,
};
