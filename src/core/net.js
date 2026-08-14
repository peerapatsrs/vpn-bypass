'use strict';

const { fail } = require('./errors');

const UNSAFE_CHARS = /[;|&$`\n\r\t\\<>]/;

function ipv4ToInt(ip) {
  const p = String(ip).split('.').map((x) => Number(x));
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

function intToIpv4(n) {
  n >>>= 0;
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function isIpv4(ip) {
  if (typeof ip !== 'string' || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;
  return ip.split('.').every((o) => {
    if (o.length > 1 && o.startsWith('0')) return false;
    const n = Number(o);
    return n >= 0 && n <= 255;
  });
}

function inCidr(ip, net, prefix) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(net) & mask);
}

function networkAddr(ip, prefix) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return intToIpv4(ipv4ToInt(ip) & mask);
}

function prefixToMask(prefix) {
  const n = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return intToIpv4(n);
}

function maskToPrefix(mask) {
  let n;
  if (typeof mask === 'string') {
    if (/^0x/i.test(mask)) n = parseInt(mask, 16) >>> 0;
    else if (isIpv4(mask)) n = ipv4ToInt(mask);
    else return null;
  } else {
    n = mask >>> 0;
  }
  if (n === 0) return 0;
  let p = 0;
  for (let i = 31; i >= 0; i -= 1) {
    if ((n >>> i) & 1) p += 1;
    else break;
  }
  const expected = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
  return expected === n ? p : null;
}

function isBlockedIPv4(ip) {
  if (!isIpv4(ip)) return true;
  if (inCidr(ip, '127.0.0.0', 8)) return true;
  if (inCidr(ip, '169.254.0.0', 16)) return true;
  if (inCidr(ip, '0.0.0.0', 8)) return true;
  if (inCidr(ip, '224.0.0.0', 4)) return true;
  if (inCidr(ip, '240.0.0.0', 4)) return true;
  if (ip === '100.100.100.200') return true;
  return false;
}

function isHostname(value) {
  if (typeof value !== 'string') return false;
  const h = value.toLowerCase().replace(/\.$/, '');
  if (!h || h.length > 253) return false;
  if (h.startsWith('-') || h.includes('..')) return false;
  if (!/^[a-z0-9.-]+$/.test(h)) return false;
  const labels = h.split('.');
  return labels.every((lab) => (
    lab.length >= 1
    && lab.length <= 63
    && !lab.startsWith('-')
    && !lab.endsWith('-')
    && /^[a-z0-9-]+$/.test(lab)
  ));
}

function isBlockedHostname(host) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h === 'metadata.google.internal') return true;
  return false;
}

function looksLikeUrl(value) {
  const v = String(value).trim();
  return /:\/\//.test(v) || v.includes('/') || /:\d+$/.test(v) || v.includes('?') || v.includes('#');
}

function normalizeHost(value) {
  return String(value).trim().toLowerCase().replace(/\.$/, '');
}

function expandWwwApex(host) {
  const h = normalizeHost(host);
  if (isIpv4(h)) return [h];
  if (h.startsWith('www.') && h.length > 4) {
    return uniqueKeep([h, h.slice(4)]);
  }
  return uniqueKeep([h, `www.${h}`]);
}

function uniqueKeep(list) {
  const seen = new Set();
  const out = [];
  for (const x of list) {
    if (!x || seen.has(x)) continue;
    seen.add(x);
    out.push(x);
  }
  return out;
}

function validateTarget(raw, { allowIp = true } = {}) {
  if (raw == null || typeof raw !== 'string') {
    throw fail('EINVAL', 'host is required');
  }
  const host = raw.trim();
  if (!host) throw fail('EINVAL', 'host is required');
  if (host.startsWith('-')) throw fail('EINVAL', 'host must not start with -');
  if (UNSAFE_CHARS.test(host)) throw fail('EINVAL', 'host contains unsafe characters');
  if (looksLikeUrl(host)) throw fail('EINVAL', 'hostname or IPv4 only, not a URL');
  if (isIpv4(host)) {
    if (!allowIp) throw fail('EINVAL', 'IP not allowed here');
    if (isBlockedIPv4(host)) throw fail('EBLOCKED', 'blocked address');
    return { type: 'ipv4', value: host };
  }
  if (!isHostname(host)) throw fail('EINVAL', 'invalid hostname');
  const value = normalizeHost(host);
  if (isBlockedHostname(value)) throw fail('EBLOCKED', 'blocked hostname');
  return { type: 'hostname', value };
}

function assertSafeIpv4(ip) {
  if (!isIpv4(ip)) throw fail('EINVAL', `invalid IPv4: ${ip}`);
}

function assertSafePrefix(prefix) {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw fail('EINVAL', `invalid prefix: ${prefix}`);
  }
}

function assertSafeIface(name) {
  if (!name) return;
  if (!/^[A-Za-z0-9._-]+$/.test(name)) {
    throw fail('EINVAL', `invalid interface: ${name}`);
  }
}

function routeKey(route) {
  return `${route.dest}/${route.prefix}|${route.gw || ''}|${route.iface || ''}|${route.kind || ''}`;
}

module.exports = {
  ipv4ToInt,
  intToIpv4,
  isIpv4,
  inCidr,
  networkAddr,
  prefixToMask,
  maskToPrefix,
  isBlockedIPv4,
  isHostname,
  isBlockedHostname,
  looksLikeUrl,
  normalizeHost,
  expandWwwApex,
  uniqueKeep,
  validateTarget,
  assertSafeIpv4,
  assertSafePrefix,
  assertSafeIface,
  routeKey,
  UNSAFE_CHARS,
};
