'use strict';

const dns = require('dns').promises;
const tls = require('tls');
const { fail } = require('./errors');
const { validateTarget, isIpv4, isBlockedIPv4 } = require('./net');

async function defaultResolve4(host) {
  return dns.resolve4(host);
}

function defaultProbeTls(host, opts = {}) {
  const timeout = opts.timeout ?? 3000;
  return new Promise((resolve) => {
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      resolve(result);
    };
    const socket = tls.connect({
      host,
      port: 443,
      servername: isIpv4(host) ? undefined : host,
      timeout,
      localAddress: opts.localAddress,
      rejectUnauthorized: false,
    }, () => {
      socket.end();
      finish({ ok: true });
    });
    socket.on('timeout', () => {
      socket.destroy();
      finish({ ok: false, error: 'timeout' });
    });
    socket.on('error', (err) => {
      finish({ ok: false, error: err.message || 'connect' });
    });
  });
}

async function resolveHostIps(host, resolve4) {
  const parsed = validateTarget(host);
  if (parsed.type === 'ipv4') {
    if (isBlockedIPv4(parsed.value)) throw fail('EBLOCKED', 'blocked address');
    return { host: parsed.value, ips: [parsed.value] };
  }
  let ips;
  try {
    ips = await resolve4(parsed.value);
  } catch (err) {
    throw fail('EINVAL', `DNS failed for ${parsed.value}`);
  }
  const v4 = (ips || []).filter((ip) => isIpv4(ip));
  if (v4.some((ip) => isBlockedIPv4(ip))) throw fail('EBLOCKED', 'resolved to a blocked address');
  if (!v4.length) throw fail('EINVAL', `no IPv4 addresses for ${parsed.value}`);
  return { host: parsed.value, ips: v4 };
}

async function probeHost(host, opts = {}) {
  const resolve4 = opts.resolveDns || defaultResolve4;
  const probeTls = opts.probeTls || defaultProbeTls;
  const parsed = validateTarget(host);
  const resolved = await resolveHostIps(parsed.value, resolve4);
  const target = parsed.type === 'hostname' ? parsed.value : resolved.ips[0];
  const result = await probeTls(target, {
    timeout: opts.timeout ?? 3000,
    localAddress: opts.localAddress,
  });
  const ok = Boolean(result && result.ok);
  return {
    host: parsed.value,
    ips: resolved.ips,
    ok,
    reachable: ok,
    via: 'lan',
    error: ok ? null : (result && result.error) || 'unreachable',
  };
}

module.exports = {
  defaultResolve4,
  defaultProbeTls,
  resolveHostIps,
  probeHost,
  validateTarget,
};
