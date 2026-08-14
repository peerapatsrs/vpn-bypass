'use strict';

const fs = require('fs');
const path = require('path');
const {
  parseScutilDns,
  parseServiceOrder,
  parseDnsServersOutput,
  parseSearchDomainsOutput,
  classifyDns,
  buildSplitDnsPlan,
  defaultUnicastServers,
  inferDnsMode,
  restoreServerArgs,
  restoreSearchArgs,
  RFC1918_PTR_ZONES,
  isSafeResolverName,
  uniqueIps,
} = require('../core/dns');
const { spawnDetached, pidAlive } = require('../core/dnsForwarder');
const { ownConfigDir } = require('../core/config');

const SCUTIL = '/usr/sbin/scutil';
const NETWORKSETUP = '/usr/sbin/networksetup';
const PS = '/bin/ps';

function create(opts = {}) {
  const exec = opts.exec;
  const startForwarder = opts.startForwarder;
  const stopForwarder = opts.stopForwarder;
  const etcResolverDir = opts.etcResolverDir || '/etc/resolver';
  const spawnImpl = opts.spawnImpl;

  async function readDns(detect) {
    let resolvers = [];
    try {
      const { stdout } = await exec(SCUTIL, ['--dns']);
      resolvers = parseScutilDns(stdout);
    } catch {
      resolvers = [];
    }
    let services = [];
    try {
      const { stdout } = await exec(NETWORKSETUP, ['-listnetworkserviceorder']);
      services = parseServiceOrder(stdout);
    } catch {
      services = [];
    }
    const classified = classifyDns(resolvers, detect || {});
    return {
      ...classified,
      services,
      defaultServers: defaultUnicastServers(resolvers),
    };
  }

  async function snapshotServices(services) {
    const previous = [];
    for (const svc of services || []) {
      if (!svc || svc.disabled || !svc.name) continue;
      if (svc.name.startsWith('*')) continue;
      let servers = [];
      let empty = true;
      let search = [];
      let searchEmpty = true;
      try {
        const got = await exec(NETWORKSETUP, ['-getdnsservers', svc.name]);
        const parsed = parseDnsServersOutput(got.stdout);
        servers = parsed.servers;
        empty = parsed.empty;
      } catch {
        continue;
      }
      try {
        const got = await exec(NETWORKSETUP, ['-getsearchdomains', svc.name]);
        const parsed = parseSearchDomainsOutput(got.stdout);
        search = parsed.search;
        searchEmpty = parsed.empty;
      } catch {
        search = [];
        searchEmpty = true;
      }
      previous.push({
        service: svc.name,
        device: svc.device || null,
        servers,
        empty,
        search,
        searchEmpty,
      });
    }
    return previous;
  }

  function writeResolverFile(dir, name, servers) {
    if (!isSafeResolverName(name)) return null;
    const ips = uniqueIps(servers);
    if (!ips.length) return null;
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, name);
    const body = `${ips.map((ip) => `nameserver ${ip}`).join('\n')}\n`;
    fs.writeFileSync(file, body, { encoding: 'utf8', mode: 0o644 });
    return file;
  }

  function ownedResolverFiles(plan) {
    const names = [...(plan.suffixes || [])];
    if (plan.vpnServers && plan.vpnServers.length) {
      names.push(...RFC1918_PTR_ZONES);
    }
    return names;
  }

  async function applyNativeSplit(plan, previous, detect) {
    const lanDevice = detect && detect.lan && detect.lan.iface;
    const files = [];
    if (plan.vpnServers && plan.vpnServers.length) {
      for (const name of ownedResolverFiles(plan)) {
        const file = writeResolverFile(etcResolverDir, name, plan.vpnServers);
        if (file) files.push(file);
      }
    }
    for (const row of previous) {
      const isLan = lanDevice && row.device === lanDevice;
      const servers = isLan ? plan.lanServers : plan.lanServers;
      try {
        await exec(NETWORKSETUP, ['-setdnsservers', row.service, ...servers]);
      } catch {
        // keep going; restore still has the snapshot
      }
      if (isLan && plan.search && plan.search.length) {
        try {
          await exec(NETWORKSETUP, ['-setsearchdomains', row.service, ...plan.search]);
        } catch {
          // ignore
        }
      }
    }
    return {
      mode: 'split',
      method: 'scoped',
      os: 'darwin',
      pid: null,
      listen: null,
      lanServers: plan.lanServers,
      vpnServers: plan.vpnServers,
      suffixes: plan.suffixes,
      search: plan.search,
      previous,
      resolverFiles: files,
      warning: plan.warning || null,
    };
  }

  async function writeForwarderConfig(configPath, plan) {
    const body = {
      listen: '127.0.0.1',
      port: plan.port || 53,
      lanServers: plan.lanServers,
      vpnServers: plan.vpnServers,
      suffixes: plan.suffixes,
    };
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, `${JSON.stringify(body, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    ownConfigDir(path.dirname(configPath));
  }

  async function launchForwarder(configPath, existingPid) {
    if (existingPid && pidAlive(existingPid) && await isOurForwarder(existingPid, configPath)) {
      return existingPid;
    }
    if (typeof startForwarder === 'function') {
      return startForwarder({ configPath, plan: null });
    }
    return spawnDetached(configPath, { spawnImpl });
  }

  async function isOurForwarder(pid, configPath) {
    if (!pidAlive(pid)) return false;
    try {
      const { stdout } = await exec(PS, ['-p', String(pid), '-o', 'args=']);
      const args = String(stdout || '');
      if (!args.includes('dnsForwarder.js')) return false;
      if (configPath && args.includes(path.basename(configPath))) return true;
      return args.includes('dnsForwarder');
    } catch {
      return false;
    }
  }

  async function killForwarder(pid, configPath) {
    if (typeof stopForwarder === 'function') {
      await stopForwarder({ pid, configPath });
      return;
    }
    if (!pid || !pidAlive(pid)) return;
    const ours = await isOurForwarder(pid, configPath);
    if (!ours) return;
    try { process.kill(pid, 'SIGTERM'); } catch { /* ignore */ }
  }

  async function applyDns(opts = {}) {
    const detect = opts.detect || {};
    const snapshot = opts.snapshot || await readDns(detect);
    const plan = buildSplitDnsPlan(detect, snapshot);
    if (!plan.ok) {
      return {
        mode: 'skipped',
        method: null,
        os: 'darwin',
        warning: plan.warning,
        previous: [],
        lanServers: [],
        vpnServers: [],
        suffixes: [],
      };
    }
    const services = snapshot.services || [];
    let previous = Array.isArray(opts.previous) && opts.previous.length
      ? opts.previous
      : await snapshotServices(services);
    previous = previous.map((row) => ({
      ...row,
      servers: uniqueIps(row.servers || []).filter((s) => s !== '127.0.0.1'),
      empty: row.empty || !uniqueIps(row.servers || []).filter((s) => s !== '127.0.0.1').length,
    }));

    const paths = opts.paths || {};
    const configPath = opts.configPath || (paths.dir ? path.join(paths.dir, 'dns-forwarder.json') : null);
    const existingPid = opts.reapply && opts.pid ? opts.pid : null;

    if (configPath) {
      try {
        await writeForwarderConfig(configPath, plan);
        const pid = await launchForwarder(configPath, existingPid);
        const launchedByStub = typeof startForwarder === 'function';
        if (pid && !launchedByStub) {
          await new Promise((resolve) => setTimeout(resolve, 40));
          if (!pidAlive(Number(pid))) {
            throw new Error('dns forwarder exited');
          }
        }
        if (pid) {
          for (const row of previous) {
            try {
              await exec(NETWORKSETUP, ['-setdnsservers', row.service, '127.0.0.1']);
            } catch {
              // continue
            }
            if (plan.search && plan.search.length && detect.lan && row.device === detect.lan.iface) {
              try {
                await exec(NETWORKSETUP, ['-setsearchdomains', row.service, ...plan.search]);
              } catch {
                // ignore
              }
            }
          }
          return {
            mode: 'split',
            method: 'forwarder',
            os: 'darwin',
            pid: Number(pid) || null,
            listen: '127.0.0.1',
            port: plan.port || 53,
            lanServers: plan.lanServers,
            vpnServers: plan.vpnServers,
            suffixes: plan.suffixes,
            search: plan.search,
            previous,
            resolverFiles: [],
            configPath,
            warning: plan.warning || null,
          };
        }
      } catch {
        // fall through to scoped split so we do not leave 127.0.0.1 without a forwarder
      }
    }

    return applyNativeSplit(plan, previous, detect);
  }

  async function restoreDns(owned) {
    if (!owned) return;
    if (owned.pid || owned.configPath) {
      await killForwarder(owned.pid, owned.configPath);
    }
    for (const file of owned.resolverFiles || []) {
      try {
        if (file && (file.startsWith('/etc/resolver/') || file.startsWith(etcResolverDir))) {
          fs.unlinkSync(file);
        }
      } catch {
        // missing is fine
      }
    }
    for (const row of owned.previous || []) {
      if (!row || !row.service) continue;
      const servers = restoreServerArgs(row);
      try {
        await exec(NETWORKSETUP, ['-setdnsservers', row.service, ...servers]);
      } catch {
        // keep restoring others
      }
      const search = restoreSearchArgs(row);
      try {
        await exec(NETWORKSETUP, ['-setsearchdomains', row.service, ...search]);
      } catch {
        // ignore
      }
    }
    if (owned.configPath) {
      try { fs.unlinkSync(owned.configPath); } catch { /* ignore */ }
    }
  }

  async function inspectDns(owned) {
    if (!owned || owned.mode === 'skipped' || owned.mode === 'unsupported') {
      return { ok: true, mode: owned && owned.mode ? owned.mode : 'none' };
    }
    let resolvers = [];
    try {
      const { stdout } = await exec(SCUTIL, ['--dns']);
      resolvers = parseScutilDns(stdout);
    } catch {
      return { ok: true, mode: owned.mode || 'unknown' };
    }
    const defaults = defaultUnicastServers(resolvers);
    const mode = inferDnsMode(defaults.length ? defaults : defaultsUnscopedFallback(resolvers), owned);
    if (owned.method === 'forwarder') {
      const alive = owned.pid ? pidAlive(owned.pid) : false;
      const pointsLocal = defaults.length
        ? defaults.every((s) => s === '127.0.0.1')
        : mode === 'split';
      return { ok: Boolean(alive && pointsLocal), mode: pointsLocal && alive ? 'split' : (mode || 'vpn'), defaults, pidAlive: alive };
    }
    if (owned.method === 'scoped' || owned.mode === 'split' || owned.mode === 'lan') {
      const want = new Set(owned.lanServers || []);
      const ok = defaults.length > 0 && defaults.every((s) => want.has(s) || s === '127.0.0.1');
      const leak = defaults.some((s) => (owned.vpnServers || []).includes(s));
      return { ok: ok && !leak, mode: leak ? 'vpn' : (ok ? (owned.mode === 'lan' ? 'lan' : 'split') : mode), defaults };
    }
    return { ok: true, mode, defaults };
  }

  function defaultsUnscopedFallback(resolvers) {
    for (const r of resolvers || []) {
      if (r.mdns) continue;
      const ns = uniqueIps(r.nameservers);
      if (ns.length) return ns;
    }
    return [];
  }

  async function dnsStatus(detect, owned) {
    const snap = await readDns(detect || {});
    const liveMode = inferDnsMode(snap.defaultServers, owned || {
      lanServers: snap.lanServers,
      vpnServers: snap.vpnServers,
    });
    let inspected = { ok: true, mode: liveMode };
    if (owned) inspected = await inspectDns(owned);
    return {
      mode: inspected.mode || liveMode || 'none',
      method: owned && owned.method,
      lanServers: (owned && owned.lanServers) || snap.lanServers,
      vpnServers: (owned && owned.vpnServers) || snap.vpnServers,
      suffixes: (owned && owned.suffixes) || snap.suffixes,
      listen: owned && owned.listen,
      warning: owned && owned.warning,
      ok: inspected.ok,
    };
  }

  return {
    readDns,
    applyDns,
    restoreDns,
    inspectDns,
    dnsStatus,
  };
}

module.exports = { create, SCUTIL: '/usr/sbin/scutil', NETWORKSETUP: '/usr/sbin/networksetup' };
