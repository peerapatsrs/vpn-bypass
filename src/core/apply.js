'use strict';

const { fail } = require('./errors');
const { withLock } = require('./lock');
const { loadConfig, saveConfig, loadState, saveState } = require('./config');
const { plan } = require('./plan');
const { routeKey, familyOf, gwEqual } = require('./net');
const { resolveHostIps, defaultResolve4 } = require('./probe');
const { buildSplitDnsPlan, sanitizeOwnedDns } = require('./dns');
const log = require('./log');

const SESSION_REPAIR_MS = 3000;
const CLI_WATCH_MS = 8000;

function ledgerEntry(action) {
  return {
    dest: action.dest,
    prefix: action.prefix,
    gw: action.gw || null,
    iface: action.iface || null,
    kind: action.kind || null,
    domain: action.domain || null,
    family: familyOf(action),
  };
}

function destMatch(a, b) {
  return (
    a.dest === b.dest
    && Number(a.prefix) === Number(b.prefix)
    && familyOf(a) === familyOf(b)
  );
}

function viaOk(owned, current, detect) {
  const kind = owned.kind;
  const lan = (detect && detect.lan) || {};
  const vpn = (detect && detect.vpn) || {};
  if (kind === 'split' || kind === 'lan-protect' || kind === 'domain') {
    const wantGw = familyOf(owned) === 'inet6' ? (owned.gw || lan.gw6) : (owned.gw || lan.gw);
    if (wantGw && current.gw && gwEqual(wantGw, current.gw)) return true;
    if (lan.iface && current.iface === lan.iface) return true;
    return false;
  }
  if (kind === 'vpn-keep' || kind === 'allow-vpn') {
    if (vpn.iface && current.iface === vpn.iface) return true;
    if (owned.iface && current.iface === owned.iface) return true;
    if (owned.gw && current.gw && gwEqual(owned.gw, current.gw)) return true;
    return false;
  }
  return true;
}

function inspectOwned(ownedRoutes, current, detect) {
  const missing = [];
  const hijacked = [];
  for (const owned of ownedRoutes || []) {
    const matches = (current || []).filter((r) => destMatch(r, owned));
    if (!matches.length) missing.push(owned);
    else if (!matches.some((r) => viaOk(owned, r, detect))) hijacked.push(owned);
  }
  return {
    missing,
    hijacked,
    ok: missing.length === 0 && hijacked.length === 0,
  };
}

function createRepairLimiter(opts = {}) {
  const settleMs = opts.settleMs == null ? 4000 : opts.settleMs;
  const windowMs = opts.windowMs == null ? 60000 : opts.windowMs;
  const maxPerWindow = opts.maxPerWindow == null ? 3 : opts.maxPerWindow;
  const clock = typeof opts.now === 'function' ? opts.now : () => Date.now();
  let lastMutateAt = 0;
  let windowStart = 0;
  let count = 0;
  return {
    allow() {
      const n = clock();
      if (lastMutateAt && n - lastMutateAt < settleMs) return 'settle';
      if (!windowStart || n - windowStart > windowMs) {
        windowStart = n;
        count = 0;
      }
      if (count >= maxPerWindow) return 'backoff';
      return null;
    },
    record() {
      lastMutateAt = clock();
      count += 1;
    },
    reset() {
      lastMutateAt = 0;
      windowStart = 0;
      count = 0;
    },
  };
}

async function execAction(platform, action, opts = {}) {
  const replace = Boolean(opts && opts.replace);
  const wantsChange = replace && typeof platform.changeCidr === 'function';
  if (action.op === 'addHost' || Number(action.prefix) === 32 || Number(action.prefix) === 128) {
    if (wantsChange && typeof platform.changeHost === 'function') {
      await platform.changeHost(action);
      return;
    }
    await platform.addHost(action);
    return;
  }
  if (wantsChange) {
    await platform.changeCidr(action);
    return;
  }
  await platform.addCidr(action);
}

async function resolveList(hosts, resolveDns) {
  const out = [];
  for (const host of hosts || []) {
    const resolved = await resolveHostIps(host, resolveDns);
    for (const ip of resolved.ips) {
      out.push({ ip, domain: resolved.host, host: resolved.host });
    }
  }
  return out;
}

async function applyActions(platform, actions) {
  for (const action of actions) {
    await execAction(platform, action);
  }
}

async function removeRoutes(platform, routes) {
  for (const route of routes || []) {
    await platform.del(route);
  }
}

function staleRoutes(previous, next) {
  const keep = new Set((next || []).map(routeKey));
  return (previous || []).filter((r) => !keep.has(routeKey(r)));
}

async function buildPlan(opts) {
  const {
    paths, platform, mode, cfg, resolveDns = defaultResolve4,
  } = opts;
  const detect = await platform.detect();
  if (!detect.vpn || !detect.vpn.up) throw fail('ENOTVPN', 'VPN is not up');
  if (mode === 'domains' && (!cfg.domains || cfg.domains.length === 0)) {
    throw fail('EDOMAIN_EMPTY', 'empty domain list');
  }
  const resolvedDomains = mode === 'domains'
    ? await resolveList(cfg.domains, resolveDns)
    : [];
  const allowViaVpn = await resolveList(cfg.allowViaVpn, resolveDns);
  const built = plan({
    mode,
    detect,
    resolvedDomains,
    allowViaVpn,
    lanProtect: cfg.lanProtect !== false,
  });
  return { detect, plan: built };
}

async function on(opts) {
  const {
    paths, platform, dryRun = false, mode: modeOpt, resolveDns = defaultResolve4,
  } = opts;
  const cfg = loadConfig(paths);
  const mode = modeOpt || cfg.mode || 'inverse';
  if (mode !== 'inverse' && mode !== 'domains') throw fail('EINVAL', `invalid mode: ${mode}`);

  return withLock(paths.lock, async () => {
    const { detect, plan: built } = await buildPlan({
      paths, platform, mode, cfg, resolveDns,
    });

    if (dryRun) {
      log.record('info', `dry-run ${mode} (${built.actions.length} actions)`);
      const routes = built.actions.map((a) => ({
        ...a,
        dest: `${a.dest}/${a.prefix}`,
        via: a.gw,
        gateway: a.gw,
      }));
      const dns = mode === 'inverse' ? buildSplitDnsPlan(detect, null) : null;
      return {
        dryRun: true,
        mode,
        actions: built.actions,
        routes,
        plan: routes,
        detect,
        dns,
      };
    }

    const admin = await platform.isAdmin();
    if (!admin) throw fail('EPRIV', 'administrator privileges required');

    const prev = loadState(paths);
    const desired = built.actions.map(ledgerEntry);
    const extra = staleRoutes(prev.ownedRoutes, desired);
    await removeRoutes(platform, extra);
    await applyActions(platform, built.actions);

    let ownedDns = null;
    if (mode === 'inverse' && typeof platform.applyDns === 'function') {
      try {
        const preserve = prev.ownedDns && Array.isArray(prev.ownedDns.previous)
          ? prev.ownedDns.previous
          : undefined;
        ownedDns = sanitizeOwnedDns(await platform.applyDns({
          detect,
          paths,
          previous: preserve,
          reapply: Boolean(prev.ownedDns),
          pid: prev.ownedDns && prev.ownedDns.pid,
        }));
        if (ownedDns && ownedDns.mode === 'split') {
          log.record('info', `dns split ${ownedDns.method || ''} lan ${(ownedDns.lanServers || []).join(',')} vpn ${(ownedDns.vpnServers || []).join(',')} suffixes ${(ownedDns.suffixes || []).join(',')}`);
        } else if (ownedDns && ownedDns.warning) {
          log.record('info', `dns ${ownedDns.mode}: ${ownedDns.warning}`);
        }
      } catch (err) {
        log.record('info', `dns split skipped: ${err && err.message ? err.message : err}`);
        ownedDns = sanitizeOwnedDns({
          mode: 'skipped',
          warning: err && err.message ? err.message : 'dns apply failed',
        });
      }
    } else if (mode !== 'inverse' && prev.ownedDns && typeof platform.restoreDns === 'function') {
      try {
        await platform.restoreDns(prev.ownedDns);
        log.record('info', 'dns restored (domains mode does not split system DNS)');
      } catch (err) {
        ownedDns = prev.ownedDns;
        log.record('info', `dns restore failed: ${err && err.message ? err.message : err}`);
      }
    }

    const nextCfg = saveConfig(paths, { ...cfg, mode });
    const state = saveState(paths, {
      applied: true,
      mode,
      ownedRoutes: desired,
      ownedDns,
      watchEnabled: nextCfg.watch,
    });
    log.record('info', `applied ${mode} (${desired.length} routes)`);
    for (const a of desired) {
      const via = (a.kind === 'allow-vpn' || a.kind === 'vpn-keep') ? 'vpn' : 'lan';
      log.record('info', `${a.dest}/${a.prefix} → ${via}${a.gw ? ` gw ${a.gw}` : ''}${a.iface ? ` ${a.iface}` : ''}${a.domain ? ` (${a.domain})` : ''}`);
    }
    const routes = built.actions.map((a) => ({
      ...a,
      dest: `${a.dest}/${a.prefix}`,
      via: a.gw,
      gateway: a.gw,
    }));
    return {
      dryRun: false,
      mode,
      actions: built.actions,
      routes,
      plan: routes,
      detect,
      state,
      dns: ownedDns,
    };
  });
}

async function off(opts) {
  const { paths, platform, dryRun = false } = opts;
  const state = loadState(paths);
  const owned = (state.ownedRoutes || []).slice();

  if (dryRun) {
    return { dryRun: true, removed: owned };
  }

  const admin = await platform.isAdmin();
  if (!admin) throw fail('EPRIV', 'administrator privileges required');

  return withLock(paths.lock, async () => {
    const latest = loadState(paths);
    const routes = latest.ownedRoutes || [];
    const ownedDns = latest.ownedDns;
    let dnsErr = null;
    if (ownedDns && typeof platform.restoreDns === 'function') {
      try {
        await platform.restoreDns(ownedDns);
        log.record('info', 'dns restored from ledger');
      } catch (err) {
        dnsErr = err;
        log.record('info', `dns restore failed: ${err && err.message ? err.message : err}`);
      }
    }
    await removeRoutes(platform, routes);
    const cfg = loadConfig(paths);
    saveConfig(paths, { ...cfg, watch: false });
    saveState(paths, {
      applied: false,
      mode: latest.mode,
      ownedRoutes: [],
      ownedDns: dnsErr ? ownedDns : null,
      watchEnabled: false,
    });
    log.record('info', `off removed ${routes.length} owned routes`);
    if (dnsErr) throw dnsErr;
    return { dryRun: false, removed: routes, dnsRestored: Boolean(ownedDns && !dnsErr) };
  });
}

async function repairOwned(opts) {
  const { paths, platform, session = false, limiter } = opts;
  const state = loadState(paths);
  const cfg = loadConfig(paths);
  if (!state.applied) return { skipped: 'off' };
  if (!session && !cfg.watch && !state.watchEnabled) return { skipped: 'watch-off' };
  const detect = await platform.detect();
  if (!detect.vpn || !detect.vpn.up) return { skipped: 'vpn-down' };
  const admin = await platform.isAdmin();
  if (!admin) return { skipped: 'epriv' };

  const current = await platform.listRoutes();
  const inspected = inspectOwned(state.ownedRoutes, current, detect);
  let dnsInspect = { ok: true };
  if (state.ownedDns && typeof platform.inspectDns === 'function') {
    try {
      dnsInspect = await platform.inspectDns(state.ownedDns);
    } catch {
      dnsInspect = { ok: true };
    }
  }
  if (inspected.ok && dnsInspect.ok) return { repaired: 0, hijacked: 0, dnsRepaired: 0 };

  if (limiter) {
    const blocked = limiter.allow();
    if (blocked) {
      return {
        skipped: blocked,
        hijacked: inspected.hijacked.length,
        missing: inspected.missing.length,
        dnsHijacked: dnsInspect.ok === false,
      };
    }
  }

  const pending = inspected.missing.concat(inspected.hijacked);
  try {
    await withLock(paths.lock, async () => {
      for (const route of pending) {
        const action = {
          ...route,
          op: (route.prefix === 32 || route.prefix === 128) ? 'addHost' : 'addCidr',
        };
        const replace = inspected.hijacked.some((h) => destMatch(h, route));
        await execAction(platform, action, { replace });
      }
      if (dnsInspect.ok === false && typeof platform.applyDns === 'function') {
        const nextDns = sanitizeOwnedDns(await platform.applyDns({
          detect,
          paths,
          previous: state.ownedDns.previous,
          reapply: true,
          pid: state.ownedDns.pid,
        }));
        const latest = loadState(paths);
        saveState(paths, { ...latest, ownedDns: nextDns });
        log.record('info', 'watch repaired DNS (VPN client overwrote resolver)');
      }
    });
  } catch (err) {
    if (err && err.code === 'ELOCK') return { skipped: 'lock', hijacked: inspected.hijacked.length };
    throw err;
  }
  if (limiter) limiter.record();
  if (pending.length) {
    log.record('info', `watch repaired ${pending.length} routes (${inspected.hijacked.length} overwritten)`);
  }
  return {
    repaired: pending.length,
    hijacked: inspected.hijacked.length,
    missing: inspected.missing.length,
    dnsRepaired: dnsInspect.ok === false ? 1 : 0,
  };
}

module.exports = {
  on,
  off,
  repairOwned,
  inspectOwned,
  createRepairLimiter,
  buildPlan,
  staleRoutes,
  ledgerEntry,
  destMatch,
  viaOk,
  SESSION_REPAIR_MS,
  CLI_WATCH_MS,
};
