'use strict';

const { fail } = require('./errors');
const { withLock } = require('./lock');
const { loadConfig, saveConfig, loadState, saveState } = require('./config');
const { plan } = require('./plan');
const { routeKey } = require('./net');
const { resolveHostIps, defaultResolve4 } = require('./probe');
const log = require('./log');

function ledgerEntry(action) {
  return {
    dest: action.dest,
    prefix: action.prefix,
    gw: action.gw || null,
    iface: action.iface || null,
    kind: action.kind || null,
    domain: action.domain || null,
  };
}

async function execAction(platform, action) {
  if (action.op === 'addHost' || action.prefix === 32) {
    await platform.addHost(action);
  } else {
    await platform.addCidr(action);
  }
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
      return {
        dryRun: true,
        mode,
        actions: built.actions,
        routes,
        plan: routes,
        detect,
      };
    }

    const admin = await platform.isAdmin();
    if (!admin) throw fail('EPRIV', 'administrator privileges required');

    const prev = loadState(paths);
    const desired = built.actions.map(ledgerEntry);
    const extra = staleRoutes(prev.ownedRoutes, desired);
    await removeRoutes(platform, extra);
    await applyActions(platform, built.actions);

    const nextCfg = saveConfig(paths, { ...cfg, mode });
    const state = saveState(paths, {
      applied: true,
      mode,
      ownedRoutes: desired,
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
    await removeRoutes(platform, routes);
    const cfg = loadConfig(paths);
    saveConfig(paths, { ...cfg, watch: false });
    saveState(paths, {
      applied: false,
      mode: latest.mode,
      ownedRoutes: [],
      watchEnabled: false,
    });
    log.record('info', `off removed ${routes.length} owned routes`);
    return { dryRun: false, removed: routes };
  });
}

async function repairOwned(opts) {
  const { paths, platform } = opts;
  const state = loadState(paths);
  const cfg = loadConfig(paths);
  if (!state.applied) return { skipped: 'off' };
  if (!cfg.watch && !state.watchEnabled) return { skipped: 'watch-off' };
  const detect = await platform.detect();
  if (!detect.vpn || !detect.vpn.up) return { skipped: 'vpn-down' };
  const admin = await platform.isAdmin();
  if (!admin) return { skipped: 'epriv' };

  const current = await platform.listRoutes();
  const missing = [];
  for (const owned of state.ownedRoutes || []) {
    const found = current.some((r) => r.dest === owned.dest && Number(r.prefix) === Number(owned.prefix));
    if (!found) missing.push(owned);
  }
  for (const route of missing) {
    const action = { ...route, op: route.prefix === 32 ? 'addHost' : 'addCidr' };
    await execAction(platform, action);
  }
  if (missing.length) log.record('info', `watch repaired ${missing.length} routes`);
  return { repaired: missing.length };
}

module.exports = {
  on,
  off,
  repairOwned,
  buildPlan,
  staleRoutes,
  ledgerEntry,
};
