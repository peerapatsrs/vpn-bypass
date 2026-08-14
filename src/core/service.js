'use strict';

const { fail } = require('./errors');
const {
  getPaths, loadConfig, saveConfig, loadState, saveState, publicConfig,
} = require('./config');
const { getPlatform } = require('../platform');
const { on, off, repairOwned } = require('./apply');
const { probeHost, resolveHostIps, defaultResolve4, defaultProbeTls } = require('./probe');
const { expandWwwApex, uniqueKeep, validateTarget, routeKey } = require('./net');
const { bestRoute, annotateRoute } = require('./match');
const { createTrafficTracker } = require('./traffic');
const { warningList, normalizeLocale, t } = require('../i18n');
const { getPublicIps } = require('./publicIp');
const { createWatch } = require('./watch');
const log = require('./log');

function requireAdmin(ok) {
  if (!ok) throw fail('EPRIV', 'administrator privileges required');
}

class Service {
  constructor(opts = {}) {
    this.paths = getPaths(opts.home);
    this.platform = opts.platform || getPlatform(opts);
    this.resolveDns = opts.resolveDns || defaultResolve4;
    this.probeTls = opts.probeTls || defaultProbeTls;
    this.fetchIp = opts.fetchIp || null;
    this.localeOverride = normalizeLocale(opts.locale);
    this.watch = createWatch();
    this.traffic = createTrafficTracker({ reverseDns: opts.reverseDns });
  }

  locale() {
    return this.localeOverride || loadConfig(this.paths).locale || 'th';
  }

  async getStatus() {
    const cfg = loadConfig(this.paths);
    const state = loadState(this.paths);
    const locale = this.locale();
    let detect;
    try {
      detect = await this.platform.detect();
    } catch {
      detect = { os: process.platform, vpn: { up: false }, lan: {}, ifaces: [] };
    }
    let hasAdmin = false;
    try {
      hasAdmin = await this.platform.isAdmin();
    } catch {
      hasAdmin = false;
    }
    const watchOn = Boolean(cfg.watch && state.applied && this.watch.isRunning());
    const lan = detect.lan || {};
    const vpn = detect.vpn || {};
    const ifaces = detect.ifaces || [];
    return {
      os: detect.os || process.platform,
      hasAdmin,
      mode: state.applied ? state.mode : cfg.mode,
      applied: Boolean(state.applied),
      watch: watchOn,
      watchActive: watchOn,
      locale,
      warnings: warningList(locale),
      ifaces,
      lan,
      vpn,
      ownedRoutes: (state.ownedRoutes || []).map((r) => annotateRoute(detect, r)),
      domains: cfg.domains,
      allowViaVpn: cfg.allowViaVpn,
      allowed: cfg.allowViaVpn,
      allowVpnHosts: cfg.allowViaVpn,
    };
  }

  getConfig() {
    return publicConfig(loadConfig(this.paths));
  }

  putConfig(partial) {
    const cfg = loadConfig(this.paths);
    const next = { ...cfg };
    if (partial && Object.prototype.hasOwnProperty.call(partial, 'locale')) {
      const loc = normalizeLocale(partial.locale);
      if (!loc) throw fail('EINVAL', 'locale must be th or en');
      next.locale = loc;
    }
    if (partial && Object.prototype.hasOwnProperty.call(partial, 'mode')) {
      if (partial.mode !== 'inverse' && partial.mode !== 'domains') {
        throw fail('EINVAL', 'mode must be inverse or domains');
      }
      if (partial.mode === 'domains' && !(next.domains && next.domains.length)) {
        throw fail('EDOMAIN_EMPTY', 'empty domain list');
      }
      next.mode = partial.mode;
    }
    if (partial && Object.prototype.hasOwnProperty.call(partial, 'watch')) {
      next.watch = Boolean(partial.watch);
    }
    if (partial && Array.isArray(partial.domains)) {
      next.domains = uniqueKeep(partial.domains.map((d) => String(d)));
    }
    if (partial && Array.isArray(partial.allowViaVpn)) {
      next.allowViaVpn = uniqueKeep(partial.allowViaVpn.map((d) => String(d)));
    }
    const saved = saveConfig(this.paths, next);
    if (saved.watch) this._ensureWatch();
    else this.watch.stop();
    return publicConfig(saved);
  }

  async on(opts = {}) {
    const result = await on({
      paths: this.paths,
      platform: this.platform,
      dryRun: Boolean(opts.dryRun),
      mode: opts.mode,
      resolveDns: this.resolveDns,
    });
    const cfg = loadConfig(this.paths);
    if (!opts.dryRun && cfg.watch) this._ensureWatch();
    return result;
  }

  async off(opts = {}) {
    this.watch.stop();
    return off({
      paths: this.paths,
      platform: this.platform,
      dryRun: Boolean(opts.dryRun),
    });
  }

  listDomains() {
    return loadConfig(this.paths).domains.slice();
  }

  async addDomain(host) {
    const parsed = validateTarget(host, { allowIp: true });
    const expanded = expandWwwApex(parsed.value);
    const cfg = loadConfig(this.paths);
    const domains = uniqueKeep(cfg.domains.concat(expanded));
    saveConfig(this.paths, { ...cfg, domains });
    log.record('info', `domain add ${expanded.join(', ')}`);
    const state = loadState(this.paths);
    if (state.applied && state.mode === 'domains') {
      await this.on({ mode: 'domains' });
    }
    return domains;
  }

  async removeDomain(host) {
    const parsed = validateTarget(host, { allowIp: true });
    const cfg = loadConfig(this.paths);
    const domains = cfg.domains.filter((d) => d !== parsed.value);
    const state = loadState(this.paths);
    if (state.applied && state.mode === 'domains' && domains.length === 0) {
      throw fail('EDOMAIN_EMPTY', 'empty domain list');
    }
    saveConfig(this.paths, { ...cfg, domains });
    log.record('info', `domain rm ${parsed.value}`);
    if (state.applied && state.mode === 'domains') {
      await this.on({ mode: 'domains' });
    }
    return domains;
  }

  async lookupHost(host) {
    const parsed = validateTarget(host);
    const detect = await this.platform.detect();
    let routes = detect.routes || [];
    if ((!routes || !routes.length) && typeof this.platform.listRoutes === 'function') {
      try {
        routes = await this.platform.listRoutes();
      } catch {
        routes = [];
      }
    }
    let ips;
    if (parsed.type === 'ipv4') {
      ips = [parsed.value];
    } else {
      const resolved = await resolveHostIps(parsed.value, this.resolveDns);
      ips = resolved.ips;
    }
    const hits = ips.map((ip) => {
      const matched = bestRoute(routes, ip);
      const row = annotateRoute(detect, matched || { dest: ip, prefix: 32, gw: null, iface: null, kind: null });
      if (!matched) row.via = 'unknown';
      if (parsed.type === 'hostname') this.traffic.rememberName(ip, parsed.value);
      return {
        ip,
        via: row.via,
        iface: row.iface,
        gw: row.gw,
        cidr: matched ? `${matched.dest}/${matched.prefix}` : null,
        kind: matched && matched.kind ? matched.kind : null,
      };
    });
    log.record(
      'info',
      `lookup ${parsed.value}: ${hits.map((h) => `${h.ip}→${h.via}${h.iface ? `@${h.iface}` : ''}`).join(', ')}`,
    );
    return { host: parsed.value, hits };
  }

  async tryHost(host) {
    const detect = await this.platform.detect();
    const localAddress = detect && detect.lan && detect.lan.addr ? detect.lan.addr : null;
    if (!localAddress) throw fail('ENOLAN', 'no LAN address to probe from');
    return probeHost(host, {
      resolveDns: this.resolveDns,
      probeTls: this.probeTls,
      localAddress,
    });
  }

  async allowHost(host) {
    const admin = await this.platform.isAdmin();
    requireAdmin(admin);
    const parsed = validateTarget(host);
    const cfg = loadConfig(this.paths);
    const allowViaVpn = uniqueKeep(cfg.allowViaVpn.concat([parsed.value]));
    saveConfig(this.paths, { ...cfg, allowViaVpn });
    const state = loadState(this.paths);
    if (state.applied) {
      const detect = await this.platform.detect();
      if (!detect.vpn || !detect.vpn.up) throw fail('ENOTVPN', 'VPN is not up');
      const resolved = await resolveHostIps(parsed.value, this.resolveDns);
      const added = [];
      for (const ip of resolved.ips) {
        const action = {
          op: 'addHost',
          dest: ip,
          prefix: 32,
          gw: detect.vpn.gw || null,
          iface: detect.vpn.iface || null,
          kind: 'allow-vpn',
          domain: parsed.value,
        };
        await this.platform.addHost(action);
        added.push({
          dest: ip, prefix: 32, gw: action.gw, iface: action.iface, kind: 'allow-vpn', domain: parsed.value,
        });
      }
      const owned = state.ownedRoutes.slice();
      for (const row of added) {
        if (!owned.some((r) => routeKey(r) === routeKey(row))) owned.push(row);
      }
      saveState(this.paths, { ...state, ownedRoutes: owned });
    }
    log.record('info', `allow ${parsed.value} via VPN`);
    return { host: parsed.value, allowViaVpn };
  }

  async denyHost(host) {
    const admin = await this.platform.isAdmin();
    requireAdmin(admin);
    const parsed = validateTarget(host);
    const cfg = loadConfig(this.paths);
    const allowViaVpn = cfg.allowViaVpn.filter((h) => h !== parsed.value);
    saveConfig(this.paths, { ...cfg, allowViaVpn });
    const state = loadState(this.paths);
    const removed = (state.ownedRoutes || []).filter((r) => r.kind === 'allow-vpn' && r.domain === parsed.value);
    for (const route of removed) {
      await this.platform.del(route);
    }
    saveState(this.paths, {
      ...state,
      ownedRoutes: (state.ownedRoutes || []).filter((r) => !(r.kind === 'allow-vpn' && r.domain === parsed.value)),
    });
    log.record('info', `deny ${parsed.value}`);
    return { host: parsed.value, allowViaVpn };
  }

  async setWatch(enabled) {
    const cfg = loadConfig(this.paths);
    const state = loadState(this.paths);
    if (enabled) {
      const admin = await this.platform.isAdmin();
      requireAdmin(admin);
      if (!state.applied) throw fail('ENOTAPPLIED', 'apply routes before watch');
      saveConfig(this.paths, { ...cfg, watch: true });
      saveState(this.paths, { ...state, watchEnabled: true });
      this._ensureWatch();
      log.record('info', 'watch on');
      return { enabled: true };
    }
    this.watch.stop();
    saveConfig(this.paths, { ...cfg, watch: false });
    saveState(this.paths, { ...state, watchEnabled: false });
    log.record('info', 'watch off');
    return { enabled: false };
  }

  _ensureWatch(unref = true) {
    this.watch.start(async () => {
      await repairOwned({ paths: this.paths, platform: this.platform });
    }, 8000, { unref });
  }

  startWatchLoop({ unref = false } = {}) {
    this._ensureWatch(unref);
  }

  stopWatch() {
    this.watch.stop();
  }

  getLog() {
    return log.list();
  }

  async getTraffic() {
    let detect;
    try {
      detect = await this.platform.detect();
    } catch {
      detect = { os: process.platform, vpn: { up: false }, lan: {}, ifaces: [], routes: [] };
    }
    if ((!detect.routes || !detect.routes.length) && typeof this.platform.listRoutes === 'function') {
      try {
        detect = { ...detect, routes: await this.platform.listRoutes() };
      } catch {
        detect = { ...detect, routes: detect.routes || [] };
      }
    }
    let connections = [];
    if (typeof this.platform.listConnections === 'function') {
      try {
        connections = await this.platform.listConnections();
      } catch {
        connections = [];
      }
    }
    return this.traffic.snapshot(detect, connections);
  }

  async getIps() {
    let detect;
    try {
      detect = await this.platform.detect();
    } catch (err) {
      return {
        lan: null,
        vpn: null,
        lanIp: null,
        vpnIp: null,
        error: err.message,
        lanResult: { ip: null, error: err.message, endpoint: null },
        vpnResult: { ip: null, error: err.message, endpoint: null },
      };
    }
    return getPublicIps(detect, this.fetchIp || undefined);
  }

  t(key, vars) {
    return t(this.locale(), key, vars);
  }
}

module.exports = { Service };
