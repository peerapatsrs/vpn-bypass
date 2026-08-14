'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { normalizeLocale } = require('../i18n');
const { uniqueKeep, normalizeHost } = require('./net');

const DEFAULT_CONFIG = {
  mode: 'inverse',
  domains: [],
  allowViaVpn: [],
  watch: false,
  locale: 'th',
  lanProtect: true,
};

const DEFAULT_STATE = {
  applied: false,
  mode: null,
  ownedRoutes: [],
  watchEnabled: false,
};

function effectiveHome() {
  const sudoUser = process.env.SUDO_USER;
  if (sudoUser && typeof process.getuid === 'function' && process.getuid() === 0) {
    if (process.platform === 'darwin') {
      const macHome = path.join('/Users', sudoUser);
      if (fs.existsSync(macHome)) return macHome;
    }
    if (process.platform !== 'win32') {
      const linuxHome = path.join('/home', sudoUser);
      if (fs.existsSync(linuxHome)) return linuxHome;
    }
  }
  return os.homedir();
}

function defaultConfigDir() {
  if (process.platform === 'win32') {
    const base = process.env.APPDATA || path.join(effectiveHome(), 'AppData', 'Roaming');
    return path.join(base, 'vpn-bypass');
  }
  const home = effectiveHome();
  const xdg = process.env.XDG_CONFIG_HOME;
  const base = xdg && !xdg.startsWith('/var/root') ? xdg : path.join(home, '.config');
  return path.join(base, 'vpn-bypass');
}

function getPaths(homeOverride) {
  const dir = homeOverride || process.env.VPN_BYPASS_HOME || defaultConfigDir();
  return {
    dir,
    config: path.join(dir, 'config.json'),
    state: path.join(dir, 'applied.json'),
    lock: path.join(dir, 'apply.lock'),
  };
}

function readJson(file, fallback) {
  try {
    const raw = fs.readFileSync(file, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === 'ENOENT') return fallback;
    throw err;
  }
}

function writeJson(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(obj, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmp, file);
}

function sanitizeConfig(raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const locale = normalizeLocale(src.locale) || 'th';
  const mode = src.mode === 'domains' ? 'domains' : 'inverse';
  const domains = Array.isArray(src.domains)
    ? uniqueKeep(src.domains.map((d) => normalizeHost(String(d))).filter(Boolean))
    : [];
  const allowViaVpn = Array.isArray(src.allowViaVpn)
    ? uniqueKeep(src.allowViaVpn.map((d) => normalizeHost(String(d))).filter(Boolean))
    : [];
  return {
    mode,
    domains,
    allowViaVpn,
    watch: Boolean(src.watch),
    locale,
    lanProtect: src.lanProtect !== false,
  };
}

function sanitizeState(raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const ownedRoutes = Array.isArray(src.ownedRoutes)
    ? src.ownedRoutes.map((r) => ({
      dest: String(r.dest),
      prefix: Number(r.prefix),
      gw: r.gw == null ? null : String(r.gw),
      iface: r.iface == null ? null : String(r.iface),
      kind: r.kind == null ? null : String(r.kind),
      domain: r.domain == null ? null : String(r.domain),
    }))
    : [];
  return {
    applied: Boolean(src.applied),
    mode: src.mode === 'domains' || src.mode === 'inverse' ? src.mode : null,
    ownedRoutes,
    watchEnabled: Boolean(src.watchEnabled),
  };
}

function loadConfig(paths) {
  return sanitizeConfig({ ...DEFAULT_CONFIG, ...readJson(paths.config, {}) });
}

function saveConfig(paths, cfg) {
  const next = sanitizeConfig({ ...DEFAULT_CONFIG, ...cfg });
  writeJson(paths.config, next);
  return next;
}

function loadState(paths) {
  return sanitizeState({ ...DEFAULT_STATE, ...readJson(paths.state, {}) });
}

function saveState(paths, state) {
  const next = sanitizeState({ ...DEFAULT_STATE, ...state });
  writeJson(paths.state, next);
  return next;
}

function publicConfig(cfg) {
  const allowViaVpn = cfg.allowViaVpn.slice();
  return {
    mode: cfg.mode,
    domains: cfg.domains.slice(),
    allowViaVpn,
    allowed: allowViaVpn,
    allowVpnHosts: allowViaVpn,
    watch: cfg.watch,
    locale: cfg.locale,
    lanProtect: cfg.lanProtect,
  };
}

module.exports = {
  DEFAULT_CONFIG,
  DEFAULT_STATE,
  defaultConfigDir,
  getPaths,
  loadConfig,
  saveConfig,
  loadState,
  saveState,
  publicConfig,
  sanitizeConfig,
};
