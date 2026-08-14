'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { normalizeLocale } = require('../i18n');
const { uniqueKeep, normalizeHost } = require('./net');
const { sanitizeOwnedDns } = require('./dns');
const { fail } = require('./errors');

const CHOWN_HINT = 'sudo chown -R "$(whoami)" ~/.config/vpn-bypass';
const SAFE_UNIX_USER = /^[A-Za-z0-9._-]+$/;

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
  ownedDns: null,
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

function configAccessError(file, err) {
  const target = file || '~/.config/vpn-bypass';
  const code = err && err.code ? err.code : 'EACCES';
  return fail(
    'EACCES',
    `cannot open ${target} (${code}); if you previously ran this tool with sudo, fix ownership: ${CHOWN_HINT}`,
  );
}

function readJson(file, fallback) {
  try {
    const raw = fs.readFileSync(file, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === 'ENOENT') return fallback;
    if (err.code === 'EACCES') throw configAccessError(file, err);
    throw err;
  }
}

function parsePositiveId(value) {
  if (value == null || value === '') return null;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) return null;
  return n;
}

function idsFromSudoUser() {
  const name = process.env.SUDO_USER;
  if (!name || !SAFE_UNIX_USER.test(name)) return null;
  if (typeof process.getuid !== 'function' || process.getuid() !== 0) return null;
  try {
    const uid = parsePositiveId(execFileSync('id', ['-u', name], {
      encoding: 'utf8',
      timeout: 2000,
    }).trim());
    const gid = parsePositiveId(execFileSync('id', ['-g', name], {
      encoding: 'utf8',
      timeout: 2000,
    }).trim());
    if (uid == null) return null;
    return { uid, gid: gid == null ? uid : gid };
  } catch {
    return null;
  }
}

function parseInvokerIds() {
  const uid = parsePositiveId(process.env.VPN_BYPASS_UID) ?? parsePositiveId(process.env.SUDO_UID);
  if (uid != null) {
    const gid = parsePositiveId(process.env.VPN_BYPASS_GID)
      ?? parsePositiveId(process.env.SUDO_GID)
      ?? uid;
    return { uid, gid };
  }
  return idsFromSudoUser();
}

function ownAsInvoker(file) {
  if (!file) return;
  if (typeof process.getuid !== 'function' || process.getuid() !== 0) return;
  const ids = parseInvokerIds();
  if (!ids) return;
  try {
    fs.chownSync(file, ids.uid, ids.gid);
  } catch {
    // ignore
  }
}

function ownConfigDir(dir) {
  if (!dir) return;
  ownAsInvoker(dir);
  try {
    for (const name of fs.readdirSync(dir)) {
      ownAsInvoker(path.join(dir, name));
    }
  } catch {
    // ignore
  }
}

function writeJson(file, obj) {
  try {
    const dir = path.dirname(file);
    fs.mkdirSync(dir, { recursive: true });
    ownAsInvoker(dir);
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, `${JSON.stringify(obj, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    ownAsInvoker(tmp);
    fs.renameSync(tmp, file);
    ownAsInvoker(file);
    ownConfigDir(dir);
  } catch (err) {
    if (err && err.code === 'EACCES') throw configAccessError(file, err);
    throw err;
  }
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
      family: r.family === 'inet6' ? 'inet6' : 'inet',
    }))
    : [];
  return {
    applied: Boolean(src.applied),
    mode: src.mode === 'domains' || src.mode === 'inverse' ? src.mode : null,
    ownedRoutes,
    ownedDns: sanitizeOwnedDns(src.ownedDns),
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
  CHOWN_HINT,
  defaultConfigDir,
  getPaths,
  loadConfig,
  saveConfig,
  loadState,
  saveState,
  publicConfig,
  sanitizeConfig,
  parseInvokerIds,
  ownAsInvoker,
  ownConfigDir,
};
