'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const net = require('net');
const { fail } = require('./errors');
const { validateTarget } = require('./net');
const { pidAlive } = require('./lock');
const { ownConfigDir, loadState } = require('./config');
const { execEnv } = require('../platform/exec');

const OSASCRIPT = '/usr/bin/osascript';
const PKEXEC = '/usr/bin/pkexec';
const ENV_KEYS = [
  'HOME',
  'USER',
  'SUDO_USER',
  'SUDO_UID',
  'SUDO_GID',
  'VPN_BYPASS_HOME',
  'VPN_BYPASS_UID',
  'VPN_BYPASS_GID',
  'VPN_BYPASS_PARENT_PID',
  'VPN_BYPASS_HELPER_SOCK',
  'VPN_BYPASS_LANG',
  'PATH',
  'LANG',
];
const JOB_CMDS = new Set(['on', 'off', 'allow', 'deny', 'watch', 'repair', 'ping', 'quit']);
const PROMPT = 'VPN Bypass needs administrator access to change routes / ต้องการสิทธิ์ผู้ดูแลเพื่อแก้เส้นทาง';

function cliScriptPath() {
  return path.resolve(__dirname, '..', '..', 'bin', 'vpn-bypass.js');
}

function refuseRealGuiElevate() {
  return Boolean(process.env.NODE_TEST_CONTEXT) && process.env.VPN_BYPASS_ALLOW_ELEVATE !== '1';
}

function posixQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function appleScriptQuote(value) {
  return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function toPlatformSockPath(sockPath, dir, uid) {
  if (process.platform === 'win32') {
    if (sockPath && (sockPath.startsWith('\\\\.\\pipe\\') || sockPath.startsWith('\\\\?\\pipe\\'))) {
      return sockPath;
    }
    const base = sockPath || (dir ? path.join(dir, 'elevate.sock') : `elevate-${uid ?? 'user'}`);
    const name = String(base).replace(/[^a-zA-Z0-9._-]/g, '_');
    return `\\\\.\\pipe\\vpn-bypass-${name}`;
  }
  if (sockPath) return sockPath;
  return defaultSockPath(dir, uid);
}

function defaultSockPath(dir, uid) {
  if (process.platform === 'win32') {
    return toPlatformSockPath(null, dir, uid);
  }
  const preferred = path.join(dir, 'elevate.sock');
  if (Buffer.byteLength(preferred) < 100) return preferred;
  const id = uid == null ? 'user' : String(uid);
  return path.join(os.tmpdir(), `vpn-bypass-elevate-${id}.sock`);
}

function pidFilePath(dir) {
  return path.join(dir, 'elevate.pid');
}

function pickEnv(src) {
  const out = {};
  for (const key of ENV_KEYS) {
    if (src[key] != null && src[key] !== '') out[key] = String(src[key]);
  }
  return out;
}

function helperEnv(paths, extra = {}) {
  let user = extra.user || process.env.SUDO_USER || process.env.USER || '';
  try {
    if (!user) user = os.userInfo().username;
  } catch {
    user = user || '';
  }
  const uid = typeof process.getuid === 'function' ? process.getuid() : extra.uid;
  const gid = typeof process.getgid === 'function' ? process.getgid() : extra.gid;
  const sock = extra.sockPath || defaultSockPath(paths.dir, uid);
  return pickEnv({
    HOME: extra.HOME || os.homedir(),
    USER: user,
    SUDO_USER: user,
    SUDO_UID: uid == null ? '' : String(uid),
    SUDO_GID: gid == null ? '' : String(gid),
    VPN_BYPASS_HOME: paths.dir,
    VPN_BYPASS_UID: uid == null ? '' : String(uid),
    VPN_BYPASS_GID: gid == null ? '' : String(gid),
    VPN_BYPASS_PARENT_PID: String(extra.parentPid || process.pid),
    VPN_BYPASS_HELPER_SOCK: sock,
    VPN_BYPASS_LANG: extra.lang || process.env.VPN_BYPASS_LANG || '',
    PATH: extra.PATH || execEnv().PATH,
    LANG: process.env.LANG || '',
  });
}

function buildDarwinShellCommand({ node, script, args = [], env = {} }) {
  const assigns = ENV_KEYS
    .filter((key) => env[key] != null && env[key] !== '')
    .map((key) => `${key}=${posixQuote(env[key])}`);
  const cmd = [posixQuote(node), posixQuote(script), ...args.map((a) => posixQuote(String(a)))];
  return `${assigns.concat(cmd).join(' ')}`;
}

function buildDarwinElevateScript(shellCmd, prompt = PROMPT) {
  return `do shell script ${appleScriptQuote(shellCmd)} with prompt ${appleScriptQuote(prompt)} with administrator privileges`;
}

function assertJob(job) {
  if (!job || typeof job !== 'object' || !JOB_CMDS.has(job.cmd)) {
    throw fail('EINVAL', 'invalid elevate job');
  }
  if (job.mode != null && job.mode !== 'inverse' && job.mode !== 'domains') {
    throw fail('EINVAL', 'invalid mode');
  }
  if (job.cmd === 'allow' || job.cmd === 'deny') {
    validateTarget(job.host);
  }
  return job;
}

function jobToArgv(job) {
  assertJob(job);
  switch (job.cmd) {
    case 'on': {
      const argv = ['on'];
      if (job.mode === 'inverse' || job.mode === 'domains') argv.push('--mode', job.mode);
      return argv;
    }
    case 'off':
      return ['off'];
    case 'allow':
      return ['allow', String(job.host)];
    case 'deny':
      return ['deny', String(job.host)];
    case 'watch':
      return job.enabled ? ['watch'] : ['watch', 'off'];
    default:
      throw fail('EINVAL', `job ${job.cmd} cannot run as a one-shot CLI`);
  }
}

function isCanceled(stderr, code) {
  const s = `${stderr || ''}`;
  if (/User canceled/i.test(s) || /canceled by the user/i.test(s) || /-128/.test(s)) return true;
  if (/Request dismissed/i.test(s) || /org\.freedesktop\.PolicyKit/i.test(s) && /dismissed/i.test(s)) return true;
  if (code === 122 /* pkexec auth fail */) return true;
  return false;
}

function spawnOnce(file, args, opts = {}) {
  const spawnImpl = opts.spawnImpl || spawn;
  if (spawnImpl === spawn && refuseRealGuiElevate()) {
    return Promise.reject(fail('EPRIV', 'elevate disabled during tests'));
  }
  if (!Array.isArray(args) || args.some((a) => typeof a !== 'string')) {
    return Promise.reject(new TypeError('elevate args must be a string array'));
  }
  const timeoutMs = opts.timeoutMs == null ? 300000 : opts.timeoutMs;
  const env = opts.env || undefined;
  return new Promise((resolve, reject) => {
    const child = spawnImpl(file, args, {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    if (child.stdout && typeof child.stdout.on === 'function') {
      child.stdout.on('data', (c) => { stdout += c; });
    }
    if (child.stderr && typeof child.stderr.on === 'function') {
      child.stderr.on('data', (c) => { stderr += c; });
    }
    const timer = setTimeout(() => {
      try { child.kill(); } catch { /* ignore */ }
      reject(fail('EFAIL', 'elevate timed out'));
    }, timeoutMs);
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code == null ? 1 : code, stdout, stderr });
    });
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function rpcOnce(sockPath, job, timeoutMs = 120000) {
  assertJob(job);
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(sockPath);
    let buf = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch { /* ignore */ }
      reject(fail('EFAIL', 'elevate helper timed out'));
    }, timeoutMs);
    function done(err, data) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { sock.end(); } catch { /* ignore */ }
      if (err) reject(err);
      else resolve(data);
    }
    sock.on('error', (err) => done(fail('EFAIL', err.message || 'elevate helper unavailable')));
    sock.on('data', (chunk) => {
      buf += chunk;
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      const line = buf.slice(0, nl);
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch (err) {
        done(fail('EFAIL', 'invalid helper response'));
        return;
      }
      if (parsed && parsed.ok === false) {
        const code = parsed.error && parsed.error.code ? parsed.error.code : 'EFAIL';
        done(fail(code, parsed.error && parsed.error.message ? parsed.error.message : code));
        return;
      }
      done(null, parsed && Object.prototype.hasOwnProperty.call(parsed, 'data') ? parsed.data : parsed);
    });
    sock.on('connect', () => {
      sock.write(`${JSON.stringify(job)}\n`);
    });
  });
}

async function resultFromDisk(service, job) {
  const cfg = service.getConfig();
  const state = loadState(service.paths);
  switch (job.cmd) {
    case 'on': {
      const st = await service.getStatus();
      return {
        dryRun: false,
        mode: st.mode,
        applied: st.applied,
        routes: st.ownedRoutes,
        dns: st.dns,
      };
    }
    case 'off':
      return { dryRun: false, removed: state.ownedRoutes || [] };
    case 'allow':
    case 'deny':
      return { host: job.host, allowViaVpn: cfg.allowViaVpn };
    case 'watch':
      return { enabled: Boolean(job.enabled) };
    default:
      return {};
  }
}

function pkexecExists() {
  try {
    return fs.existsSync(PKEXEC);
  } catch {
    return false;
  }
}

function createElevate(opts = {}) {
  const paths = opts.paths;
  if (!paths || !paths.dir) throw new Error('elevate paths required');
  const platformName = opts.platform || process.platform;
  const spawnImpl = opts.spawnImpl || spawn;
  const node = opts.node || process.execPath;
  const script = opts.script || cliScriptPath();
  const rawSockPath = opts.sockPath || defaultSockPath(paths.dir, typeof process.getuid === 'function' ? process.getuid() : 0);
  const sockPath = toPlatformSockPath(rawSockPath, paths.dir, typeof process.getuid === 'function' ? process.getuid() : 0);
  const pidFile = opts.pidFile || pidFilePath(paths.dir);

  function supported() {
    if (typeof opts.supported === 'boolean') return opts.supported;
    if (platformName === 'darwin') return true;
    if (platformName === 'linux') return pkexecExists();
    if (platformName === 'win32') return true;
    return false;
  }

  function isHelperRunning() {
    try {
      const raw = fs.readFileSync(pidFile, 'utf8').trim();
      const pid = Number(raw);
      if (!pidAlive(pid)) return false;
      if (platformName === 'win32' || process.platform === 'win32' || sockPath.startsWith('\\\\.\\pipe\\') || sockPath.startsWith('\\\\?\\pipe\\')) {
        return true;
      }
      return fs.existsSync(sockPath);
    } catch {
      return false;
    }
  }

  async function waitUntilReady(timeoutMs = 15000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (isHelperRunning()) {
        try {
          await rpcOnce(sockPath, { cmd: 'ping' }, 2000);
          return;
        } catch {
          // retry
        }
      }
      await sleep(50);
    }
    throw fail('EFAIL', 'elevate helper did not start');
  }

  async function startDarwinHelper() {
    if (typeof opts.startHelper === 'function') {
      await opts.startHelper();
      await waitUntilReady();
      return;
    }
    fs.mkdirSync(paths.dir, { recursive: true });
    ownConfigDir(paths.dir);
    const env = helperEnv(paths, { sockPath, parentPid: process.pid });
    const shellCmd = buildDarwinShellCommand({
      node,
      script,
      args: ['elevate-helper'],
      env,
    });
    const osa = buildDarwinElevateScript(shellCmd);
    const result = await spawnOnce(OSASCRIPT, ['-e', osa], {
      spawnImpl,
      timeoutMs: 300000,
    });
    if (isCanceled(result.stderr, result.code)) {
      throw fail('EPRIV', 'administrator privileges required');
    }
    if (result.code !== 0) {
      throw fail('EPRIV', result.stderr || 'administrator privileges required');
    }
    await waitUntilReady();
  }

  async function ensureHelper() {
    if (isHelperRunning()) {
      try {
        await rpcOnce(sockPath, { cmd: 'ping' }, 2000);
        return;
      } catch {
        // restart
      }
    }
    if (platformName !== 'darwin') {
      throw fail('EPRIV', 'administrator privileges required');
    }
    await startDarwinHelper();
  }

  async function oneShot(job) {
    const argv = jobToArgv(job);
    const env = helperEnv(paths, { sockPath, parentPid: process.pid });
    if (platformName === 'linux') {
      if (!pkexecExists() && spawnImpl === spawn) {
        throw fail('EPRIV', 'administrator privileges required');
      }
      const envArgs = ENV_KEYS.filter((k) => env[k]).map((k) => `${k}=${env[k]}`);
      const result = await spawnOnce(PKEXEC, ['/usr/bin/env', ...envArgs, node, script, ...argv], {
        spawnImpl,
        timeoutMs: 300000,
      });
      if (isCanceled(result.stderr, result.code) || result.code !== 0) {
        throw fail('EPRIV', result.stderr || 'administrator privileges required');
      }
      return { elevated: true };
    }
    if (platformName === 'win32') {
      const argList = [script, ...argv].map((a) => `'${String(a).replace(/'/g, "''")}'`).join(',');
      const cmd = `Start-Process -FilePath '${String(node).replace(/'/g, "''")}' -ArgumentList @(${argList}) -Verb RunAs -Wait -WindowStyle Hidden`;
      const result = await spawnOnce('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd], {
        spawnImpl,
        timeoutMs: 300000,
      });
      if (result.code !== 0) {
        throw fail('EPRIV', result.stderr || 'administrator privileges required');
      }
      return { elevated: true };
    }
    throw fail('EPRIV', 'administrator privileges required');
  }

  async function run(job) {
    assertJob(job);
    if (job.cmd === 'repair' || job.cmd === 'ping' || job.cmd === 'quit' || (job.cmd === 'watch' && job.enabled === false)) {
      if (!isHelperRunning()) {
        if (job.cmd === 'watch') return { enabled: false };
        if (job.cmd === 'quit' || job.cmd === 'ping') return { ok: true };
        return { skipped: 'epriv' };
      }
      return rpcOnce(sockPath, job);
    }
    if (platformName === 'darwin' && supported()) {
      await ensureHelper();
      return rpcOnce(sockPath, job);
    }
    if (job.cmd === 'on' || job.cmd === 'off' || job.cmd === 'allow' || job.cmd === 'deny') {
      return oneShot(job);
    }
    throw fail('EPRIV', 'administrator privileges required');
  }

  async function quit() {
    if (!isHelperRunning()) return { ok: true };
    try {
      return await rpcOnce(sockPath, { cmd: 'quit' }, 3000);
    } catch {
      return { ok: true };
    }
  }

  return {
    supported,
    isHelperRunning,
    ensureHelper,
    run,
    quit,
    sockPath,
    pidFile,
    paths,
    platformName,
  };
}

function canRunElevate(service) {
  return Boolean(service && service.elevate && typeof service.elevate.supported === 'function' && service.elevate.supported());
}

async function withElevate(service, job, fn, after) {
  try {
    return await fn();
  } catch (err) {
    if (!err || err.code !== 'EPRIV' || !canRunElevate(service)) throw err;
    const data = await service.elevate.run(job);
    if (typeof after === 'function') return after(data);
    if (data && data.elevated) return resultFromDisk(service, job);
    if (data == null) return resultFromDisk(service, job);
    return data;
  }
}

module.exports = {
  OSASCRIPT,
  PKEXEC,
  ENV_KEYS,
  PROMPT,
  posixQuote,
  appleScriptQuote,
  defaultSockPath,
  pidFilePath,
  helperEnv,
  buildDarwinShellCommand,
  buildDarwinElevateScript,
  assertJob,
  jobToArgv,
  isCanceled,
  cliScriptPath,
  refuseRealGuiElevate,
  createElevate,
  toPlatformSockPath,
  canRunElevate,
  withElevate,
  resultFromDisk,
  helperChildEnvKeys: ENV_KEYS,
};
