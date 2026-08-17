'use strict';

const fs = require('fs');
const net = require('net');
const { spawn } = require('child_process');
const { fail } = require('./errors');
const { ownAsInvoker, ownConfigDir } = require('./config');
const { repairOwned } = require('./apply');
const { pidAlive } = require('./lock');
const { assertJob, defaultSockPath, toPlatformSockPath, pidFilePath, ENV_KEYS } = require('./elevate');
const { execEnv } = require('../platform/exec');

const MAX_JOB = 64 * 1024;

function helperChildEnv() {
  const env = {};
  for (const key of ENV_KEYS) {
    if (process.env[key]) env[key] = process.env[key];
  }
  env.VPN_BYPASS_HELPER_READY = '1';
  env.PATH = execEnv().PATH;
  if (process.env.HOME) env.HOME = process.env.HOME;
  return env;
}

function daemonizeHelper() {
  if (process.env.VPN_BYPASS_HELPER_READY === '1') return false;
  if (process.env.VPN_BYPASS_HELPER_FOREGROUND === '1') return false;
  const child = spawn(process.execPath, [process.argv[1], 'elevate-helper'], {
    detached: true,
    stdio: 'ignore',
    env: helperChildEnv(),
    windowsHide: true,
  });
  child.unref();
  return true;
}

async function handleJob(service, job) {
  assertJob(job);
  switch (job.cmd) {
    case 'ping':
      return { ok: true, pid: process.pid };
    case 'on':
      return service.on({ mode: job.mode });
    case 'off':
      return service.off();
    case 'allow':
      return service.allowHost(job.host);
    case 'deny':
      return service.denyHost(job.host);
    case 'watch':
      return service.setWatch(Boolean(job.enabled));
    case 'repair':
      return repairOwned({
        paths: service.paths,
        platform: service.platform,
        session: true,
        limiter: service.repairLimiter,
      });
    case 'quit':
      return { ok: true, quit: true };
    default:
      throw fail('EINVAL', 'unknown elevate job');
  }
}

function sendJson(conn, obj) {
  try {
    conn.write(`${JSON.stringify(obj)}\n`);
  } catch {
    // ignore
  }
}

function attachConn(conn, service, onQuit) {
  let buf = '';
  conn.on('data', async (chunk) => {
    buf += chunk;
    if (buf.length > MAX_JOB) {
      sendJson(conn, { ok: false, error: { code: 'EINVAL', message: 'job too large' } });
      conn.end();
      return;
    }
    const nl = buf.indexOf('\n');
    if (nl === -1) return;
    const line = buf.slice(0, nl);
    buf = buf.slice(nl + 1);
    let job;
    try {
      job = JSON.parse(line);
    } catch {
      sendJson(conn, { ok: false, error: { code: 'EINVAL', message: 'invalid JSON' } });
      return;
    }
    try {
      const data = await handleJob(service, job);
      sendJson(conn, { ok: true, data });
      if (job.cmd === 'quit') {
        conn.end();
        if (typeof onQuit === 'function') onQuit();
      }
    } catch (err) {
      sendJson(conn, {
        ok: false,
        error: {
          code: (err && err.code) || 'EFAIL',
          message: (err && err.message) || 'elevate failed',
        },
      });
    }
  });
}

function listenHelper(service, opts = {}) {
  const paths = service.paths;
  const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
  const rawSock = opts.sockPath || process.env.VPN_BYPASS_HELPER_SOCK || defaultSockPath(paths.dir, uid);
  const sockPath = toPlatformSockPath(rawSock, paths.dir, uid);
  const pidFile = opts.pidFile || pidFilePath(paths.dir);
  const isPipe = sockPath.startsWith('\\\\.\\pipe\\') || sockPath.startsWith('\\\\?\\pipe\\');
  fs.mkdirSync(paths.dir, { recursive: true });
  ownConfigDir(paths.dir);
  if (!isPipe) {
    try { fs.unlinkSync(sockPath); } catch { /* ignore */ }
  }

  const server = net.createServer();
  let closing = false;

  function shutdown() {
    if (closing) return;
    closing = true;
    try { server.close(); } catch { /* ignore */ }
    if (!isPipe) {
      try { fs.unlinkSync(sockPath); } catch { /* ignore */ }
    }
    try { fs.unlinkSync(pidFile); } catch { /* ignore */ }
    if (typeof opts.onShutdown === 'function') opts.onShutdown();
  }

  server.on('connection', (conn) => {
    attachConn(conn, service, shutdown);
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(sockPath, () => {
      server.removeListener('error', reject);
      if (!isPipe) {
        try { fs.chmodSync(sockPath, 0o600); } catch { /* ignore */ }
        ownAsInvoker(sockPath);
      }
      fs.writeFileSync(pidFile, `${process.pid}\n`, { encoding: 'utf8', mode: 0o600 });
      ownAsInvoker(pidFile);
      ownConfigDir(paths.dir);

      const parentPid = Number(process.env.VPN_BYPASS_PARENT_PID);
      const timer = setInterval(() => {
        if (Number.isInteger(parentPid) && parentPid > 1 && !pidAlive(parentPid)) {
          clearInterval(timer);
          shutdown();
        }
      }, 2000);
      if (typeof timer.unref === 'function') timer.unref();

      const handle = {
        server,
        sockPath,
        pidFile,
        stop() {
          clearInterval(timer);
          shutdown();
        },
      };
      resolve(handle);
    });
  });
}

async function runElevateHelper(service, opts = {}) {
  if (daemonizeHelper()) return { daemonized: true };
  if (opts.returnHandle) return listenHelper(service, opts);
  await new Promise((resolve, reject) => {
    listenHelper(service, { ...opts, onShutdown: resolve }).catch(reject);
  });
  process.exit(0);
}

module.exports = {
  handleJob,
  listenHelper,
  runElevateHelper,
  daemonizeHelper,
  helperChildEnv,
};
