'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { EventEmitter } = require('events');
const {
  posixQuote,
  appleScriptQuote,
  buildDarwinShellCommand,
  buildDarwinElevateScript,
  buildWin32ElevateCommand,
  encodeUtf16LeBase64,
  assertJob,
  jobToArgv,
  createElevate,
  OSASCRIPT,
  withElevate,
} = require('../src/core/elevate');
const { listenHelper, handleJob } = require('../src/core/helper');
const { Service } = require('../src/core/service');
const { createServer } = require('../src/server');
const { tmpHome, mockPlatform } = require('./helpers');
const http = require('http');

function fakeChild(code = 0) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = () => {};
  setImmediate(() => child.emit('close', code));
  return child;
}

function jsonReq(port, method, pathname, token, body, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? Buffer.from(JSON.stringify(body)) : null;
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: pathname,
      method,
      headers: {
        Host: `127.0.0.1:${port}`,
        ...(token ? { 'X-Vpn-Bypass-Token': token } : {}),
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}),
        ...extraHeaders,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try {
          resolve({ status: res.status, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function close(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

describe('elevate quoting + jobs', () => {
  it('posix and AppleScript quotes do not break out', () => {
    assert.equal(posixQuote(`it'is`), `'it'\\''is'`);
    assert.match(appleScriptQuote('say "hi"\\x'), /\\"/);
    const env = {
      HOME: `/Users/o'reilly`,
      SUDO_USER: `o'reilly`,
      VPN_BYPASS_HOME: '/tmp/vpn-bypass-home',
      PATH: '/usr/sbin:/sbin:/usr/bin:/bin',
    };
    const shell = buildDarwinShellCommand({
      node: '/usr/local/bin/node',
      script: '/opt/vpn-bypass/bin/vpn-bypass.js',
      args: ['elevate-helper'],
      env,
    });
    assert.match(shell, /elevate-helper/);
    assert.equal(shell.includes('csrf'), false);
    assert.equal(shell.includes('token'), false);
    assert.equal(shell.includes('X-Vpn'), false);
    const script = buildDarwinElevateScript(shell);
    assert.match(script, /with administrator privileges/);
    assert.equal(script.includes('evil.com'), false);
  });

  it('jobs whitelist hosts via argv, never unsanitized shell fragments', () => {
    assert.throws(() => assertJob({ cmd: 'allow', host: "x.com'; rm -rf /" }), (err) => err.code === 'EINVAL');
    assert.throws(() => assertJob({ cmd: 'on;reboot' }), (err) => err.code === 'EINVAL');
    assert.throws(() => assertJob({ cmd: 'on', mode: 'drop-tables' }), (err) => err.code === 'EINVAL');
    const argv = jobToArgv({ cmd: 'allow', host: 'intranet.example.com' });
    assert.deepEqual(argv, ['allow', 'intranet.example.com']);
    assert.deepEqual(jobToArgv({ cmd: 'on', mode: 'inverse' }), ['on', '--mode', 'inverse']);
    assert.deepEqual(jobToArgv({ cmd: 'off' }), ['off']);
  });

  it('default spawn refuses GUI elevate during tests', async () => {
    const home = tmpHome();
    const elevate = createElevate({
      paths: { dir: home, config: `${home}/c.json`, state: `${home}/s.json`, lock: `${home}/l` },
      platform: 'darwin',
      supported: true,
    });
    await assert.rejects(() => elevate.ensureHelper(), (err) => err.code === 'EPRIV');
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('win32 canElevate and oneShot uses RunAs PassThru with helper env', async () => {
    const home = tmpHome();
    const calls = [];
    const elevate = createElevate({
      paths: { dir: home, config: `${home}/c.json`, state: `${home}/s.json`, lock: `${home}/l` },
      platform: 'win32',
      node: 'C:\\Program Files\\nodejs\\node.exe',
      script: 'C:\\vpn-bypass\\bin\\vpn-bypass.js',
      spawnImpl: (file, args, opts) => {
        calls.push({ file, args: args.slice(), env: opts && opts.env });
        return fakeChild(0);
      },
    });
    assert.equal(elevate.supported(), true);
    await elevate.run({ cmd: 'on', mode: 'inverse' });
    assert.equal(calls.length, 1);
    assert.match(String(calls[0].file), /powershell\.exe$/i);
    const cmd = calls[0].args.join(' ');
    assert.match(cmd, /RunAs/);
    assert.match(cmd, /PassThru/);
    assert.match(cmd, /ExitCode/);
    assert.match(cmd, /EncodedCommand/);
    const encoded = /EncodedCommand','([A-Za-z0-9+/=]+)'/.exec(cmd)
      || /EncodedCommand','([^']+)'/.exec(cmd)
      || /EncodedCommand','([^']+)/.exec(cmd);
    assert.ok(encoded, cmd);
    const inner = Buffer.from(encoded[1], 'base64').toString('utf16le');
    assert.match(inner, /vpn-bypass\.js/);
    assert.match(inner, /'on'/);
    assert.match(inner, /VPN_BYPASS_HOME/);
    assert.ok(calls[0].env && calls[0].env.PATH);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('buildWin32ElevateCommand encodes node argv without CSRF', () => {
    const built = buildWin32ElevateCommand({
      node: 'C:\\Program Files\\nodejs\\node.exe',
      script: 'D:\\app\\bin\\vpn-bypass.js',
      args: ['on', '--mode', 'inverse'],
      env: { VPN_BYPASS_HOME: 'C:\\Users\\a\\AppData\\Roaming\\vpn-bypass', PATH: 'C:\\Windows\\System32' },
      powershell: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    });
    assert.match(built.file, /powershell\.exe$/i);
    assert.equal(built.inner.includes('csrf'), false);
    assert.match(built.inner, /VPN_BYPASS_HOME/);
    assert.match(built.args.join(' '), /EncodedCommand/);
    const roundtrip = Buffer.from(encodeUtf16LeBase64(built.inner), 'base64').toString('utf16le');
    assert.equal(roundtrip, built.inner);
  });
});

describe('elevate helper rpc (in-process, no osascript)', () => {
  it('unprivileged on elevates through helper and applies with mock platform', async () => {
    const home = tmpHome();
    const helperPlat = mockPlatform({ admin: true });
    const userPlat = mockPlatform({ admin: false });
    const helperSvc = new Service({ home, platform: helperPlat });
    const userSvc = new Service({ home, platform: userPlat });
    const sockPath = `${home}/elevate.sock`;
    const pidFile = `${home}/elevate.pid`;
    const handle = await listenHelper(helperSvc, { sockPath, pidFile });
    const elevate = createElevate({
      paths: userSvc.paths,
      platform: 'darwin',
      supported: true,
      sockPath,
      pidFile,
    });
    userSvc.elevate = elevate;
    try {
      const data = await withElevate(userSvc, { cmd: 'on', mode: 'inverse' }, () => userSvc.on({ mode: 'inverse' }));
      assert.equal(data.dryRun, false);
      assert.ok(helperPlat.adds.length > 0);
      assert.equal(userPlat.adds.length, 0);
      const st = await userSvc.getStatus();
      assert.equal(st.applied, true);
      assert.equal(st.canElevate, true);
    } finally {
      handle.stop();
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('osascript spawn is argv-array, includes elevate-helper, not CSRF or hostnames', async () => {
    const home = tmpHome();
    const helperPlat = mockPlatform({ admin: true });
    const helperSvc = new Service({ home, platform: helperPlat });
    const sockPath = `${home}/elevate.sock`;
    const pidFile = `${home}/elevate.pid`;
    const calls = [];
    let handle;
    process.env.CSRF_FAKE = 'super-secret-token-value';
    const elevate = createElevate({
      paths: helperSvc.paths,
      platform: 'darwin',
      supported: true,
      sockPath,
      pidFile,
      spawnImpl: (file, args) => {
        calls.push({ file, args: args.slice() });
        listenHelper(helperSvc, { sockPath, pidFile }).then((h) => { handle = h; });
        return fakeChild(0);
      },
    });
    try {
      await elevate.ensureHelper();
      assert.equal(calls.length, 1);
      assert.equal(calls[0].file, OSASCRIPT);
      assert.equal(calls[0].args[0], '-e');
      const script = calls[0].args[1];
      assert.match(script, /elevate-helper/);
      assert.equal(script.includes('super-secret-token-value'), false);
      assert.equal(script.includes('intranet.evil.com'), false);
      assert.match(script, /VPN_BYPASS_HOME/);
      await elevate.run({ cmd: 'on', mode: 'inverse' });
      assert.ok(helperPlat.adds.length > 0);
    } finally {
      delete process.env.CSRF_FAKE;
      if (handle) handle.stop();
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('handleJob ping and repair skip when not applied', async () => {
    const home = tmpHome();
    const svc = new Service({ home, platform: mockPlatform({ admin: true }) });
    const ping = await handleJob(svc, { cmd: 'ping' });
    assert.equal(ping.ok, true);
    const repaired = await handleJob(svc, { cmd: 'repair' });
    assert.equal(repaired.skipped, 'off');
    fs.rmSync(home, { recursive: true, force: true });
  });
});

describe('server elevate wiring', () => {
  it('GET /api/status does not elevate; dry-run does not elevate; on without token does not elevate', async () => {
    const home = tmpHome();
    const service = new Service({ home, platform: mockPlatform({ admin: false }) });
    let elevateCalls = 0;
    service.elevate = {
      supported: () => true,
      isHelperRunning: () => false,
      async run() {
        elevateCalls += 1;
        throw new Error('should not elevate');
      },
    };
    const { server, token, listen } = createServer({ host: '127.0.0.1', service });
    const info = await listen(0);
    try {
      const st = await jsonReq(info.port, 'GET', '/api/status', token, null);
      assert.equal(st.json.ok, true);
      assert.equal(st.json.data.hasAdmin, false);
      assert.equal(st.json.data.canElevate, true);
      const dry = await jsonReq(info.port, 'POST', '/api/on', token, { mode: 'inverse', dryRun: true });
      assert.equal(dry.json.ok, true);
      assert.equal(dry.json.data.dryRun, true);
      const noTok = await jsonReq(info.port, 'POST', '/api/on', '', { mode: 'inverse' });
      assert.equal(noTok.json.ok, false);
      assert.equal(noTok.json.error.code, 'EAUTH');
      assert.equal(elevateCalls, 0);
    } finally {
      await close(server);
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('POST /api/on without admin uses elevate and does not mutate the unprivileged platform', async () => {
    const home = tmpHome();
    const helperPlat = mockPlatform({ admin: true });
    const userPlat = mockPlatform({ admin: false });
    const helperSvc = new Service({ home, platform: helperPlat });
    const userSvc = new Service({ home, platform: userPlat });
    const sockPath = `${home}/elevate.sock`;
    const pidFile = `${home}/elevate.pid`;
    const handle = await listenHelper(helperSvc, { sockPath, pidFile });
    userSvc.elevate = createElevate({
      paths: userSvc.paths,
      platform: 'darwin',
      supported: true,
      sockPath,
      pidFile,
    });
    const { server, token, listen } = createServer({ host: '127.0.0.1', service: userSvc });
    const info = await listen(0);
    try {
      const res = await jsonReq(info.port, 'POST', '/api/on', token, { mode: 'inverse' });
      assert.equal(res.json.ok, true);
      assert.ok(helperPlat.adds.length > 0);
      assert.equal(userPlat.adds.length, 0);
      const st = await jsonReq(info.port, 'GET', '/api/status', token, null);
      assert.equal(st.json.data.applied, true);
    } finally {
      handle.stop();
      await close(server);
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('POST /api/on without admin and without elevate stays EPRIV', async () => {
    const home = tmpHome();
    const service = new Service({ home, platform: mockPlatform({ admin: false }) });
    const { server, token, listen } = createServer({ host: '127.0.0.1', service });
    const info = await listen(0);
    try {
      const res = await jsonReq(info.port, 'POST', '/api/on', token, { mode: 'inverse' });
      assert.equal(res.json.ok, false);
      assert.equal(res.json.error.code, 'EPRIV');
    } finally {
      await close(server);
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
