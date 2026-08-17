'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const {
  getPaths,
  loadConfig,
  saveConfig,
  parseInvokerIds,
  ownAsInvoker,
  CHOWN_HINT,
} = require('../src/core/config');
const { AppError } = require('../src/core/errors');
const { t } = require('../src/i18n');
const { main } = require('../src/run');
const { tmpHome } = require('./helpers');

function eacces(file) {
  const err = new Error(`EACCES: permission denied, open '${file}'`);
  err.code = 'EACCES';
  return err;
}

describe('config ownership + EACCES', () => {
  it('parseInvokerIds prefers VPN_BYPASS_UID then SUDO_UID', () => {
    const prev = {
      VPN_BYPASS_UID: process.env.VPN_BYPASS_UID,
      VPN_BYPASS_GID: process.env.VPN_BYPASS_GID,
      SUDO_UID: process.env.SUDO_UID,
      SUDO_GID: process.env.SUDO_GID,
      SUDO_USER: process.env.SUDO_USER,
    };
    try {
      process.env.VPN_BYPASS_UID = '501';
      process.env.VPN_BYPASS_GID = '20';
      process.env.SUDO_UID = '999';
      process.env.SUDO_GID = '999';
      assert.deepEqual(parseInvokerIds(), { uid: 501, gid: 20 });

      delete process.env.VPN_BYPASS_UID;
      delete process.env.VPN_BYPASS_GID;
      process.env.SUDO_UID = '501';
      process.env.SUDO_GID = '20';
      assert.deepEqual(parseInvokerIds(), { uid: 501, gid: 20 });

      delete process.env.SUDO_UID;
      delete process.env.SUDO_GID;
      delete process.env.SUDO_USER;
      assert.equal(parseInvokerIds(), null);
    } finally {
      for (const [k, v] of Object.entries(prev)) {
        if (v == null) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  it('ownAsInvoker chowns as the invoking user when running as root', () => {
    const origGetuid = process.getuid;
    const origChown = fs.chownSync;
    const prevUid = process.env.SUDO_UID;
    const prevGid = process.env.SUDO_GID;
    const prevVpnUid = process.env.VPN_BYPASS_UID;
    const prevVpnGid = process.env.VPN_BYPASS_GID;
    const calls = [];
    process.getuid = () => 0;
    fs.chownSync = (file, uid, gid) => { calls.push({ file, uid, gid }); };
    delete process.env.VPN_BYPASS_UID;
    delete process.env.VPN_BYPASS_GID;
    process.env.SUDO_UID = '501';
    process.env.SUDO_GID = '20';
    try {
      ownAsInvoker('/tmp/vpn-bypass-owned.json');
      assert.deepEqual(calls, [{ file: '/tmp/vpn-bypass-owned.json', uid: 501, gid: 20 }]);
    } finally {
      process.getuid = origGetuid;
      fs.chownSync = origChown;
      if (prevUid == null) delete process.env.SUDO_UID;
      else process.env.SUDO_UID = prevUid;
      if (prevGid == null) delete process.env.SUDO_GID;
      else process.env.SUDO_GID = prevGid;
      if (prevVpnUid == null) delete process.env.VPN_BYPASS_UID;
      else process.env.VPN_BYPASS_UID = prevVpnUid;
      if (prevVpnGid == null) delete process.env.VPN_BYPASS_GID;
      else process.env.VPN_BYPASS_GID = prevVpnGid;
    }
  });

  it('mocked EACCES on config open becomes AppError EACCES with chown hint', () => {
    const orig = fs.readFileSync;
    fs.readFileSync = (file, enc) => {
      throw eacces(file);
    };
    try {
      assert.throws(
        () => loadConfig(getPaths('/tmp/vpn-bypass-eacces')),
        (err) => {
          assert.equal(err instanceof AppError, true);
          assert.equal(err.name, 'AppError');
          assert.equal(err.code, 'EACCES');
          assert.match(err.message, /chown/);
          assert.match(err.message, /whoami/);
          assert.match(err.message, /vpn-bypass/);
          assert.equal(err.message.includes('permission denied, open'), false);
          return true;
        },
      );
    } finally {
      fs.readFileSync = orig;
    }
  });

  it('mocked EACCES on config write becomes AppError EACCES', () => {
    const home = tmpHome();
    const orig = fs.writeFileSync;
    fs.writeFileSync = (file, data, opts) => {
      throw eacces(file);
    };
    try {
      assert.throws(
        () => saveConfig(getPaths(home), { locale: 'th' }),
        (err) => {
          assert.equal(err instanceof AppError, true);
          assert.equal(err.code, 'EACCES');
          assert.match(err.message, /chown/);
          return true;
        },
      );
    } finally {
      fs.writeFileSync = orig;
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('CLI prints Thai/EN i18n for EACCES, not a raw Node stack', async () => {
    const home = tmpHome();
    const paths = getPaths(home);
    saveConfig(paths, { locale: 'en' });
    const origRead = fs.readFileSync;
    fs.readFileSync = (file, enc) => {
      if (typeof file === 'string' && file.includes('config.json')) {
        throw eacces(file);
      }
      return origRead(file, enc);
    };
    const chunks = [];
    const origErr = process.stderr.write;
    process.stderr.write = (c) => {
      chunks.push(String(c));
      return true;
    };
    try {
      const code = await main(['--lang', 'en', 'status'], { home });
      assert.equal(code, 1);
      const out = chunks.join('');
      assert.match(out, /chown -R "\$\(whoami\)" ~\/\.config\/vpn-bypass/);
      assert.equal(out.includes('permission denied, open'), false);
      assert.equal(out.includes('at Object.readFileSync'), false);
      assert.equal(t('th', 'error.EACCES').includes(CHOWN_HINT), true);
    } finally {
      fs.readFileSync = origRead;
      process.stderr.write = origErr;
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
