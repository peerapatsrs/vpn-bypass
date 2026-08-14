'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { probeHost, createLanResolve4 } = require('../src/core/probe');
const { validateTarget } = require('../src/core/net');

describe('try / probe validation', () => {
  it('rejects URLs', async () => {
    await assert.rejects(() => probeHost('https://example.com'), (err) => err.code === 'EINVAL');
    await assert.rejects(() => probeHost('http://example.com/path'), (err) => err.code === 'EINVAL');
    await assert.rejects(() => probeHost('example.com:443'), (err) => err.code === 'EINVAL');
    await assert.rejects(() => probeHost('example.com/foo'), (err) => err.code === 'EINVAL');
  });

  it('rejects 127.0.0.1, link-local, metadata, and unsafe args', async () => {
    await assert.rejects(() => probeHost('127.0.0.1'), (err) => err.code === 'EBLOCKED');
    await assert.rejects(() => probeHost('169.254.169.254'), (err) => err.code === 'EBLOCKED');
    await assert.rejects(() => probeHost('localhost'), (err) => err.code === 'EBLOCKED');
    assert.throws(() => validateTarget('-n'), (err) => err.code === 'EINVAL');
    assert.throws(() => validateTarget('host;rm'), (err) => err.code === 'EINVAL');
    assert.throws(() => validateTarget('host|x'), (err) => err.code === 'EINVAL');
    assert.throws(() => validateTarget('host$(x)'), (err) => err.code === 'EINVAL');
  });

  it('does not add routes', async () => {
    let probed = false;
    let bound;
    const result = await probeHost('example.com', {
      resolveDns: async () => ['93.184.216.34'],
      localAddress: '192.168.1.42',
      probeTls: async (_host, opts) => {
        probed = true;
        bound = opts && opts.localAddress;
        return { ok: true };
      },
    });
    assert.equal(result.ok, true);
    assert.equal(probed, true);
    assert.equal(bound, '192.168.1.42');
    assert.deepEqual(result.ips, ['93.184.216.34']);
  });

  it('LAN resolver is used when it returns A records, else falls back', async () => {
    const lan = createLanResolve4('192.168.1.1', async () => ['8.8.8.8'], () => ({
      setServers() {},
      resolve4: async () => ['1.2.3.4'],
    }));
    assert.deepEqual(await lan('example.com'), ['1.2.3.4']);
    const fallback = createLanResolve4('192.168.1.1', async () => ['8.8.8.8'], () => ({
      setServers() {},
      resolve4: async () => { throw new Error('timeout'); },
    }));
    assert.deepEqual(await fallback('example.com'), ['8.8.8.8']);
    const skipped = createLanResolve4('127.0.0.1', async () => ['9.9.9.9']);
    assert.deepEqual(await skipped('example.com'), ['9.9.9.9']);
  });
});
