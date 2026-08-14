'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const { createServer, assertLoopbackHost, startServer } = require('../src/server');
const { Service } = require('../src/core/service');
const { tmpHome, mockPlatform } = require('./helpers');

describe('server bind + API', () => {
  it('rejects non-loopback bind', () => {
    assert.throws(() => assertLoopbackHost('0.0.0.0'), (err) => err.code === 'ENOTLOOPBACK');
    assert.throws(() => assertLoopbackHost('::'), (err) => err.code === 'ENOTLOOPBACK');
    assert.throws(() => assertLoopbackHost('192.168.1.42'), (err) => err.code === 'ENOTLOOPBACK');
    const home = tmpHome();
    const service = new Service({ home, platform: mockPlatform() });
    assert.throws(() => createServer({ host: '0.0.0.0', service }), (err) => err.code === 'ENOTLOOPBACK');
    assert.equal(process.env.HOST || '', process.env.HOST || '');
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('GET /api/status is lightweight and returns locale', async () => {
    const home = tmpHome();
    const service = new Service({ home, platform: mockPlatform() });
    service.putConfig({ locale: 'en' });
    const { server, token, listen } = createServer({ host: '127.0.0.1', service });
    const info = await listen(0);
    try {
      const res = await jsonGet(info.port, '/api/status', token);
      assert.equal(res.ok, true);
      assert.equal(res.data.locale, 'en');
      assert.equal(typeof res.data.hasAdmin, 'boolean');
      assert.equal(typeof res.data.canElevate, 'boolean');
      assert.ok(Array.isArray(res.data.warnings));
      assert.ok(Array.isArray(res.data.ifaces));
      assert.equal(typeof res.data.repairActive, 'boolean');
      assert.equal(typeof res.data.hijacked, 'boolean');
      assert.ok(res.data.dns);
      assert.equal(typeof res.data.dns.mode, 'string');
      assert.equal(Object.prototype.hasOwnProperty.call(res.data, 'lanIp'), false);
    } finally {
      await close(server);
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('PUT /api/config accepts locale', async () => {
    const home = tmpHome();
    const service = new Service({ home, platform: mockPlatform() });
    const { server, token, listen } = createServer({ host: '127.0.0.1', service });
    const info = await listen(0);
    try {
      const put = await jsonReq(info.port, 'PUT', '/api/config', token, { locale: 'en' });
      assert.equal(put.ok, true);
      assert.equal(put.data.locale, 'en');
      const cfg = await jsonGet(info.port, '/api/config', token);
      assert.equal(cfg.data.locale, 'en');
    } finally {
      await close(server);
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});

function jsonGet(port, pathname, token) {
  return jsonReq(port, 'GET', pathname, token, null);
}

function jsonReq(port, method, pathname, token, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? Buffer.from(JSON.stringify(body)) : null;
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: pathname,
      method,
      headers: {
        'X-Vpn-Bypass-Token': token,
        Host: `127.0.0.1:${port}`,
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}),
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
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
