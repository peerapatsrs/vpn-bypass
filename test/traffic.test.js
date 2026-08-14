'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { parseLsofFields, parseSs, parseNetstatTcp } = require('../src/platform/connections');
const { classifyConnection } = require('../src/core/match');
const { isWebConnection, classifyLive } = require('../src/core/traffic');
const { Service } = require('../src/core/service');
const { tmpHome, mockPlatform, sampleDetect } = require('./helpers');

const DETECT = sampleDetect({
  routes: [
    { dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1', iface: 'en0', inactive: false },
    { dest: '128.0.0.0', prefix: 1, gw: '192.168.1.1', iface: 'en0', inactive: false },
    { dest: '0.0.0.0', prefix: 0, gw: '10.243.1.1', iface: 'utun6', inactive: false },
    { dest: '10.10.0.0', prefix: 16, gw: '10.243.1.1', iface: 'utun6', inactive: false },
  ],
});

describe('live website path', () => {
  it('parses lsof field output', () => {
    const conns = parseLsofFields(`
p8812
cGoogle
n192.168.1.42:51234->57.144.160.1:443
n10.243.1.92:51235->10.10.1.8:443
nTCP 192.168.1.42:51236->1.1.1.1:443 (ESTABLISHED)
`);
    assert.equal(conns.length, 3);
    assert.equal(conns[0].process, 'Google');
    assert.equal(conns[0].ip, '57.144.160.1');
    assert.equal(conns[0].localIp, '192.168.1.42');
    assert.equal(conns[1].ip, '10.10.1.8');
    assert.equal(conns[2].port, 443);
  });

  it('parses ss and windows netstat', () => {
    const ss = parseSs('0  0  192.168.1.42:51234  57.144.160.1:443\n');
    assert.equal(ss[0].ip, '57.144.160.1');
    const win = parseNetstatTcp('  TCP    192.168.1.42:51234    57.144.160.1:443    ESTABLISHED\n');
    assert.equal(win[0].port, 443);
  });

  it('uses the socket local address: LAN vs VPN', () => {
    const fb = { ip: '57.144.160.1', port: 443, localIp: '192.168.1.42', localPort: 51234, process: 'Google' };
    const corp = { ip: '10.10.1.8', port: 443, localIp: '10.243.1.92', localPort: 51235, process: 'Safari' };
    assert.equal(classifyConnection(DETECT, fb).via, 'lan');
    assert.equal(classifyConnection(DETECT, corp).via, 'vpn');
    assert.equal(isWebConnection(DETECT, fb), true);
    assert.equal(isWebConnection(DETECT, { ...fb, ip: '192.168.1.1' }), false);
    assert.equal(isWebConnection(DETECT, { ...fb, ip: '127.0.0.1' }), false);
  });

  it('labels facebook via LAN and intranet via VPN in getTraffic', async () => {
    const home = tmpHome();
    const platform = mockPlatform({
      detect: DETECT,
      connections: [
        { ip: '57.144.160.1', port: 443, localIp: '192.168.1.42', localPort: 51234, process: 'Google' },
        { ip: '10.10.1.8', port: 443, localIp: '10.243.1.92', localPort: 51235, process: 'Safari' },
      ],
    });
    const svc = new Service({
      home,
      platform,
      reverseDns: async () => null,
      resolveDns: async () => ['57.144.160.1'],
    });
    await svc.lookupHost('www.facebook.com');
    const snap = await svc.getTraffic();
    const fb = snap.live.find((r) => r.ip === '57.144.160.1');
    const corp = snap.live.find((r) => r.ip === '10.10.1.8');
    assert.equal(fb.via, 'lan');
    assert.equal(fb.host, 'www.facebook.com');
    assert.equal(corp.via, 'vpn');
    assert.ok(snap.recent.some((r) => r.ip === '57.144.160.1' && r.via === 'lan'));
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('merges duplicate sockets to the same IP', () => {
    const live = classifyLive(DETECT, [
      { ip: '57.144.160.1', port: 443, localIp: '192.168.1.42', localPort: 1, process: 'Google' },
      { ip: '57.144.160.1', port: 443, localIp: '192.168.1.42', localPort: 2, process: 'Google' },
    ]);
    assert.equal(live.length, 1);
    assert.deepEqual(live[0].ports, [443]);
  });
});
