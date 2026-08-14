'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { parseDarwinNetstat, parseIfconfig, inferTopology } = require('../src/platform/common');
const { bestRoute, classifyPath } = require('../src/core/match');
const { Service } = require('../src/core/service');
const { tmpHome, mockPlatform } = require('./helpers');

const FIX = path.join(__dirname, 'fixtures/darwin');

describe('route path log', () => {
  it('longest prefix: /1 LAN wins over VPN default', () => {
    const routes = parseDarwinNetstat(fs.readFileSync(path.join(FIX, 'netstat-rn.txt'), 'utf8'));
    const ifaces = parseIfconfig(fs.readFileSync(path.join(FIX, 'ifconfig.txt'), 'utf8'));
    const detect = inferTopology(routes, ifaces, 'darwin');
    detect.routes.push({
      dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1', iface: 'en0', inactive: false,
    });
    const hit = bestRoute(detect.routes, '57.144.160.1');
    assert.equal(hit.prefix, 1);
    assert.equal(hit.iface, 'en0');
    assert.equal(classifyPath(detect, hit).via, 'lan');
  });

  it('RFC1918 /8 via VPN beats /1 LAN for corp IPs', () => {
    const routes = [
      { dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1', iface: 'en0', inactive: false },
      { dest: '10.0.0.0', prefix: 8, gw: null, iface: 'utun6', kind: 'vpn-keep', inactive: false },
    ];
    const detect = {
      lan: { iface: 'en0', gw: '192.168.1.1' },
      vpn: { iface: 'utun6', gw: '10.243.1.1', up: true },
      routes,
    };
    const hit = bestRoute(routes, '10.10.1.8');
    assert.equal(hit.prefix, 8);
    assert.equal(classifyPath(detect, hit).via, 'vpn');
    const web = bestRoute(routes, '57.144.160.1');
    assert.equal(web.prefix, 1);
    assert.equal(classifyPath(detect, web).via, 'lan');
  });

  it('without /1, facebook IP uses VPN default', () => {
    const routes = parseDarwinNetstat(fs.readFileSync(path.join(FIX, 'netstat-rn.txt'), 'utf8'));
    const ifaces = parseIfconfig(fs.readFileSync(path.join(FIX, 'ifconfig.txt'), 'utf8'));
    const detect = inferTopology(routes, ifaces, 'darwin');
    const hit = bestRoute(detect.routes, '57.144.160.1');
    assert.equal(hit.iface, 'utun6');
    assert.equal(classifyPath(detect, hit).via, 'vpn');
  });

  it('lookupHost records lan vs vpn per IP', async () => {
    const routes = parseDarwinNetstat(fs.readFileSync(path.join(FIX, 'netstat-rn.txt'), 'utf8'));
    const ifaces = parseIfconfig(fs.readFileSync(path.join(FIX, 'ifconfig.txt'), 'utf8'));
    const detect = inferTopology(routes, ifaces, 'darwin');
    detect.routes.push({
      dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1', iface: 'en0', inactive: false,
    });
    const home = tmpHome();
    const platform = mockPlatform({ detect });
    platform.listRoutes = async () => detect.routes;
    const svc = new Service({
      home,
      platform,
      resolveDns: async () => ['57.144.160.1'],
    });
    const result = await svc.lookupHost('www.facebook.com');
    assert.equal(result.hits[0].via, 'lan');
    assert.equal(result.hits[0].iface, 'en0');
    fs.rmSync(home, { recursive: true, force: true });
  });
});
