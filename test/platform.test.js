'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const darwin = require('../src/platform/darwin');
const linux = require('../src/platform/linux');
const win32 = require('../src/platform/win32');
const { parseDarwinNetstat, parseIfconfig, parseLinuxIpRoute, parseLinuxIpAddr, inferTopology } = require('../src/platform/common');

const FIX = path.join(__dirname, 'fixtures');

describe('parse fixtures', () => {
  it('parses darwin netstat + ifconfig and finds LAN gw despite inactive default', () => {
    const routes = parseDarwinNetstat(fs.readFileSync(path.join(FIX, 'darwin/netstat-rn.txt'), 'utf8'));
    const ifaces = parseIfconfig(fs.readFileSync(path.join(FIX, 'darwin/ifconfig.txt'), 'utf8'));
    const detect = inferTopology(routes, ifaces, 'darwin');
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.vpn.iface, 'utun6');
    assert.equal(detect.vpn.addr, '10.243.1.92');
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.equal(detect.lan.iface, 'en0');
    assert.equal(detect.lan.network, '192.168.1.0');
    assert.ok(detect.vpn.cidrs.some((c) => c.dest === '10.10.0.0' && c.prefix === 16));
    assert.equal(darwin.parseRoutes === parseDarwinNetstat || typeof darwin.parseRoutes === 'function', true);
  });

  it('parses linux ip route/addr', () => {
    const routes = parseLinuxIpRoute(fs.readFileSync(path.join(FIX, 'linux/ip-route.txt'), 'utf8'));
    const ifaces = parseLinuxIpAddr(fs.readFileSync(path.join(FIX, 'linux/ip-addr.txt'), 'utf8'));
    const detect = inferTopology(routes, ifaces, 'linux');
    assert.equal(detect.vpn.iface, 'tun0');
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.equal(detect.lan.addr, '192.168.1.42');
    assert.equal(typeof linux.parseRoutes, 'function');
  });

  it('parses windows route print', () => {
    const text = fs.readFileSync(path.join(FIX, 'win32/route-print.txt'), 'utf8');
    const routes = win32.parseRoutes(text);
    assert.ok(routes.some((r) => r.dest === '0.0.0.0' && r.gw === '192.168.1.1'));
    assert.ok(routes.some((r) => r.dest === '0.0.0.0' && r.gw === '10.243.1.1'));
    const detect = win32.detectFromPrint(text);
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.equal(detect.vpn.up, true);
  });
});
