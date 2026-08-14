'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const darwin = require('../src/platform/darwin');
const linux = require('../src/platform/linux');
const win32 = require('../src/platform/win32');
const { parseDarwinNetstat, parseDarwinNetstat6, parseIfconfig, parseLinuxIpRoute, parseLinuxIpRoute6, parseLinuxIpAddr, inferTopology, inferIpv6 } = require('../src/platform/common');
const { recordingExec, tmpHome, sampleDetect } = require('./helpers');
const { getPaths } = require('../src/core/config');

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

  it('parses darwin inet6 netstat and infers LAN gw6', () => {
    const v4 = parseDarwinNetstat(fs.readFileSync(path.join(FIX, 'darwin/netstat-rn.txt'), 'utf8'));
    const v6 = parseDarwinNetstat6(fs.readFileSync(path.join(FIX, 'darwin/netstat-rn-inet6.txt'), 'utf8'));
    const ifaces = parseIfconfig(fs.readFileSync(path.join(FIX, 'darwin/ifconfig.txt'), 'utf8'));
    assert.ok(v6.some((r) => r.dest === '::' && r.prefix === 1 && r.family === 'inet6'));
    assert.ok(v6.some((r) => r.dest === '8000::' && r.prefix === 1));
    const topo = inferIpv6(v6, inferTopology(v4, ifaces, 'darwin'));
    assert.equal(topo.lan.gw6, 'fe80::1%en0');
  });

  it('parses linux inet6 routes and infers LAN gw6', () => {
    const v4 = parseLinuxIpRoute(fs.readFileSync(path.join(FIX, 'linux/ip-route.txt'), 'utf8'));
    const v6 = parseLinuxIpRoute6(fs.readFileSync(path.join(FIX, 'linux/ip-route-inet6.txt'), 'utf8'));
    const ifaces = parseLinuxIpAddr(fs.readFileSync(path.join(FIX, 'linux/ip-addr.txt'), 'utf8'));
    const topo = inferIpv6(v6, inferTopology(v4, ifaces, 'linux'));
    assert.equal(topo.lan.gw6, 'fe80::1');
    assert.ok(v6.some((r) => r.dest === '::' && r.prefix === 1));
  });

  it('darwin addCidr changes existing /1 and never deletes default 0/0', async () => {
    const exec = recordingExec(async (_file, args) => {
      if (args.includes('add')) {
        const err = new Error('File exists');
        err.stderr = 'File exists';
        throw err;
      }
      return { stdout: '', stderr: '' };
    });
    const platform = darwin.create(exec, { isAdmin: async () => true, getuid: () => 0 });
    await platform.addCidr({ dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1', kind: 'split', family: 'inet' });
    const joined = exec.calls.map((c) => c.args.join(' '));
    assert.ok(joined.some((j) => j.includes('add') && j.includes('0.0.0.0/1')));
    assert.ok(joined.some((j) => j.includes('change') && j.includes('0.0.0.0/1')));
    assert.equal(joined.some((j) => /\bdelete\b/.test(j)), false);
    await platform.addCidr({ dest: '::', prefix: 1, gw: 'fe80::1%en0', kind: 'split', family: 'inet6' });
    assert.ok(exec.calls.some((c) => c.args.includes('-inet6') && c.args.includes('change')));
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

  it('darwin applyDns points system DNS at 127.0.0.1 and restore never leaves it', async () => {
    const scutil = fs.readFileSync(path.join(FIX, 'darwin/scutil-dns.txt'), 'utf8');
    const order = fs.readFileSync(path.join(FIX, 'darwin/networksetup-order.txt'), 'utf8');
    const exec = recordingExec(async (file, args) => {
      const base = path.basename(file);
      const joined = args.join(' ');
      if (base === 'scutil') return { stdout: scutil, stderr: '' };
      if (base === 'networksetup') {
        if (joined.includes('listnetworkserviceorder')) return { stdout: order, stderr: '' };
        if (joined.includes('getdnsservers')) return { stdout: '10.230.8.8\n', stderr: '' };
        if (joined.includes('getsearchdomains')) return { stdout: 'corp.example\n', stderr: '' };
        return { stdout: '', stderr: '' };
      }
      if (base === 'ps') return { stdout: 'node src/core/dnsForwarder.js dns-forwarder.json', stderr: '' };
      return { stdout: '', stderr: '' };
    });
    const home = tmpHome();
    const platform = darwin.create(exec, {
      isAdmin: async () => true,
      startForwarder: async () => 4242,
      stopForwarder: async () => {},
    });
    const owned = await platform.applyDns({ detect: sampleDetect(), paths: getPaths(home) });
    assert.equal(owned.mode, 'split');
    assert.equal(owned.listen, '127.0.0.1');
    assert.ok(exec.calls.some((c) => c.args.includes('-setdnsservers') && c.args.includes('127.0.0.1')));
    await platform.restoreDns(owned);
    const setCalls = exec.calls.filter((c) => c.args.includes('-setdnsservers'));
    const last = setCalls[setCalls.length - 1];
    assert.equal(last.args.includes('127.0.0.1'), false);
    assert.ok(last.args.includes('10.230.8.8') || last.args.includes('Empty'));
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('linux applyDns no-ops without resolvectl and does not rewrite resolv.conf', async () => {
    const exec = recordingExec(async () => {
      const err = new Error('not found');
      err.code = 'ENOENT';
      throw err;
    });
    const platform = linux.create(exec, { isAdmin: async () => true });
    const result = await platform.applyDns({ detect: sampleDetect() });
    assert.equal(result.mode, 'skipped');
    assert.equal(exec.calls.some((c) => c.joined.includes('resolv.conf')), false);
  });

  it('win32 applyDns does not call netsh dns', async () => {
    const exec = recordingExec();
    const platform = win32.create(exec, { isAdmin: async () => true });
    const result = await platform.applyDns({ detect: sampleDetect() });
    assert.equal(result.mode, 'unsupported');
    assert.equal(exec.calls.length, 0);
    assert.equal(exec.calls.some((c) => /netsh|set dns/i.test(c.joined)), false);
  });
});
