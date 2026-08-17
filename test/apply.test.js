'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { Service } = require('../src/core/service');
const { on, off, repairOwned, createRepairLimiter } = require('../src/core/apply');
const { getPaths, saveState, loadState } = require('../src/core/config');
const { getPlatform } = require('../src/platform');
const { tmpHome, mockPlatform, sampleDetect, recordingExec, mutationCalls } = require('./helpers');

describe('apply / off / dry-run', () => {
  it('off deletes only ledger ownedRoutes', async () => {
    const home = tmpHome();
    const platform = mockPlatform();
    const paths = getPaths(home);
    saveState(paths, {
      applied: true,
      mode: 'inverse',
      ownedRoutes: [
        { dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1', kind: 'split', domain: null },
        { dest: '128.0.0.0', prefix: 1, gw: '192.168.1.1', kind: 'split', domain: null },
      ],
      watchEnabled: false,
    });
    const result = await off({ paths, platform });
    assert.equal(result.removed.length, 2);
    assert.equal(platform.dels.length, 2);
    assert.deepEqual(platform.dels.map((r) => r.dest).sort(), ['0.0.0.0', '128.0.0.0']);
    assert.equal(platform.adds.length, 0);
    const state = loadState(paths);
    assert.equal(state.applied, false);
    assert.deepEqual(state.ownedRoutes, []);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('dry-run uses the planner and performs zero add/delete execs', async () => {
    const fixtureNet = fs.readFileSync(path.join(__dirname, 'fixtures/darwin/netstat-rn.txt'), 'utf8');
    const fixtureIf = fs.readFileSync(path.join(__dirname, 'fixtures/darwin/ifconfig.txt'), 'utf8');
    const exec = recordingExec(async (file) => {
      const base = path.basename(file);
      if (base === 'netstat') return { stdout: fixtureNet, stderr: '' };
      if (base === 'ifconfig') return { stdout: fixtureIf, stderr: '' };
      throw new Error(`unexpected exec ${file}`);
    });
    const home = tmpHome();
    const platform = getPlatform({ os: 'darwin', exec, isAdmin: async () => true });
    const result = await on({
      paths: getPaths(home),
      platform,
      dryRun: true,
      mode: 'inverse',
    });
    assert.equal(result.dryRun, true);
    assert.ok(result.actions.some((a) => a.dest === '0.0.0.0' && a.prefix === 1));
    assert.ok(result.actions.some((a) => a.kind === 'lan-protect' && a.dest === '192.168.1.0'));
    assert.ok(result.actions.some((a) => a.kind === 'vpn-keep' && a.dest === '10.0.0.0' && a.prefix === 8));
    assert.equal(mutationCalls(exec.calls).length, 0);
    assert.equal(result.dns.ok, true);
    assert.equal(result.dns.mode, 'split');
    assert.equal(loadState(getPaths(home)).applied, false);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('win32 inverse dry-run from unnamed Ethernet 3 fixture', async () => {
    const print = fs.readFileSync(path.join(__dirname, 'fixtures/win32/route-print-wifi.txt'), 'utf8');
    const ipconfig = fs.readFileSync(path.join(__dirname, 'fixtures/win32/ipconfig-wifi.txt'), 'utf8');
    const exec = recordingExec(async (file) => {
      const base = path.basename(file).toLowerCase();
      if (base === 'route') return { stdout: print, stderr: '' };
      if (base === 'ipconfig') return { stdout: ipconfig, stderr: '' };
      return { stdout: '', stderr: '' };
    });
    const home = tmpHome();
    const platform = getPlatform({ os: 'win32', exec, isAdmin: async () => true });
    const result = await on({
      paths: getPaths(home),
      platform,
      dryRun: true,
      mode: 'inverse',
    });
    assert.equal(result.dryRun, true);
    assert.equal(result.detect.vpn.up, true);
    assert.equal(result.detect.vpn.iface, 'Ethernet 3');
    assert.ok(result.actions.some((a) => a.kind === 'split' && a.gw === '192.168.1.1' && a.prefix === 1));
    assert.equal(mutationCalls(exec.calls).length, 0);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('linux inverse dry-run from unnamed eth1 fixture', async () => {
    const routeTxt = fs.readFileSync(path.join(__dirname, 'fixtures/linux/ip-route-unnamed.txt'), 'utf8');
    const addrTxt = fs.readFileSync(path.join(__dirname, 'fixtures/linux/ip-addr-unnamed.txt'), 'utf8');
    const exec = recordingExec(async (file, args) => {
      const joined = [file, ...args].join(' ');
      if (joined.includes('route')) return { stdout: routeTxt, stderr: '' };
      if (joined.includes('addr')) return { stdout: addrTxt, stderr: '' };
      return { stdout: '', stderr: '' };
    });
    const home = tmpHome();
    const platform = getPlatform({ os: 'linux', exec, isAdmin: async () => true });
    const result = await on({
      paths: getPaths(home),
      platform,
      dryRun: true,
      mode: 'inverse',
    });
    assert.equal(result.dryRun, true);
    assert.equal(result.detect.vpn.iface, 'eth1');
    assert.ok(result.actions.some((a) => a.kind === 'split' && a.gw === '192.168.1.1'));
    assert.equal(mutationCalls(exec.calls).length, 0);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('watch does not re-apply after off or when VPN is down', async () => {
    const home = tmpHome();
    const platform = mockPlatform();
    const svc = new Service({ home, platform });
    await svc.on({ mode: 'inverse' });
    assert.ok(platform.adds.length > 0);
    platform.adds.length = 0;
    await svc.off();
    platform.dels.length = 0;
    const { repairOwned } = require('../src/core/apply');
    const afterOff = await repairOwned({ paths: getPaths(home), platform });
    assert.equal(afterOff.skipped, 'off');
    assert.equal(platform.adds.length, 0);

    saveState(getPaths(home), {
      applied: true,
      mode: 'inverse',
      watchEnabled: true,
      ownedRoutes: [{ dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1', kind: 'split', domain: null }],
    });
    platform.detect = async () => sampleDetect({ vpn: { up: false, iface: null, addr: null, gw: null, cidrs: [] } });
    const down = await repairOwned({ paths: getPaths(home), platform });
    assert.equal(down.skipped, 'vpn-down');
    assert.equal(platform.adds.length, 0);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('on domains with empty list fails EDOMAIN_EMPTY', async () => {
    const home = tmpHome();
    const svc = new Service({ home, platform: mockPlatform() });
    await assert.rejects(() => svc.on({ mode: 'domains' }), (err) => err.code === 'EDOMAIN_EMPTY');
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('repairOwned skips when watch is off unless session repair is on', async () => {
    const home = tmpHome();
    const platform = mockPlatform({
      listRoutes: [{ dest: '0.0.0.0', prefix: 1, gw: '10.243.1.1', iface: 'utun6', family: 'inet' }],
    });
    const paths = getPaths(home);
    saveState(paths, {
      applied: true,
      mode: 'inverse',
      watchEnabled: false,
      ownedRoutes: [{ dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1', kind: 'split', family: 'inet' }],
    });
    const skipped = await repairOwned({ paths, platform, session: false });
    assert.equal(skipped.skipped, 'watch-off');
    assert.equal(platform.adds.length, 0);
    const repaired = await repairOwned({ paths, platform, session: true });
    assert.equal(repaired.repaired, 1);
    assert.equal(repaired.hijacked, 1);
    assert.ok(platform.adds.some((a) => a.op === 'changeCidr' && a.dest === '0.0.0.0'));
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('repairOwned treats GP-hijacked /1 (wrong via) as needing change, never deletes default', async () => {
    const home = tmpHome();
    const platform = mockPlatform({
      listRoutes: [
        { dest: '0.0.0.0', prefix: 1, gw: '10.243.1.1', iface: 'utun6', family: 'inet' },
        { dest: '128.0.0.0', prefix: 1, gw: '10.243.1.1', iface: 'utun6', family: 'inet' },
        { dest: '0.0.0.0', prefix: 0, gw: '10.243.1.1', iface: 'utun6', family: 'inet' },
      ],
    });
    const paths = getPaths(home);
    saveState(paths, {
      applied: true,
      mode: 'inverse',
      watchEnabled: true,
      ownedRoutes: [
        { dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1', kind: 'split', family: 'inet' },
        { dest: '128.0.0.0', prefix: 1, gw: '192.168.1.1', kind: 'split', family: 'inet' },
      ],
    });
    const result = await repairOwned({ paths, platform });
    assert.equal(result.hijacked, 2);
    assert.equal(result.repaired, 2);
    assert.equal(platform.dels.length, 0);
    assert.ok(platform.adds.every((a) => a.dest !== '0.0.0.0' || a.prefix === 1));
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('repair limiter backs off after settle window', async () => {
    const home = tmpHome();
    const platform = mockPlatform({
      listRoutes: [{ dest: '0.0.0.0', prefix: 1, gw: '10.243.1.1', iface: 'utun6', family: 'inet' }],
    });
    const paths = getPaths(home);
    saveState(paths, {
      applied: true,
      mode: 'inverse',
      watchEnabled: true,
      ownedRoutes: [{ dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1', kind: 'split', family: 'inet' }],
    });
    let now = 1_000_000;
    const limiter = createRepairLimiter({ settleMs: 4000, now: () => now });
    const first = await repairOwned({ paths, platform, limiter });
    assert.equal(first.repaired, 1);
    platform.adds.length = 0;
    const second = await repairOwned({ paths, platform, limiter });
    assert.equal(second.skipped, 'settle');
    assert.equal(platform.adds.length, 0);
    now += 5000;
    const third = await repairOwned({ paths, platform, limiter });
    assert.equal(third.repaired, 1);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('without admin, on fails EPRIV but dry-run works', async () => {
    const home = tmpHome();
    const svc = new Service({ home, platform: mockPlatform({ admin: false }) });
    await assert.rejects(() => svc.on({ mode: 'inverse' }), (err) => err.code === 'EPRIV');
    const dry = await svc.on({ mode: 'inverse', dryRun: true });
    assert.equal(dry.dryRun, true);
    const allowed = await svc.allowHost('intranet.example.com');
    assert.equal(allowed.host, 'intranet.example.com');
    assert.equal(svc.getConfig().allowViaVpn.includes('intranet.example.com'), true);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('session repair does not persist CLI watch', async () => {
    const home = tmpHome();
    const platform = mockPlatform();
    const svc = new Service({ home, platform });
    svc.enableSessionRepair();
    await svc.on({ mode: 'inverse' });
    const st = await svc.getStatus();
    assert.equal(st.repairActive, true);
    assert.equal(st.watch, false);
    assert.equal(svc.getConfig().watch, false);
    svc.stopWatch();
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('inverse on ledgers ownedDns and off restores it', async () => {
    const home = tmpHome();
    const platform = mockPlatform();
    const svc = new Service({ home, platform });
    const result = await svc.on({ mode: 'inverse' });
    assert.equal(platform.dnsApplies.length, 1);
    assert.equal(result.dns.mode, 'split');
    const state = loadState(getPaths(home));
    assert.equal(state.ownedDns.mode, 'split');
    assert.equal(state.ownedDns.listen, '127.0.0.1');
    await svc.off();
    assert.equal(platform.dnsRestores.length, 1);
    assert.equal(loadState(getPaths(home)).ownedDns, null);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('repairOwned re-applies DNS when GP overwrites resolver', async () => {
    const home = tmpHome();
    const platform = mockPlatform({
      listRoutes: [
        { dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1', iface: 'en0', family: 'inet' },
      ],
      inspectDns: { ok: false, mode: 'vpn' },
    });
    const paths = getPaths(home);
    saveState(paths, {
      applied: true,
      mode: 'inverse',
      watchEnabled: true,
      ownedRoutes: [{ dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1', kind: 'split', family: 'inet' }],
      ownedDns: {
        mode: 'split',
        method: 'forwarder',
        listen: '127.0.0.1',
        pid: 4242,
        lanServers: ['192.168.1.1'],
        vpnServers: ['10.243.1.1'],
        suffixes: ['corp.example'],
        previous: [{ service: 'Wi-Fi', servers: ['10.243.1.1'], empty: false, search: [], searchEmpty: true }],
      },
    });
    const result = await repairOwned({ paths, platform });
    assert.equal(result.dnsRepaired, 1);
    assert.equal(platform.dnsApplies.length, 1);
    assert.equal(platform.dels.length, 0);
    fs.rmSync(home, { recursive: true, force: true });
  });
});
