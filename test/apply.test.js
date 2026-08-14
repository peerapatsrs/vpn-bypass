'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { Service } = require('../src/core/service');
const { on, off } = require('../src/core/apply');
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
    assert.equal(loadState(getPaths(home)).applied, false);
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

  it('without admin, on fails EPRIV but dry-run works', async () => {
    const home = tmpHome();
    const svc = new Service({ home, platform: mockPlatform({ admin: false }) });
    await assert.rejects(() => svc.on({ mode: 'inverse' }), (err) => err.code === 'EPRIV');
    const dry = await svc.on({ mode: 'inverse', dryRun: true });
    assert.equal(dry.dryRun, true);
    fs.rmSync(home, { recursive: true, force: true });
  });
});
