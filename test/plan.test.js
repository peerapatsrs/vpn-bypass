'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { plan, planInverse, planDomains } = require('../src/core/plan');
const { sampleDetect } = require('./helpers');

describe('plan', () => {
  it('inverse adds /1 via LAN and re-pins RFC1918 plus VPN CIDRs via VPN', () => {
    const detect = sampleDetect();
    const { actions } = plan({ mode: 'inverse', detect });
    const splits = actions.filter((a) => a.kind === 'split');
    assert.equal(splits.length, 2);
    assert.deepEqual(splits.map((a) => `${a.dest}/${a.prefix}`).sort(), ['0.0.0.0/1', '128.0.0.0/1']);
    for (const a of splits) {
      assert.equal(a.gw, '192.168.1.1');
      assert.equal(a.op, 'addCidr');
    }
    const keep = actions.filter((a) => a.kind === 'vpn-keep');
    assert.ok(keep.some((a) => a.dest === '10.0.0.0' && a.prefix === 8));
    assert.ok(keep.some((a) => a.dest === '172.16.0.0' && a.prefix === 12));
    assert.ok(keep.some((a) => a.dest === '192.168.0.0' && a.prefix === 16));
    assert.ok(keep.some((a) => a.dest === '10.10.0.0' && a.prefix === 16));
    for (const a of keep) {
      assert.equal(a.iface, 'utun6');
    }
    const protect = actions.find((a) => a.kind === 'lan-protect');
    assert.equal(protect.dest, '192.168.1.0');
    assert.equal(protect.prefix, 24);
    assert.equal(protect.gw, '192.168.1.1');
  });

  it('inverse protects the home LAN /24 via LAN GW', () => {
    const detect = sampleDetect();
    const actions = planInverse(detect);
    const protect = actions.find((a) => a.kind === 'lan-protect');
    assert.ok(protect);
    assert.equal(protect.dest, '192.168.1.0');
    assert.equal(protect.prefix, 24);
    assert.equal(protect.gw, '192.168.1.1');
  });

  it('domains has host routes via LAN GW and no /1 splits', () => {
    const detect = sampleDetect();
    const actions = planDomains(detect, [
      { ip: '1.2.3.4', domain: 'example.com' },
      { ip: '1.2.3.5', domain: 'www.example.com' },
    ]);
    assert.equal(actions.every((a) => a.op === 'addHost'), true);
    assert.equal(actions.every((a) => a.gw === '192.168.1.1'), true);
    assert.equal(actions.some((a) => a.prefix === 1), false);
    const built = plan({
      mode: 'domains',
      detect,
      resolvedDomains: [{ ip: '8.8.8.8', domain: 'dns.google' }],
    });
    assert.equal(built.actions.some((a) => a.kind === 'split'), false);
    assert.ok(built.actions.some((a) => a.kind === 'domain' && a.dest === '8.8.8.8'));
    assert.ok(built.actions.some((a) => a.kind === 'lan-protect'));
  });

  it('allow-via-VPN host routes use the VPN iface', () => {
    const { actions } = plan({
      mode: 'inverse',
      detect: sampleDetect(),
      allowViaVpn: [{ ip: '10.1.2.3', domain: 'intranet.corp.example' }],
    });
    const allow = actions.find((a) => a.kind === 'allow-vpn');
    assert.ok(allow);
    assert.equal(allow.dest, '10.1.2.3');
    assert.equal(allow.iface, 'utun6');
    assert.equal(allow.gw, '10.243.1.1');
  });

  it('inverse still pins RFC1918 when GP listed no extra CIDRs', () => {
    const base = sampleDetect();
    const detect = sampleDetect({ vpn: { ...base.vpn, cidrs: [] } });
    const { actions } = plan({ mode: 'inverse', detect });
    const keep = actions.filter((a) => a.kind === 'vpn-keep');
    assert.ok(keep.some((a) => a.dest === '10.0.0.0' && a.prefix === 8));
    assert.equal(keep.some((a) => a.dest === '10.10.0.0'), false);
  });

  it('inverse adds inet6 /1 via LAN gw6 when present', () => {
    const base = sampleDetect();
    const detect = sampleDetect({
      lan: { ...base.lan, gw6: 'fe80::1%en0' },
    });
    const actions = planInverse(detect);
    const v6 = actions.filter((a) => a.family === 'inet6' && a.kind === 'split');
    assert.equal(v6.length, 2);
    assert.deepEqual(v6.map((a) => `${a.dest}/${a.prefix}`).sort(), ['8000::/1', '::/1']);
    for (const a of v6) {
      assert.equal(a.gw, 'fe80::1%en0');
      assert.equal(a.iface, 'en0');
    }
  });

  it('inverse skips inet6 /1 when no LAN inet6 gateway', () => {
    const actions = planInverse(sampleDetect());
    assert.equal(actions.some((a) => a.family === 'inet6'), false);
    assert.equal(actions.filter((a) => a.kind === 'split').length, 2);
  });
});
