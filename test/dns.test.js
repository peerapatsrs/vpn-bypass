'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const {
  parseScutilDns,
  parseServiceOrder,
  classifyDns,
  hostnameUsesVpnDns,
  isRfc1918Ptr,
  buildSplitDnsPlan,
  inferDnsMode,
  restoreServerArgs,
} = require('../src/core/dns');
const { sampleDetect } = require('./helpers');

const FIX = path.join(__dirname, 'fixtures/darwin');

describe('split-DNS policy', () => {
  it('parses scutil --dns and classifies LAN vs VPN vs corp suffixes', () => {
    const text = fs.readFileSync(path.join(FIX, 'scutil-dns.txt'), 'utf8');
    const resolvers = parseScutilDns(text);
    assert.ok(resolvers.some((r) => r.nameservers.includes('10.230.8.8') && !r.scoped));
    assert.ok(resolvers.some((r) => r.iface === 'en0' && r.nameservers.includes('192.168.1.1')));
    assert.ok(resolvers.some((r) => r.supplemental && r.domains.includes('corp.example')));
    const detect = sampleDetect();
    const classified = classifyDns(resolvers, detect);
    assert.deepEqual(classified.lanServers, ['192.168.1.1']);
    assert.ok(classified.vpnServers.includes('10.230.8.8'));
    assert.ok(classified.suffixes.includes('corp.example'));
    assert.equal(classified.suffixes.includes('local'), false);
    const plan = buildSplitDnsPlan(detect, classified);
    assert.equal(plan.ok, true);
    assert.equal(plan.mode, 'split');
    assert.equal(plan.listen, '127.0.0.1');
  });

  it('sends facebook.com to LAN and corp / RFC1918 PTR to VPN', () => {
    const suffixes = ['corp.example'];
    assert.equal(hostnameUsesVpnDns('facebook.com', suffixes), false);
    assert.equal(hostnameUsesVpnDns('www.facebook.com', suffixes), false);
    assert.equal(hostnameUsesVpnDns('jira.corp.example', suffixes), true);
    assert.equal(hostnameUsesVpnDns('corp.example', suffixes), true);
    assert.equal(hostnameUsesVpnDns('notcorp.example', suffixes), false);
    assert.equal(hostnameUsesVpnDns('evil.corp.example.attacker.com', suffixes), false);
    assert.equal(isRfc1918Ptr('1.1.168.192.in-addr.arpa'), true);
    assert.equal(hostnameUsesVpnDns('1.1.168.192.in-addr.arpa', suffixes), true);
    assert.equal(isRfc1918Ptr('1.1.1.10.in-addr.arpa'), true);
    assert.equal(isRfc1918Ptr('1.1.16.172.in-addr.arpa'), true);
    assert.equal(isRfc1918Ptr('1.1.15.172.in-addr.arpa'), false);
    assert.equal(isRfc1918Ptr('1.1.1.8.in-addr.arpa'), false);
  });

  it('infers dns mode split/lan/vpn and never restores 127.0.0.1 as previous', () => {
    assert.equal(inferDnsMode(['127.0.0.1']), 'split');
    assert.equal(inferDnsMode(['192.168.1.1'], { lanServers: ['192.168.1.1'], vpnServers: ['10.1.1.1'] }), 'lan');
    assert.equal(inferDnsMode(['10.1.1.1'], { lanServers: ['192.168.1.1'], vpnServers: ['10.1.1.1'] }), 'vpn');
    assert.deepEqual(restoreServerArgs({ servers: ['127.0.0.1'], empty: false }), ['Empty']);
    assert.deepEqual(restoreServerArgs({ servers: ['10.1.1.1'], empty: false }), ['10.1.1.1']);
    assert.deepEqual(restoreServerArgs({ servers: [], empty: true }), ['Empty']);
  });

  it('parses networksetup service order', () => {
    const services = parseServiceOrder(fs.readFileSync(path.join(FIX, 'networksetup-order.txt'), 'utf8'));
    assert.equal(services[0].name, 'Wi-Fi');
    assert.equal(services[0].device, 'en0');
    assert.equal(services[0].disabled, false);
  });
});
