'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

function tmpHome() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'vpn-bypass-'));
}

function sampleDetect(overrides = {}) {
  return {
    os: 'darwin',
    vpn: {
      up: true,
      iface: 'utun6',
      addr: '10.243.1.92',
      gw: '10.243.1.1',
      cidrs: [{ dest: '10.10.0.0', prefix: 16, gw: '10.243.1.1', iface: 'utun6' }],
    },
    lan: {
      iface: 'en0',
      addr: '192.168.1.42',
      gw: '192.168.1.1',
      prefix: 24,
      network: '192.168.1.0',
    },
    ifaces: [
      { name: 'utun6', role: 'vpn', addr: '10.243.1.92' },
      { name: 'en0', role: 'lan', addr: '192.168.1.42', gw: '192.168.1.1' },
    ],
    routes: [],
    ...overrides,
  };
}

function mockPlatform(opts = {}) {
  const detectSnap = opts.detect || sampleDetect();
  const adds = [];
  const dels = [];
  const listed = opts.listRoutes || [];
  const dnsApplies = [];
  const dnsRestores = [];
  return {
    detect: async () => detectSnap,
    listRoutes: async () => listed.slice(),
    addCidr: async (r) => { adds.push({ ...r, op: 'addCidr' }); },
    addHost: async (r) => { adds.push({ ...r, op: 'addHost' }); },
    changeCidr: async (r) => { adds.push({ ...r, op: 'changeCidr' }); },
    changeHost: async (r) => { adds.push({ ...r, op: 'changeHost' }); },
    del: async (r) => { dels.push({ ...r }); },
    isAdmin: async () => (opts.admin == null ? true : Boolean(opts.admin)),
    listConnections: async () => (opts.connections || []).slice(),
    readDns: async () => opts.dnsSnapshot || {
      lanServers: ['192.168.1.1'],
      vpnServers: ['10.243.1.1'],
      suffixes: ['corp.example'],
      search: ['corp.example'],
      resolvers: [],
      defaultServers: ['10.243.1.1'],
      services: [{ name: 'Wi-Fi', device: 'en0', disabled: false }],
    },
    applyDns: async (o) => {
      const ledger = opts.applyDnsResult || {
        mode: 'split',
        method: 'forwarder',
        os: 'darwin',
        pid: 4242,
        listen: '127.0.0.1',
        lanServers: ['192.168.1.1'],
        vpnServers: ['10.243.1.1'],
        suffixes: ['corp.example'],
        previous: [{ service: 'Wi-Fi', device: 'en0', servers: ['10.243.1.1'], empty: false, search: ['corp.example'], searchEmpty: false }],
        resolverFiles: [],
        warning: null,
      };
      dnsApplies.push(o || {});
      return ledger;
    },
    restoreDns: async (owned) => { dnsRestores.push(owned); },
    inspectDns: async () => (opts.inspectDns || { ok: true, mode: 'split' }),
    dnsStatus: async () => (opts.dnsStatus || { mode: 'vpn', ok: true, lanServers: ['192.168.1.1'], vpnServers: ['10.243.1.1'], suffixes: ['corp.example'] }),
    adds,
    dels,
    dnsApplies,
    dnsRestores,
  };
}

function recordingExec(handler) {
  const calls = [];
  async function exec(file, args = []) {
    calls.push({ file, args: args.slice(), joined: [file, ...args].join(' ') });
    if (handler) return handler(file, args, calls);
    return { stdout: '', stderr: '', code: 0 };
  }
  exec.calls = calls;
  return exec;
}

function mutationCalls(calls) {
  return calls.filter((c) => {
    const j = c.joined.toLowerCase();
    const file = String(c.file || '').toLowerCase();
    if (file.includes('networksetup') && (j.includes('setdnsservers') || j.includes('setsearchdomains'))) {
      return true;
    }
    if (file.includes('resolvectl') && /(dns|domain|default-route|revert)/.test(j)) {
      return true;
    }
    return (
      /(^|\s)(add|delete|del|replace)(\s|$)/.test(j)
      && (j.includes('route') || c.file === 'route' || c.file === 'ip')
    );
  });
}

module.exports = {
  tmpHome,
  sampleDetect,
  mockPlatform,
  recordingExec,
  mutationCalls,
};
