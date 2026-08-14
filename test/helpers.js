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
  return {
    detect: async () => detectSnap,
    listRoutes: async () => listed.slice(),
    addCidr: async (r) => { adds.push({ op: 'addCidr', ...r }); },
    addHost: async (r) => { adds.push({ op: 'addHost', ...r }); },
    del: async (r) => { dels.push({ ...r }); },
    isAdmin: async () => (opts.admin == null ? true : Boolean(opts.admin)),
    listConnections: async () => (opts.connections || []).slice(),
    adds,
    dels,
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
