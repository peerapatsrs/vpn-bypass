'use strict';

function skipped(detect, extra) {
  const lanGw = detect && detect.lan && detect.lan.gw;
  return {
    mode: 'unsupported',
    method: null,
    os: 'win32',
    warning: 'Windows system DNS is left unchanged so adapters are not bricked. General-web DNS may still go via the VPN.',
    previous: [],
    lanServers: lanGw ? [lanGw] : [],
    vpnServers: [],
    suffixes: [],
    ifaces: [],
    ...extra,
  };
}

function create() {
  async function readDns(detect) {
    return {
      lanServers: detect && detect.lan && detect.lan.gw ? [detect.lan.gw] : [],
      vpnServers: [],
      suffixes: [],
      search: [],
      resolvers: [],
      defaultServers: [],
    };
  }

  async function applyDns(opts = {}) {
    return skipped(opts.detect);
  }

  async function restoreDns() {
    return undefined;
  }

  async function inspectDns(owned) {
    return { ok: true, mode: (owned && owned.mode) || 'unsupported' };
  }

  async function dnsStatus(detect, owned) {
    return {
      mode: owned && owned.mode ? owned.mode : 'unsupported',
      method: null,
      lanServers: [],
      vpnServers: [],
      suffixes: [],
      listen: null,
      warning: (owned && owned.warning) || skipped(detect).warning,
      ok: true,
    };
  }

  return { readDns, applyDns, restoreDns, inspectDns, dnsStatus };
}

module.exports = { create };
