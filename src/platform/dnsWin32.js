'use strict';

function skipped(detect, extra, osName) {
  const lanGw = detect && detect.lan && detect.lan.gw;
  const os = osName || 'win32';
  return {
    mode: 'unsupported',
    method: null,
    os,
    warning: os === 'win32'
      ? 'Windows system DNS is left unchanged so adapters are not bricked. General-web DNS may still go via the VPN.'
      : 'System DNS is left unchanged on this OS. General-web DNS may still go via the VPN.',
    previous: [],
    lanServers: lanGw ? [lanGw] : [],
    vpnServers: [],
    suffixes: [],
    ifaces: [],
    ...extra,
  };
}

function create(opts = {}) {
  const osName = opts.os || 'win32';
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
    return skipped(opts.detect, undefined, osName);
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
      warning: (owned && owned.warning) || skipped(detect, undefined, osName).warning,
      ok: true,
    };
  }

  return { readDns, applyDns, restoreDns, inspectDns, dnsStatus };
}

module.exports = { create };
