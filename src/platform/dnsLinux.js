'use strict';

const { buildSplitDnsPlan, RFC1918_PTR_ZONES } = require('../core/dns');
const { assertSafeIface } = require('../core/net');

function create(opts = {}) {
  const exec = opts.exec;

  async function resolvectlAvailable() {
    try {
      await exec('resolvectl', ['--no-pager', 'status']);
      return true;
    } catch {
      try {
        await exec('resolvectl', ['status']);
        return true;
      } catch {
        return false;
      }
    }
  }

  async function readDns(detect) {
    const lan = (detect && detect.lan) || {};
    const vpn = (detect && detect.vpn) || {};
    const lanServers = lan.gw ? [lan.gw] : [];
    return {
      lanServers,
      vpnServers: [],
      suffixes: [],
      search: [],
      resolvers: [],
      defaultServers: lanServers,
    };
  }

  async function applyDns(optsArg = {}) {
    const detect = optsArg.detect || {};
    const snapshot = optsArg.snapshot || await readDns(detect);
    const plan = buildSplitDnsPlan(detect, snapshot);
    const lanIface = detect.lan && detect.lan.iface;
    const vpnIface = detect.vpn && detect.vpn.iface;
    const available = await resolvectlAvailable();
    if (!available) {
      return {
        mode: 'skipped',
        method: null,
        os: 'linux',
        warning: 'resolvectl not available; system DNS unchanged (intranet names still work, general-web DNS may still use the VPN)',
        previous: [],
        lanServers: plan.lanServers || [],
        vpnServers: plan.vpnServers || [],
        suffixes: plan.suffixes || [],
        ifaces: [],
      };
    }
    if (!plan.ok || !lanIface) {
      return {
        mode: 'skipped',
        method: null,
        os: 'linux',
        warning: (plan && plan.warning) || 'no LAN interface for resolvectl; system DNS unchanged',
        previous: [],
        lanServers: [],
        vpnServers: [],
        suffixes: [],
        ifaces: [],
      };
    }
    try { assertSafeIface(lanIface); } catch {
      return { mode: 'skipped', os: 'linux', warning: 'unsafe LAN iface', ifaces: [], previous: [] };
    }
    const ifaces = [lanIface];
    try {
      await exec('resolvectl', ['dns', lanIface, ...plan.lanServers]);
      await exec('resolvectl', ['default-route', lanIface, 'yes']);
    } catch {
      return {
        mode: 'skipped',
        method: 'resolvectl',
        os: 'linux',
        warning: 'resolvectl could not set LAN DNS; system DNS unchanged',
        previous: [],
        lanServers: plan.lanServers,
        vpnServers: plan.vpnServers,
        suffixes: plan.suffixes,
        ifaces: [],
      };
    }
    if (vpnIface) {
      try { assertSafeIface(vpnIface); } catch {
        return {
          mode: 'split',
          method: 'resolvectl',
          os: 'linux',
          lanServers: plan.lanServers,
          vpnServers: plan.vpnServers,
          suffixes: plan.suffixes,
          ifaces,
          previous: [],
          warning: 'VPN iface skipped for domain routing',
        };
      }
      const domains = [];
      for (const s of plan.suffixes || []) domains.push(`~${s}`);
      if (plan.vpnServers && plan.vpnServers.length) {
        for (const z of RFC1918_PTR_ZONES) domains.push(`~${z}`);
      }
      try {
        if (plan.vpnServers.length) {
          await exec('resolvectl', ['dns', vpnIface, ...plan.vpnServers]);
        }
        if (domains.length) {
          await exec('resolvectl', ['domain', vpnIface, ...domains]);
        }
        await exec('resolvectl', ['default-route', vpnIface, 'no']);
        ifaces.push(vpnIface);
      } catch {
        // LAN DNS still applied
      }
    }
    return {
      mode: 'split',
      method: 'resolvectl',
      os: 'linux',
      lanServers: plan.lanServers,
      vpnServers: plan.vpnServers,
      suffixes: plan.suffixes,
      search: plan.search,
      ifaces,
      previous: [],
      warning: plan.warning || null,
    };
  }

  async function restoreDns(owned) {
    if (!owned) return;
    for (const iface of owned.ifaces || []) {
      try { assertSafeIface(iface); } catch { continue; }
      try {
        await exec('resolvectl', ['revert', iface]);
      } catch {
        // best-effort
      }
    }
  }

  async function inspectDns(owned) {
    if (!owned || owned.mode !== 'split' || !owned.ifaces || !owned.ifaces.length) {
      return { ok: true, mode: owned && owned.mode ? owned.mode : 'none' };
    }
    const lanIface = owned.ifaces[0];
    try {
      const { stdout } = await exec('resolvectl', ['dns', lanIface]);
      const text = String(stdout || '');
      const leak = (owned.vpnServers || []).some((s) => text.includes(s));
      const hasLan = (owned.lanServers || []).some((s) => text.includes(s));
      return { ok: hasLan && !leak, mode: leak ? 'vpn' : (hasLan ? 'split' : 'vpn') };
    } catch {
      return { ok: true, mode: owned.mode };
    }
  }

  async function dnsStatus(detect, owned) {
    return {
      mode: owned && owned.mode ? owned.mode : 'none',
      method: owned && owned.method,
      lanServers: (owned && owned.lanServers) || (detect && detect.lan && detect.lan.gw ? [detect.lan.gw] : []),
      vpnServers: (owned && owned.vpnServers) || [],
      suffixes: (owned && owned.suffixes) || [],
      listen: null,
      warning: owned && owned.warning,
      ok: true,
    };
  }

  return { readDns, applyDns, restoreDns, inspectDns, dnsStatus };
}

module.exports = { create };
