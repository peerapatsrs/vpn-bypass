'use strict';

const { createExec } = require('./exec');
const {
  parseLinuxIpRoute, parseLinuxIpRoute6, parseLinuxIpAddr, inferTopology, inferIpv6,
} = require('./common');
const { unixIsAdmin, cidrArg, ignoreExists, ignoreMissing } = require('./mutate');
const { fail } = require('../core/errors');
const {
  assertSafeIpv4, assertSafeIpv6, assertSafePrefix, assertSafePrefix6, assertSafeIface,
  familyOf, stripZone, isLinkLocal6,
} = require('../core/net');
const { parseSs, stdoutOrEmpty } = require('./connections');
const dnsLinux = require('./dnsLinux');

function viaOrDev(route) {
  if ((route.kind === 'allow-vpn' || route.kind === 'vpn-keep') && route.iface) {
    assertSafeIface(route.iface);
    return ['dev', route.iface];
  }
  if (route.gw) {
    assertSafeIpv4(route.gw);
    return ['via', route.gw];
  }
  if (route.iface) {
    assertSafeIface(route.iface);
    return ['dev', route.iface];
  }
  return [];
}

function viaOrDev6(route) {
  const out = [];
  if (route.gw) {
    assertSafeIpv6(route.gw);
    out.push('via', stripZone(route.gw));
  }
  const iface = route.iface;
  if (iface) {
    assertSafeIface(iface);
    out.push('dev', iface);
  } else if (route.gw && isLinkLocal6(route.gw)) {
    throw fail('EINVAL', 'link-local IPv6 via requires iface');
  }
  return out;
}

function create(execImpl, opts = {}) {
  const exec = createExec(execImpl);
  const isAdmin = opts.isAdmin || unixIsAdmin(opts.getuid);

  async function listRoutes4() {
    const { stdout } = await exec('ip', ['-4', 'route', 'show']);
    return parseLinuxIpRoute(stdout);
  }

  async function listRoutes6() {
    try {
      const { stdout } = await exec('ip', ['-6', 'route', 'show']);
      return parseLinuxIpRoute6(stdout);
    } catch {
      return [];
    }
  }

  async function listRoutes() {
    const v4 = await listRoutes4();
    const v6 = await listRoutes6();
    return v4.concat(v6);
  }

  async function detect() {
    let routes = [];
    let routes6 = [];
    let ifaces = [];
    try {
      const r = await exec('ip', ['-4', 'route', 'show']);
      routes = parseLinuxIpRoute(r.stdout);
    } catch {
      routes = [];
    }
    try {
      const r6 = await exec('ip', ['-6', 'route', 'show']);
      routes6 = parseLinuxIpRoute6(r6.stdout);
    } catch {
      routes6 = [];
    }
    try {
      const a = await exec('ip', ['-4', 'addr', 'show']);
      ifaces = parseLinuxIpAddr(a.stdout);
    } catch {
      ifaces = [];
    }
    return inferIpv6(routes6, inferTopology(routes, ifaces, 'linux'));
  }

  async function addCidr(route) {
    if (familyOf(route) === 'inet6') {
      assertSafeIpv6(route.dest);
      assertSafePrefix6(route.prefix);
      const args = ['-6', 'route', 'replace', `${route.dest}/${route.prefix}`, ...viaOrDev6(route)];
      await ignoreExists(() => exec('ip', args));
      return;
    }
    assertSafeIpv4(route.dest);
    assertSafePrefix(route.prefix);
    const args = ['route', 'replace', cidrArg(route), ...viaOrDev(route)];
    await ignoreExists(() => exec('ip', args));
  }

  async function addHost(route) {
    if (familyOf(route) === 'inet6') {
      assertSafeIpv6(route.dest);
      const args = ['-6', 'route', 'replace', `${route.dest}/128`, ...viaOrDev6(route)];
      await ignoreExists(() => exec('ip', args));
      return;
    }
    assertSafeIpv4(route.dest);
    const args = ['route', 'replace', `${route.dest}/32`, ...viaOrDev(route)];
    await ignoreExists(() => exec('ip', args));
  }

  async function changeCidr(route) {
    return addCidr(route);
  }

  async function changeHost(route) {
    return addHost(route);
  }

  async function del(route) {
    if (familyOf(route) === 'inet6') {
      assertSafeIpv6(route.dest);
      const prefix = route.prefix == null ? 128 : route.prefix;
      assertSafePrefix6(prefix);
      await ignoreMissing(() => exec('ip', ['-6', 'route', 'del', `${route.dest}/${prefix}`]));
      return;
    }
    assertSafeIpv4(route.dest);
    const prefix = route.prefix == null ? 32 : route.prefix;
    assertSafePrefix(prefix);
    await ignoreMissing(() => exec('ip', ['route', 'del', `${route.dest}/${prefix}`]));
  }

  async function listConnections() {
    const stdout = await stdoutOrEmpty(exec, 'ss', ['-tnH', 'state', 'established']);
    return parseSs(stdout);
  }

  const dns = dnsLinux.create({ exec });

  return {
    detect, listRoutes, listConnections, addCidr, addHost, changeCidr, changeHost, del, isAdmin,
    parseRoutes: parseLinuxIpRoute,
    readDns: dns.readDns,
    applyDns: dns.applyDns,
    restoreDns: dns.restoreDns,
    inspectDns: dns.inspectDns,
    dnsStatus: dns.dnsStatus,
  };
}

module.exports = { create, parseRoutes: parseLinuxIpRoute, parseAddr: parseLinuxIpAddr };
