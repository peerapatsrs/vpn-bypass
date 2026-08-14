'use strict';

const { createExec } = require('./exec');
const { parseLinuxIpRoute, parseLinuxIpAddr, inferTopology } = require('./common');
const { unixIsAdmin, cidrArg, ignoreExists, ignoreMissing } = require('./mutate');
const { assertSafeIpv4, assertSafePrefix, assertSafeIface } = require('../core/net');
const { parseSs, stdoutOrEmpty } = require('./connections');

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

function create(execImpl, opts = {}) {
  const exec = createExec(execImpl);
  const isAdmin = opts.isAdmin || unixIsAdmin(opts.getuid);

  async function listRoutes() {
    const { stdout } = await exec('ip', ['-4', 'route', 'show']);
    return parseLinuxIpRoute(stdout);
  }

  async function detect() {
    let routes = [];
    let ifaces = [];
    try {
      const r = await exec('ip', ['-4', 'route', 'show']);
      routes = parseLinuxIpRoute(r.stdout);
    } catch {
      routes = [];
    }
    try {
      const a = await exec('ip', ['-4', 'addr', 'show']);
      ifaces = parseLinuxIpAddr(a.stdout);
    } catch {
      ifaces = [];
    }
    return inferTopology(routes, ifaces, 'linux');
  }

  async function addCidr(route) {
    assertSafeIpv4(route.dest);
    assertSafePrefix(route.prefix);
    const args = ['route', 'replace', cidrArg(route), ...viaOrDev(route)];
    await ignoreExists(() => exec('ip', args));
  }

  async function addHost(route) {
    assertSafeIpv4(route.dest);
    const args = ['route', 'replace', `${route.dest}/32`, ...viaOrDev(route)];
    await ignoreExists(() => exec('ip', args));
  }

  async function del(route) {
    assertSafeIpv4(route.dest);
    const prefix = route.prefix == null ? 32 : route.prefix;
    assertSafePrefix(prefix);
    await ignoreMissing(() => exec('ip', ['route', 'del', `${route.dest}/${prefix}`]));
  }

  async function listConnections() {
    const stdout = await stdoutOrEmpty(exec, 'ss', ['-tnH', 'state', 'established']);
    return parseSs(stdout);
  }

  return { detect, listRoutes, listConnections, addCidr, addHost, del, isAdmin, parseRoutes: parseLinuxIpRoute };
}

module.exports = { create, parseRoutes: parseLinuxIpRoute, parseAddr: parseLinuxIpAddr };
