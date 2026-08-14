'use strict';

const { createExec } = require('./exec');
const { parseDarwinNetstat, parseIfconfig, inferTopology } = require('./common');
const { unixIsAdmin, cidrArg, ignoreExists, ignoreMissing } = require('./mutate');
const { assertSafeIpv4, assertSafePrefix, assertSafeIface } = require('../core/net');
const { parseLsofFields, stdoutOrEmpty } = require('./connections');

const NETSTAT = '/usr/sbin/netstat';
const IFCONFIG = '/sbin/ifconfig';
const ROUTE = '/sbin/route';
const LSOF = '/usr/sbin/lsof';

function create(execImpl, opts = {}) {
  const exec = createExec(execImpl);
  const isAdmin = opts.isAdmin || unixIsAdmin(opts.getuid);

  async function listRoutes() {
    const { stdout } = await exec(NETSTAT, ['-rn', '-f', 'inet']);
    return parseDarwinNetstat(stdout);
  }

  async function detect() {
    let routes = [];
    let ifaces = [];
    try {
      const net = await exec(NETSTAT, ['-rn', '-f', 'inet']);
      routes = parseDarwinNetstat(net.stdout);
    } catch {
      routes = [];
    }
    try {
      const ic = await exec(IFCONFIG, []);
      ifaces = parseIfconfig(ic.stdout);
    } catch {
      ifaces = [];
    }
    return inferTopology(routes, ifaces, 'darwin');
  }

  async function addCidr(route) {
    assertSafeIpv4(route.dest);
    assertSafePrefix(route.prefix);
    if (route.gw) assertSafeIpv4(route.gw);
    const args = ['-n', 'add', '-net', cidrArg(route)];
    if ((route.kind === 'allow-vpn' || route.kind === 'vpn-keep') && route.iface) {
      assertSafeIface(route.iface);
      args.push('-interface', route.iface);
    } else if (route.gw) {
      args.push(route.gw);
    } else if (route.iface) {
      assertSafeIface(route.iface);
      args.push('-interface', route.iface);
    }
    await ignoreExists(() => exec(ROUTE, args));
  }

  async function addHost(route) {
    assertSafeIpv4(route.dest);
    const args = ['-n', 'add', '-host', route.dest];
    if (route.kind === 'allow-vpn' && route.iface) {
      assertSafeIface(route.iface);
      args.push('-interface', route.iface);
    } else if (route.gw) {
      assertSafeIpv4(route.gw);
      args.push(route.gw);
    } else if (route.iface) {
      assertSafeIface(route.iface);
      args.push('-interface', route.iface);
    }
    await ignoreExists(() => exec(ROUTE, args));
  }

  async function del(route) {
    assertSafeIpv4(route.dest);
    const prefix = route.prefix == null ? 32 : route.prefix;
    assertSafePrefix(prefix);
    const args = prefix === 32
      ? ['-n', 'delete', '-host', route.dest]
      : ['-n', 'delete', '-net', `${route.dest}/${prefix}`];
    await ignoreMissing(() => exec(ROUTE, args));
  }

  async function listConnections() {
    const stdout = await stdoutOrEmpty(exec, LSOF, [
      '-a', '+c', '0', '-n', '-P', '-Fpcn',
      '-iTCP:80,443,8080,8443',
      '-sTCP:ESTABLISHED',
    ]);
    return parseLsofFields(stdout);
  }

  return { detect, listRoutes, listConnections, addCidr, addHost, del, isAdmin, parseRoutes: parseDarwinNetstat };
}

module.exports = { create, parseRoutes: parseDarwinNetstat, parseIfconfig };
