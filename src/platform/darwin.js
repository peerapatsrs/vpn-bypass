'use strict';

const { createExec } = require('./exec');
const {
  parseDarwinNetstat, parseDarwinNetstat6, parseIfconfig, inferTopology, inferIpv6,
} = require('./common');
const { unixIsAdmin, cidrArg, ignoreExists, ignoreMissing, addOrChange } = require('./mutate');
const {
  assertSafeIpv4, assertSafeIpv6, assertSafePrefix, assertSafePrefix6, assertSafeIface, familyOf,
} = require('../core/net');
const { parseLsofFields, stdoutOrEmpty } = require('./connections');
const dnsDarwin = require('./dnsDarwin');

const NETSTAT = '/usr/sbin/netstat';
const IFCONFIG = '/sbin/ifconfig';
const ROUTE = '/sbin/route';
const LSOF = '/usr/sbin/lsof';

function inet6Args(route, op) {
  assertSafeIpv6(route.dest);
  const prefix = route.prefix == null ? 128 : route.prefix;
  assertSafePrefix6(prefix);
  const args = prefix === 128
    ? ['-n', op, '-inet6', '-host', route.dest]
    : ['-n', op, '-inet6', '-net', `${route.dest}/${prefix}`];
  if (route.gw) {
    assertSafeIpv6(route.gw);
    args.push(route.gw);
  } else if (route.iface) {
    assertSafeIface(route.iface);
    args.push('-interface', route.iface);
  }
  return args;
}

function inetArgs(route, op) {
  assertSafeIpv4(route.dest);
  const prefix = route.prefix == null ? 32 : route.prefix;
  assertSafePrefix(prefix);
  const args = prefix === 32
    ? ['-n', op, '-host', route.dest]
    : ['-n', op, '-net', cidrArg({ dest: route.dest, prefix })];
  if ((route.kind === 'allow-vpn' || route.kind === 'vpn-keep') && route.iface && op !== 'delete') {
    assertSafeIface(route.iface);
    args.push('-interface', route.iface);
  } else if (route.gw && op !== 'delete') {
    assertSafeIpv4(route.gw);
    args.push(route.gw);
  } else if (route.iface && op !== 'delete') {
    assertSafeIface(route.iface);
    args.push('-interface', route.iface);
  }
  return args;
}

function mutateArgs(route, op) {
  return familyOf(route) === 'inet6' ? inet6Args(route, op) : inetArgs(route, op);
}

function create(execImpl, opts = {}) {
  const exec = createExec(execImpl);
  const isAdmin = opts.isAdmin || unixIsAdmin(opts.getuid);

  async function listRoutes4() {
    const { stdout } = await exec(NETSTAT, ['-rn', '-f', 'inet']);
    return parseDarwinNetstat(stdout);
  }

  async function listRoutes6() {
    try {
      const { stdout } = await exec(NETSTAT, ['-rn', '-f', 'inet6']);
      return parseDarwinNetstat6(stdout);
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
      const net = await exec(NETSTAT, ['-rn', '-f', 'inet']);
      routes = parseDarwinNetstat(net.stdout);
    } catch {
      routes = [];
    }
    try {
      const net6 = await exec(NETSTAT, ['-rn', '-f', 'inet6']);
      routes6 = parseDarwinNetstat6(net6.stdout);
    } catch {
      routes6 = [];
    }
    try {
      const ic = await exec(IFCONFIG, []);
      ifaces = parseIfconfig(ic.stdout);
    } catch {
      ifaces = [];
    }
    return inferIpv6(routes6, inferTopology(routes, ifaces, 'darwin'));
  }

  async function addCidr(route) {
    await addOrChange(
      () => exec(ROUTE, mutateArgs(route, 'add')),
      () => exec(ROUTE, mutateArgs(route, 'change')),
    );
  }

  async function addHost(route) {
    const host = { ...route, prefix: familyOf(route) === 'inet6' ? 128 : 32 };
    await addOrChange(
      () => exec(ROUTE, mutateArgs(host, 'add')),
      () => exec(ROUTE, mutateArgs(host, 'change')),
    );
  }

  async function changeCidr(route) {
    try {
      await exec(ROUTE, mutateArgs(route, 'change'));
    } catch (err) {
      await ignoreExists(() => exec(ROUTE, mutateArgs(route, 'add')));
    }
  }

  async function changeHost(route) {
    const host = { ...route, prefix: familyOf(route) === 'inet6' ? 128 : 32 };
    return changeCidr(host);
  }

  async function del(route) {
    const copy = { ...route };
    if (copy.prefix == null) copy.prefix = familyOf(copy) === 'inet6' ? 128 : 32;
    await ignoreMissing(() => exec(ROUTE, mutateArgs(copy, 'delete')));
  }

  async function listConnections() {
    const stdout = await stdoutOrEmpty(exec, LSOF, [
      '-a', '+c', '0', '-n', '-P', '-Fpcn',
      '-iTCP:80,443,8080,8443',
      '-sTCP:ESTABLISHED',
    ]);
    return parseLsofFields(stdout);
  }

  const dns = dnsDarwin.create({
    exec,
    startForwarder: opts.startForwarder,
    stopForwarder: opts.stopForwarder,
    etcResolverDir: opts.etcResolverDir,
    spawnImpl: opts.spawnImpl,
  });

  return {
    detect,
    listRoutes,
    listConnections,
    addCidr,
    addHost,
    changeCidr,
    changeHost,
    del,
    isAdmin,
    parseRoutes: parseDarwinNetstat,
    readDns: dns.readDns,
    applyDns: dns.applyDns,
    restoreDns: dns.restoreDns,
    inspectDns: dns.inspectDns,
    dnsStatus: dns.dnsStatus,
  };
}

module.exports = { create, parseRoutes: parseDarwinNetstat, parseIfconfig };
