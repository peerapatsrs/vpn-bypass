'use strict';

const { fail } = require('../core/errors');
const { assertSafeIpv4, assertSafePrefix, assertSafeIface, prefixToMask } = require('../core/net');
const { isAlreadyExists, isNotInTable } = require('./exec');

async function addOrChange(addFn, changeFn) {
  try {
    await addFn();
  } catch (err) {
    if (isAlreadyExists(err) && typeof changeFn === 'function') {
      await changeFn();
      return;
    }
    throw err;
  }
}

async function ignoreExists(fn) {
  try {
    await fn();
  } catch (err) {
    if (isAlreadyExists(err)) return;
    throw err;
  }
}

async function ignoreMissing(fn) {
  try {
    await fn();
  } catch (err) {
    if (isNotInTable(err)) return;
    throw err;
  }
}

function wrapMutations(exec, spec) {
  return {
    async addCidr(route) {
      assertSafeIpv4(route.dest);
      assertSafePrefix(route.prefix);
      if (route.gw) assertSafeIpv4(route.gw);
      if (route.iface) assertSafeIface(route.iface);
      await ignoreExists(() => exec(spec.addCidr(route).file, spec.addCidr(route).args));
    },
    async addHost(route) {
      assertSafeIpv4(route.dest);
      if (route.gw) assertSafeIpv4(route.gw);
      if (route.iface) assertSafeIface(route.iface);
      const cmd = spec.addHost(route);
      await ignoreExists(() => exec(cmd.file, cmd.args));
    },
    async del(route) {
      assertSafeIpv4(route.dest);
      assertSafePrefix(route.prefix == null ? 32 : route.prefix);
      const cmd = spec.del(route);
      await ignoreMissing(() => exec(cmd.file, cmd.args));
    },
  };
}

function unixIsAdmin(getuid) {
  const fn = getuid || (typeof process.getuid === 'function' ? process.getuid.bind(process) : null);
  return async function isAdmin() {
    if (!fn) return false;
    try {
      return fn() === 0;
    } catch {
      return false;
    }
  };
}

function cidrArg(route) {
  return `${route.dest}/${route.prefix}`;
}

function winMask(route) {
  return prefixToMask(route.prefix == null ? 32 : route.prefix);
}

module.exports = {
  ignoreExists,
  ignoreMissing,
  addOrChange,
  wrapMutations,
  unixIsAdmin,
  cidrArg,
  winMask,
  fail,
};
