'use strict';

const { fail } = require('../core/errors');
const { createExec } = require('./exec');

const BSD = new Set(['freebsd', 'openbsd', 'netbsd', 'dragonfly']);

function resolveOs(osName) {
  const n = String(osName || process.platform).toLowerCase();
  if (n === 'android') return 'linux';
  if (BSD.has(n)) return 'bsd';
  return n;
}

function getPlatform(opts = {}) {
  const requested = opts.os || process.platform;
  const osName = resolveOs(requested);
  const exec = createExec(opts.exec);
  if (osName === 'darwin') return require('./darwin').create(exec, opts);
  if (osName === 'linux') return require('./linux').create(exec, { ...opts, topologyOs: 'linux' });
  if (osName === 'win32') return require('./win32').create(exec, opts);
  if (osName === 'bsd') {
    return require('./darwin').create(exec, {
      ...opts,
      topologyOs: BSD.has(String(requested).toLowerCase()) ? requested : 'freebsd',
      dnsSkip: true,
      bin: {
        netstat: 'netstat',
        ifconfig: 'ifconfig',
        route: 'route',
        lsof: 'lsof',
      },
    });
  }
  throw fail('EUNSUPPORTED', `Unsupported OS: ${requested}`);
}

module.exports = { getPlatform, resolveOs };
