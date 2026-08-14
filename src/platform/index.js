'use strict';

const { fail } = require('../core/errors');
const { createExec } = require('./exec');

function getPlatform(opts = {}) {
  const osName = opts.os || process.platform;
  const exec = createExec(opts.exec);
  let mod;
  if (osName === 'darwin') mod = require('./darwin');
  else if (osName === 'linux') mod = require('./linux');
  else if (osName === 'win32') mod = require('./win32');
  else throw fail('EUNSUPPORTED', `Unsupported OS: ${osName}`);
  return mod.create(exec, opts);
}

module.exports = { getPlatform };
