'use strict';

const { fail } = require('./core/errors');

const COMMANDS = new Set([
  'status', 'on', 'off', 'domain', 'try', 'allow', 'deny', 'watch', 'ui', 'lang', 'lookup', 'help',
  'elevate-helper',
]);

function parseArgv(argv) {
  const out = {
    lang: null,
    command: null,
    args: [],
    flags: {
      mode: null,
      dryRun: false,
      help: false,
      version: false,
    },
  };
  const args = Array.from(argv || []);
  while (args.length) {
    const a = args.shift();
    if (a === '--lang' || a === '-l') {
      out.lang = args.shift() || '';
    } else if (a.startsWith('--lang=')) {
      out.lang = a.slice('--lang='.length);
    } else if (a === '--mode') {
      out.flags.mode = args.shift() || '';
    } else if (a.startsWith('--mode=')) {
      out.flags.mode = a.slice('--mode='.length);
    } else if (a === '--dry-run') {
      out.flags.dryRun = true;
    } else if (a === '--help' || a === '-h') {
      out.flags.help = true;
    } else if (a === '--version' || a === '-v') {
      out.flags.version = true;
    } else if (a.startsWith('-')) {
      throw fail('EINVAL', `unknown flag: ${a}`, { flag: a });
    } else if (!out.command) {
      out.command = a;
    } else {
      out.args.push(a);
    }
  }
  if (out.flags.mode && out.flags.mode !== 'inverse' && out.flags.mode !== 'domains') {
    throw fail('EINVAL', `invalid mode: ${out.flags.mode}`);
  }
  if (out.command && !COMMANDS.has(out.command)) {
    throw fail('EINVAL', `unknown command: ${out.command}`, { command: out.command });
  }
  return out;
}

module.exports = { parseArgv, COMMANDS };
