#!/usr/bin/env node
'use strict';

const { main } = require('../src/run');

main(process.argv.slice(2)).then((code) => {
  if (typeof code === 'number' && code !== 0) process.exit(code);
}).catch((err) => {
  const msg = err && err.message ? err.message : String(err);
  process.stderr.write(`${msg}\n`);
  process.exit(1);
});
