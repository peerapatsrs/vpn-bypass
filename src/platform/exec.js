'use strict';

const { execFile } = require('child_process');

const SAFE_PATH = '/usr/sbin:/sbin:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin';

function execEnv(extra) {
  const env = { ...process.env, ...(extra || {}) };
  const merged = `${SAFE_PATH}:${env.PATH || ''}`
    .split(':')
    .filter(Boolean);
  env.PATH = [...new Set(merged)].join(':');
  return env;
}

function createExec(custom) {
  if (typeof custom === 'function') return custom;
  return function exec(file, args = [], opts = {}) {
    if (!Array.isArray(args) || args.some((a) => typeof a !== 'string')) {
      return Promise.reject(new TypeError('exec args must be a string array'));
    }
    return new Promise((resolve, reject) => {
      execFile(file, args, {
        encoding: 'utf8',
        timeout: opts.timeout ?? 20000,
        maxBuffer: 4 * 1024 * 1024,
        windowsHide: true,
        env: execEnv(opts.env),
      }, (err, stdout, stderr) => {
        if (err) {
          err.stdout = stdout || '';
          err.stderr = stderr || '';
          reject(err);
          return;
        }
        resolve({ stdout: stdout || '', stderr: stderr || '', code: 0 });
      });
    });
  };
}

function isAlreadyExists(err) {
  const s = `${err && err.stdout || ''} ${err && err.stderr || ''} ${err && err.message || ''}`.toLowerCase();
  return s.includes('file exists') || s.includes('already exists') || s.includes('object already exists');
}

function isNotInTable(err) {
  const s = `${err && err.stdout || ''} ${err && err.stderr || ''} ${err && err.message || ''}`.toLowerCase();
  return (
    s.includes('not in table')
    || s.includes('no such process')
    || s.includes('cannot find')
    || s.includes('element not found')
    || s.includes('not found')
    || (err && err.code === 'ESRCH')
  );
}

module.exports = { createExec, isAlreadyExists, isNotInTable, execEnv };
