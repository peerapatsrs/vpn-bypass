'use strict';

const path = require('path');
const { execFile } = require('child_process');

const SAFE_UNIX_PATH = '/usr/sbin:/sbin:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin';
const SAFE_WIN32_PATH = [
  process.env.SystemRoot ? path.join(process.env.SystemRoot, 'System32') : 'C:\\Windows\\System32',
  process.env.SystemRoot ? process.env.SystemRoot : 'C:\\Windows',
  process.env.SystemRoot ? path.join(process.env.SystemRoot, 'System32', 'Wbem') : 'C:\\Windows\\System32\\Wbem',
  process.env.SystemRoot ? path.join(process.env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0') : 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
].join(';');

function execEnv(extra) {
  const env = { ...process.env, ...(extra || {}) };
  const delimiter = path.delimiter;
  const safe = process.platform === 'win32' ? SAFE_WIN32_PATH : SAFE_UNIX_PATH;
  const merged = `${safe}${delimiter}${env.PATH || ''}`
    .split(delimiter)
    .filter(Boolean);
  env.PATH = [...new Set(merged)].join(delimiter);
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
