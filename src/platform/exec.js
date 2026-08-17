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

function stripNuls(text) {
  const s = String(text || '');
  return s.includes('\0') ? s.replace(/\0/g, '') : s;
}

function ipv4TokenCount(text) {
  return (String(text || '').match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || []).length;
}

function looksLikeUtf16Le(buf) {
  if (!buf || buf.length < 8) return false;
  if (buf[0] === 0xFF && buf[1] === 0xFE) return true;
  const needles = ['0.0.0.0', '127.0.0.1', 'IPv4', 'ipconfig', 'Wi-Fi', 'Ethernet', 'Active'];
  for (const s of needles) {
    if (buf.indexOf(Buffer.from(s, 'utf16le')) !== -1) return true;
  }
  const n = Math.min(buf.length - (buf.length % 2), 512);
  if (n < 16) return false;
  let nulHi = 0;
  for (let i = 0; i < n; i += 2) {
    if (buf[i + 1] === 0) nulHi += 1;
  }
  return nulHi / (n / 2) >= 0.7;
}

function decodeBuffer(buf) {
  if (!buf.length) return '';
  if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) {
    return stripNuls(buf.toString('utf16le').replace(/^\uFEFF/, ''));
  }
  if (buf.length >= 2 && buf[0] === 0xFE && buf[1] === 0xFF) {
    const swapped = Buffer.from(buf);
    swapped.swap16();
    return stripNuls(swapped.toString('utf16le').replace(/^\uFEFF/, ''));
  }
  if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) {
    return stripNuls(buf.toString('utf8').replace(/^\uFEFF/, ''));
  }
  if (looksLikeUtf16Le(buf)) {
    return stripNuls(buf.toString('utf16le').replace(/^\uFEFF/, ''));
  }
  const utf8 = stripNuls(buf.toString('utf8'));
  if (!utf8.includes('\uFFFD')) return utf8;
  const latin1 = stripNuls(buf.toString('latin1'));
  return ipv4TokenCount(latin1) > ipv4TokenCount(utf8) ? latin1 : utf8;
}

function decodeExecOutput(input) {
  if (input == null) return '';
  if (typeof input === 'string') return stripNuls(input);
  if (Buffer.isBuffer(input)) return decodeBuffer(input);
  if (ArrayBuffer.isView(input)) {
    return decodeBuffer(Buffer.from(input.buffer, input.byteOffset, input.byteLength));
  }
  return stripNuls(String(input));
}

function defaultExecFile(file, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, {
      encoding: 'buffer',
      timeout: opts.timeout ?? 20000,
      maxBuffer: 4 * 1024 * 1024,
      windowsHide: true,
      env: execEnv(opts.env),
    }, (err, stdout, stderr) => {
      if (err) {
        err.stdout = stdout;
        err.stderr = stderr;
        reject(err);
        return;
      }
      resolve({ stdout, stderr, code: 0 });
    });
  });
}

function createExec(custom) {
  const inner = typeof custom === 'function' ? custom : defaultExecFile;
  return function exec(file, args = [], opts = {}) {
    if (!Array.isArray(args) || args.some((a) => typeof a !== 'string')) {
      return Promise.reject(new TypeError('exec args must be a string array'));
    }
    return Promise.resolve()
      .then(() => inner(file, args, opts))
      .then((r) => ({
        stdout: decodeExecOutput(r && r.stdout),
        stderr: decodeExecOutput(r && r.stderr),
        code: r && r.code != null ? r.code : 0,
      }))
      .catch((err) => {
        if (err && typeof err === 'object') {
          err.stdout = decodeExecOutput(err.stdout);
          err.stderr = decodeExecOutput(err.stderr);
        }
        throw err;
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

module.exports = {
  createExec,
  decodeExecOutput,
  isAlreadyExists,
  isNotInTable,
  execEnv,
};
