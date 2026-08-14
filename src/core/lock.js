'use strict';

const fs = require('fs');
const { fail } = require('./errors');

function pidAlive(pid) {
  if (!pid || !Number.isInteger(pid)) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

async function withLock(lockPath, fn) {
  fs.mkdirSync(require('path').dirname(lockPath), { recursive: true });
  let fd;
  try {
    fd = fs.openSync(lockPath, 'wx');
  } catch (err) {
    if (err.code === 'EEXIST') {
      try {
        const raw = fs.readFileSync(lockPath, 'utf8').trim();
        const pid = Number(raw);
        if (!pidAlive(pid)) {
          fs.unlinkSync(lockPath);
          fd = fs.openSync(lockPath, 'wx');
        }
      } catch {
        // fall through
      }
    }
    if (fd == null) throw fail('ELOCK', 'apply lock is held');
  }
  try {
    fs.writeFileSync(fd, String(process.pid));
    return await fn();
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      // ignore
    }
    try {
      fs.unlinkSync(lockPath);
    } catch {
      // ignore
    }
  }
}

module.exports = { withLock, pidAlive };
