'use strict';

const MAX = 250;
const items = [];

function record(level, message, extra) {
  items.push({
    ts: new Date().toISOString(),
    level: level || 'info',
    message: String(message || ''),
    extra: extra == null ? null : extra,
  });
  if (items.length > MAX) items.splice(0, items.length - MAX);
}

function list() {
  return items.slice();
}

function reset() {
  items.length = 0;
}

module.exports = { record, list, reset };
