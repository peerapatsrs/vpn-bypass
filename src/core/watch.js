'use strict';

function createWatch() {
  let timer = null;
  let running = false;

  function stop() {
    running = false;
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  function start(tick, intervalMs, { unref } = {}) {
    stop();
    running = true;
    timer = setInterval(() => {
      if (!running) return;
      Promise.resolve()
        .then(() => tick())
        .catch(() => {});
    }, intervalMs || 8000);
    if (unref && timer.unref) timer.unref();
  }

  function isRunning() {
    return running && timer != null;
  }

  return { start, stop, isRunning };
}

module.exports = { createWatch };
