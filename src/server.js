'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { fail, httpStatus, AppError } = require('./core/errors');
const { t } = require('./i18n');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.txt': 'text/plain; charset=utf-8',
};

function isLoopbackHost(host) {
  const h = String(host || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  return h === '127.0.0.1' || h === '::1' || h === 'localhost';
}

function assertLoopbackHost(host) {
  if (!isLoopbackHost(host)) {
    throw fail('ENOTLOOPBACK', 'Listen address must be loopback (127.0.0.1)', { http: 400 });
  }
}

function escapeAttr(value) {
  return String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}

function injectHtml(html, { token, locale }) {
  const script = `<script>window.__VPN_BYPASS_TOKEN__=${JSON.stringify(token)};window.__VPN_BYPASS_LOCALE__=${JSON.stringify(locale || 'th')};</script>`;
  let out = String(html);
  if (/<meta\s+name=["']vpn-bypass-token["'][^>]*>/i.test(out)) {
    out = out.replace(
      /<meta\s+name=["']vpn-bypass-token["'][^>]*>/i,
      `<meta name="vpn-bypass-token" content="${escapeAttr(token)}">`,
    );
  } else if (out.includes('</head>')) {
    out = out.replace('</head>', `<meta name="vpn-bypass-token" content="${escapeAttr(token)}">\n</head>`);
  }
  if (out.includes('</head>')) return out.replace('</head>', `${script}\n</head>`);
  return `${script}\n${out}`;
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(payload);
}

function sendErr(res, err, locale) {
  const code = (err && err.code) || 'EFAIL';
  const message = code === 'EINVAL' && err && err.message
    ? t(locale, 'error.EINVAL', { message: err.message.replace(/^Invalid input: /, '') })
    : t(locale, `error.${code}`, { message: err && err.message ? err.message : '', host: (err && err.extra && err.extra.host) || '' });
  sendJson(res, err && err.http || httpStatus(code), {
    ok: false,
    error: { code, message },
  });
}

function sendOk(res, data) {
  sendJson(res, 200, { ok: true, data: data == null ? {} : data });
}

function readBody(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n > limit) {
        reject(fail('EINVAL', 'body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function parseJsonBody(req) {
  const raw = await readBody(req);
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw fail('EINVAL', 'invalid JSON');
  }
}

function authorize(req, token, port) {
  const got = req.headers['x-vpn-bypass-token'];
  if (!got || got !== token) {
    throw fail('EAUTH', 'missing or invalid token', { http: 401 });
  }
  const host = String(req.headers.host || '');
  if (host !== `127.0.0.1:${port}`) {
    throw fail('EORIGIN', 'invalid Host', { http: 403 });
  }
  const origin = req.headers.origin;
  if (origin != null && origin !== '' && origin !== `http://127.0.0.1:${port}`) {
    throw fail('EORIGIN', 'invalid Origin', { http: 403 });
  }
}

function safeJoin(root, rel) {
  const cleaned = String(rel || '').replace(/^\/+/, '');
  const resolved = path.resolve(root, cleaned);
  const rootReal = path.resolve(root);
  if (resolved !== rootReal && !resolved.startsWith(rootReal + path.sep)) {
    throw fail('EINVAL', 'invalid path', { http: 403 });
  }
  return resolved;
}

async function serveStatic(req, res, uiDir, { token, locale }) {
  let rel = new URL(req.url, 'http://127.0.0.1').pathname;
  if (rel === '/') rel = '/index.html';
  const filePath = safeJoin(uiDir, rel);
  let data;
  try {
    data = fs.readFileSync(filePath);
  } catch (err) {
    if (rel === '/index.html') {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('vpn-bypass UI is not installed in ui/');
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('not found');
    return;
  }
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.html') {
    const html = injectHtml(data.toString('utf8'), { token, locale });
    res.writeHead(200, { 'Content-Type': MIME['.html'], 'Cache-Control': 'no-store' });
    res.end(html);
    return;
  }
  res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
  res.end(data);
}

async function routeApi(req, service, url) {
  const method = req.method || 'GET';
  const p = url.pathname.replace(/\/+$/, '') || '/';

  if (p === '/api/status' && method === 'GET') return service.getStatus();
  if (p === '/api/ips' && method === 'GET') return service.getIps();
  if (p === '/api/config' && method === 'GET') return service.getConfig();
  if (p === '/api/config' && method === 'PUT') {
    const body = await parseJsonBody(req);
    return service.putConfig(body);
  }
  if (p === '/api/on' && method === 'POST') {
    const body = await parseJsonBody(req);
    return service.on({ mode: body.mode, dryRun: Boolean(body.dryRun) });
  }
  if (p === '/api/off' && method === 'POST') {
    await parseJsonBody(req);
    return service.off();
  }
  if (p === '/api/domains' && method === 'GET') {
    return { domains: service.listDomains() };
  }
  if (p === '/api/domains' && method === 'POST') {
    const body = await parseJsonBody(req);
    const host = body.host || body.domain;
    const domains = await service.addDomain(host);
    return { domains };
  }
  if (p === '/api/domains' && method === 'DELETE') {
    const body = await parseJsonBody(req);
    const host = body.host || body.domain || url.searchParams.get('host');
    const domains = await service.removeDomain(host);
    return { domains };
  }
  if (p === '/api/try' && method === 'POST') {
    const body = await parseJsonBody(req);
    return service.tryHost(body.host);
  }
  if (p === '/api/allow' && method === 'POST') {
    const body = await parseJsonBody(req);
    return service.allowHost(body.host);
  }
  if (p === '/api/deny' && method === 'POST') {
    const body = await parseJsonBody(req);
    return service.denyHost(body.host);
  }
  if (p === '/api/watch' && method === 'POST') {
    const body = await parseJsonBody(req);
    return service.setWatch(Boolean(body.enabled));
  }
  if (p === '/api/log' && method === 'GET') {
    return { entries: service.getLog() };
  }
  if (p === '/api/lookup' && method === 'POST') {
    const body = await parseJsonBody(req);
    return service.lookupHost(body.host);
  }
  if (p === '/api/traffic' && method === 'GET') {
    return service.getTraffic();
  }
  throw fail('EINVAL', `unknown route ${method} ${p}`, { http: 404 });
}

function createServer(opts = {}) {
  const host = opts.host || '127.0.0.1';
  assertLoopbackHost(host);
  if (Object.prototype.hasOwnProperty.call(opts, 'envHost') && opts.envHost) {
    // tests can pass process.env.HOST explicitly; production ignores HOST
  }
  const service = opts.service;
  if (!service) throw new Error('service required');
  const token = opts.token || crypto.randomBytes(24).toString('hex');
  const uiDir = opts.uiDir || path.join(__dirname, '../ui');

  const server = http.createServer(async (req, res) => {
    const locale = service.locale();
    try {
      const url = new URL(req.url, 'http://127.0.0.1');
      if (url.pathname.startsWith('/api/')) {
        const addr = server.address();
        const port = addr && addr.port;
        authorize(req, token, port);
        const data = await routeApi(req, service, url);
        sendOk(res, data);
        return;
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        throw fail('EINVAL', 'method not allowed', { http: 405 });
      }
      await serveStatic(req, res, uiDir, { token, locale });
    } catch (err) {
      if (!(err instanceof AppError) && err && err.code !== 'EAUTH') {
        sendErr(res, fail('EFAIL', 'internal error'), locale);
        return;
      }
      sendErr(res, err, locale);
    }
  });

  function listen(port) {
    return new Promise((resolve, reject) => {
      const onErr = (err) => reject(err);
      server.once('error', onErr);
      server.listen(port, host, () => {
        server.removeListener('error', onErr);
        const addr = server.address();
        if (!addr || !isLoopbackHost(addr.address)) {
          server.close();
          reject(fail('ENOTLOOPBACK', 'server bound to a non-loopback address'));
          return;
        }
        resolve({ host: addr.address, port: addr.port, token });
      });
    });
  }

  async function listenPreferred(preferred = 18787) {
    try {
      return await listen(preferred);
    } catch (err) {
      if (err && err.code === 'EADDRINUSE') return listen(0);
      throw err;
    }
  }

  return {
    server, token, host, uiDir, listen, listenPreferred, assertLoopbackHost,
  };
}

async function startServer(opts = {}) {
  const host = opts.host || '127.0.0.1';
  assertLoopbackHost(host);
  const created = createServer({ ...opts, host });
  const info = await created.listenPreferred(opts.port == null ? 18787 : opts.port);
  return { ...created, ...info };
}

module.exports = {
  createServer,
  startServer,
  assertLoopbackHost,
  isLoopbackHost,
  injectHtml,
  authorize,
};
