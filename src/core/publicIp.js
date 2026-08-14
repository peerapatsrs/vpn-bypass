'use strict';

const https = require('https');

const ENDPOINTS = [
  { hostname: 'api.ipify.org', path: '/', port: 443 },
  { hostname: 'icanhazip.com', path: '/', port: 443 },
  { hostname: 'ifconfig.me', path: '/ip', port: 443 },
];

function fetchText(endpoint, localAddress, timeout = 4000) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: endpoint.hostname,
      path: endpoint.path,
      port: endpoint.port,
      method: 'GET',
      localAddress,
      timeout,
      headers: { Accept: 'text/plain' },
    }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400) {
        res.resume();
        reject(new Error('redirect'));
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('timeout'));
    });
    req.on('error', reject);
    req.end();
  });
}

function parseIp(text) {
  const m = String(text || '').trim().match(/(\d{1,3}\.){3}\d{1,3}/);
  return m ? m[0] : null;
}

async function publicIpVia(localAddress, fetchImpl) {
  const fetch = fetchImpl || fetchText;
  let lastErr = null;
  for (const ep of ENDPOINTS) {
    try {
      const body = await fetch(ep, localAddress);
      const ip = parseIp(body);
      if (ip) return { ip, error: null, endpoint: ep.hostname };
    } catch (err) {
      lastErr = err;
    }
  }
  return { ip: null, error: lastErr ? lastErr.message : 'unavailable', endpoint: null };
}

async function getPublicIps(detect, fetchImpl) {
  const lanAddr = detect && detect.lan && detect.lan.addr ? detect.lan.addr : undefined;
  const vpnAddr = detect && detect.vpn && detect.vpn.addr ? detect.vpn.addr : undefined;
  const [lan, vpn] = await Promise.all([
    lanAddr ? publicIpVia(lanAddr, fetchImpl) : Promise.resolve({ ip: null, error: 'no LAN address', endpoint: null }),
    vpnAddr ? publicIpVia(vpnAddr, fetchImpl) : Promise.resolve({ ip: null, error: 'no VPN address', endpoint: null }),
  ]);
  return {
    lan: lan.ip,
    vpn: vpn.ip,
    lanIp: lan.ip,
    vpnIp: vpn.ip,
    error: (!lan.ip && !vpn.ip) ? (lan.error || vpn.error) : null,
    lanResult: lan,
    vpnResult: vpn,
  };
}

module.exports = { ENDPOINTS, getPublicIps, publicIpVia, parseIp };
