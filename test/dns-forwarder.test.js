'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('dgram');
const { createForwarder, decodeQname } = require('../src/core/dnsForwarder');

function encodeQuery(name, type = 1, id = 0x1234) {
  const labels = String(name).split('.').filter(Boolean);
  const parts = [Buffer.from([id >> 8, id & 0xff, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])];
  for (const lab of labels) {
    const b = Buffer.from(lab);
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0, 0, type >> 8, type & 0xff, 0, 1]));
  return Buffer.concat(parts);
}

function bindUdp() {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    sock.once('error', reject);
    sock.bind(0, '127.0.0.1', () => {
      sock.removeListener('error', reject);
      resolve({ sock, port: sock.address().port });
    });
  });
}

describe('local DNS forwarder', () => {
  it('decodes QNAME from a query packet', () => {
    const pkt = encodeQuery('facebook.com');
    assert.equal(decodeQname(pkt), 'facebook.com');
  });

  it('forwards facebook.com to LAN DNS and corp suffix / PTR to VPN DNS', async () => {
    const lanGot = [];
    const vpnGot = [];
    const lan = await bindUdp();
    const vpn = await bindUdp();
    lan.sock.on('message', (msg, rinfo) => {
      lanGot.push(decodeQname(msg));
      const resp = Buffer.from(msg);
      resp[2] = 0x81;
      resp[3] = 0x80;
      lan.sock.send(resp, rinfo.port, rinfo.address);
    });
    vpn.sock.on('message', (msg, rinfo) => {
      vpnGot.push(decodeQname(msg));
      const resp = Buffer.from(msg);
      resp[2] = 0x81;
      resp[3] = 0x80;
      vpn.sock.send(resp, rinfo.port, rinfo.address);
    });

    const fwd = createForwarder({
      listen: '127.0.0.1',
      port: 0,
      lanServers: [`127.0.0.1:${lan.port}`],
      vpnServers: [`127.0.0.1:${vpn.port}`],
      suffixes: ['corp.example'],
    });
    const addr = await fwd.start();
    const client = dgram.createSocket('udp4');
    try {
      await new Promise((resolve, reject) => {
        client.send(encodeQuery('facebook.com', 1, 1), addr.port, '127.0.0.1', (err) => (err ? reject(err) : resolve()));
      });
      await new Promise((resolve, reject) => {
        client.send(encodeQuery('jira.corp.example', 1, 2), addr.port, '127.0.0.1', (err) => (err ? reject(err) : resolve()));
      });
      await new Promise((resolve, reject) => {
        client.send(encodeQuery('1.1.168.192.in-addr.arpa', 12, 3), addr.port, '127.0.0.1', (err) => (err ? reject(err) : resolve()));
      });
      const deadline = Date.now() + 1000;
      while (Date.now() < deadline && (lanGot.length < 1 || vpnGot.length < 2)) {
        await new Promise((resolve) => setTimeout(resolve, 15));
      }
      assert.deepEqual(lanGot, ['facebook.com']);
      assert.ok(vpnGot.includes('jira.corp.example'));
      assert.ok(vpnGot.includes('1.1.168.192.in-addr.arpa'));
      assert.equal(fwd.pickUpstream('aaaa.example'), fwd.cfg.lanServers[0]);
    } finally {
      client.close();
      fwd.stop();
      lan.sock.close();
      vpn.sock.close();
    }
  });

  it('refuses to listen on a non-loopback address', () => {
    assert.throws(() => createForwarder({ listen: '0.0.0.0', lanServers: ['192.168.1.1'] }));
  });
});
