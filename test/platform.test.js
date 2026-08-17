'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const darwin = require('../src/platform/darwin');
const linux = require('../src/platform/linux');
const win32 = require('../src/platform/win32');
const {
  parseDarwinNetstat,
  parseDarwinNetstat6,
  parseIfconfig,
  parseLinuxIpRoute,
  parseLinuxIpRoute6,
  parseLinuxIpAddr,
  inferTopology,
  inferIpv6,
  isVpnIface,
  isWifiIface,
  isLanIface,
  parseWin32NetRoute,
} = require('../src/platform/common');
const { getPlatform, resolveOs } = require('../src/platform');
const { decodeExecOutput, createExec } = require('../src/platform/exec');
const { recordingExec, tmpHome, sampleDetect } = require('./helpers');
const { getPaths } = require('../src/core/config');

const FIX = path.join(__dirname, 'fixtures');

describe('parse fixtures', () => {
  it('parses darwin netstat + ifconfig and finds LAN gw despite inactive default', () => {
    const routes = parseDarwinNetstat(fs.readFileSync(path.join(FIX, 'darwin/netstat-rn.txt'), 'utf8'));
    const ifaces = parseIfconfig(fs.readFileSync(path.join(FIX, 'darwin/ifconfig.txt'), 'utf8'));
    const detect = inferTopology(routes, ifaces, 'darwin');
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.vpn.iface, 'utun6');
    assert.equal(detect.vpn.addr, '10.243.1.92');
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.equal(detect.lan.iface, 'en0');
    assert.equal(detect.lan.network, '192.168.1.0');
    assert.ok(detect.vpn.cidrs.some((c) => c.dest === '10.10.0.0' && c.prefix === 16));
    assert.equal(darwin.parseRoutes === parseDarwinNetstat || typeof darwin.parseRoutes === 'function', true);
  });

  it('parses linux ip route/addr', () => {
    const routes = parseLinuxIpRoute(fs.readFileSync(path.join(FIX, 'linux/ip-route.txt'), 'utf8'));
    const ifaces = parseLinuxIpAddr(fs.readFileSync(path.join(FIX, 'linux/ip-addr.txt'), 'utf8'));
    const detect = inferTopology(routes, ifaces, 'linux');
    assert.equal(detect.vpn.iface, 'tun0');
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.equal(detect.lan.addr, '192.168.1.42');
    assert.equal(typeof linux.parseRoutes, 'function');
  });

  it('detects linux VPN on unnamed eth1 vs 192.168 ens192', () => {
    const routes = parseLinuxIpRoute(fs.readFileSync(path.join(FIX, 'linux/ip-route-unnamed.txt'), 'utf8'));
    const ifaces = parseLinuxIpAddr(fs.readFileSync(path.join(FIX, 'linux/ip-addr-unnamed.txt'), 'utf8'));
    const detect = inferTopology(routes, ifaces, 'linux');
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.vpn.iface, 'eth1');
    assert.equal(detect.vpn.addr, '10.243.1.92');
    assert.equal(detect.lan.iface, 'ens192');
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.equal(detect.lan.addr, '192.168.1.42');
    assert.equal(isVpnIface('eth1'), false);
    assert.equal(isVpnIface('ens192'), false);
  });

  it('recovers linux LAN when the only default is unnamed eth1', () => {
    const routes = parseLinuxIpRoute(fs.readFileSync(path.join(FIX, 'linux/ip-route-fulltunnel-unnamed.txt'), 'utf8'));
    const ifaces = parseLinuxIpAddr(fs.readFileSync(path.join(FIX, 'linux/ip-addr-unnamed.txt'), 'utf8'));
    const detect = inferTopology(routes, ifaces, 'linux');
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.vpn.iface, 'eth1');
    assert.equal(detect.lan.iface, 'ens192');
    assert.equal(detect.lan.addr, '192.168.1.42');
    assert.equal(detect.lan.gw, '192.168.1.1');
  });

  it('does not treat linux hypervisor 10.211.55-only as VPN', () => {
    const routes = parseLinuxIpRoute(fs.readFileSync(path.join(FIX, 'linux/ip-route-hypervisor-novpn.txt'), 'utf8'));
    const ifaces = parseLinuxIpAddr(fs.readFileSync(path.join(FIX, 'linux/ip-addr-hypervisor.txt'), 'utf8'));
    const detect = inferTopology(routes, ifaces, 'linux');
    assert.equal(detect.vpn.up, false);
    assert.equal(detect.lan.gw, '10.211.55.1');
    assert.equal(detect.lan.addr, '10.211.55.9');
  });

  it('detects darwin VPN on en8 without utun in the name', () => {
    const routes = parseDarwinNetstat(fs.readFileSync(path.join(FIX, 'darwin/netstat-rn-unnamed.txt'), 'utf8'));
    const ifaces = parseIfconfig(fs.readFileSync(path.join(FIX, 'darwin/ifconfig-unnamed.txt'), 'utf8'));
    const detect = inferTopology(routes, ifaces, 'darwin');
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.vpn.iface, 'en8');
    assert.equal(detect.vpn.addr, '10.243.1.92');
    assert.equal(detect.lan.iface, 'en0');
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.equal(isVpnIface('en8'), false);
  });

  it('parses darwin inet6 netstat and infers LAN gw6', () => {
    const v4 = parseDarwinNetstat(fs.readFileSync(path.join(FIX, 'darwin/netstat-rn.txt'), 'utf8'));
    const v6 = parseDarwinNetstat6(fs.readFileSync(path.join(FIX, 'darwin/netstat-rn-inet6.txt'), 'utf8'));
    const ifaces = parseIfconfig(fs.readFileSync(path.join(FIX, 'darwin/ifconfig.txt'), 'utf8'));
    assert.ok(v6.some((r) => r.dest === '::' && r.prefix === 1 && r.family === 'inet6'));
    assert.ok(v6.some((r) => r.dest === '8000::' && r.prefix === 1));
    const topo = inferIpv6(v6, inferTopology(v4, ifaces, 'darwin'));
    assert.equal(topo.lan.gw6, 'fe80::1%en0');
  });

  it('parses linux inet6 routes and infers LAN gw6', () => {
    const v4 = parseLinuxIpRoute(fs.readFileSync(path.join(FIX, 'linux/ip-route.txt'), 'utf8'));
    const v6 = parseLinuxIpRoute6(fs.readFileSync(path.join(FIX, 'linux/ip-route-inet6.txt'), 'utf8'));
    const ifaces = parseLinuxIpAddr(fs.readFileSync(path.join(FIX, 'linux/ip-addr.txt'), 'utf8'));
    const topo = inferIpv6(v6, inferTopology(v4, ifaces, 'linux'));
    assert.equal(topo.lan.gw6, 'fe80::1');
    assert.ok(v6.some((r) => r.dest === '::' && r.prefix === 1));
  });

  it('darwin addCidr changes existing /1 and never deletes default 0/0', async () => {
    const exec = recordingExec(async (_file, args) => {
      if (args.includes('add')) {
        const err = new Error('File exists');
        err.stderr = 'File exists';
        throw err;
      }
      return { stdout: '', stderr: '' };
    });
    const platform = darwin.create(exec, { isAdmin: async () => true, getuid: () => 0 });
    await platform.addCidr({ dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1', kind: 'split', family: 'inet' });
    const joined = exec.calls.map((c) => c.args.join(' '));
    assert.ok(joined.some((j) => j.includes('add') && j.includes('0.0.0.0/1')));
    assert.ok(joined.some((j) => j.includes('change') && j.includes('0.0.0.0/1')));
    assert.equal(joined.some((j) => /\bdelete\b/.test(j)), false);
    await platform.addCidr({ dest: '::', prefix: 1, gw: 'fe80::1%en0', kind: 'split', family: 'inet6' });
    assert.ok(exec.calls.some((c) => c.args.includes('-inet6') && c.args.includes('change')));
  });

  it('parses windows route print', () => {
    const text = fs.readFileSync(path.join(FIX, 'win32/route-print.txt'), 'utf8');
    const routes = win32.parseRoutes(text);
    assert.ok(routes.some((r) => r.dest === '0.0.0.0' && r.gw === '192.168.1.1'));
    assert.ok(routes.some((r) => r.dest === '0.0.0.0' && r.gw === '10.243.1.1'));
    const detect = win32.detectFromPrint(text);
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.equal(detect.vpn.up, true);
  });

  it('treats Windows Wi-Fi as LAN when VPN is a generic Ethernet adapter', () => {
    const text = fs.readFileSync(path.join(FIX, 'win32/route-print-wifi.txt'), 'utf8');
    const ipconfig = fs.readFileSync(path.join(FIX, 'win32/ipconfig-wifi.txt'), 'utf8');
    const detect = win32.detectFromPrint(text, ipconfig);
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.equal(detect.lan.iface, 'Wi-Fi');
    assert.equal(detect.lan.addr, '192.168.1.42');
    assert.notEqual(detect.lan.iface, 'Ethernet 3');
    assert.equal(detect.vpn.iface, 'Ethernet 3');
    assert.equal(isVpnIface('Wi-Fi'), false);
    assert.equal(isWifiIface('Wi-Fi'), true);
    assert.equal(isLanIface('Wi-Fi'), true);
    assert.equal(isWifiIface('Microsoft Wi-Fi Direct Virtual Adapter'), false);
  });

  it('detects common full-tunnel VPN adapter names and ignores LAN nics', () => {
    for (const name of [
      'utun6', 'tun0', 'tap0', 'wg0', 'gpd0', 'cscotun0', 'PANGP Virtual Ethernet Adapter',
      'Wintun', 'NordLynx', 'Cisco AnyConnect', 'FortiSSL', 'OpenVPN TAP-Windows6',
      'WAN Miniport (IKEv2)', 'Cloudflare WARP', 'Tailscale Tunnel', 'ZeroTier One',
      'Mullvad', 'ProtonVPN', 'Zscaler', 'Pulse Secure',
    ]) {
      assert.equal(isVpnIface(name), true, name);
    }
    for (const name of ['Wi-Fi', 'Ethernet', 'Ethernet 3', 'en0', 'en8', 'eth1', 'ens192', 'wlan0', 'Parallels VirtIO Ethernet Adapter']) {
      assert.equal(isVpnIface(name), false, name);
    }
  });

  it('treats Windows WLAN as LAN without a named VPN adapter', () => {
    const text = fs.readFileSync(path.join(FIX, 'win32/route-print-wlan.txt'), 'utf8');
    const detect = win32.detectFromPrint(text);
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.lan.iface, 'WLAN');
    assert.equal(detect.lan.gw, '192.168.0.1');
    assert.equal(isWifiIface('WLAN'), true);
    assert.equal(isVpnIface('Ethernet 2'), false);
  });

  it('detects VPN on generic Local Area Connection names', () => {
    const text = fs.readFileSync(path.join(FIX, 'win32/route-print-generic.txt'), 'utf8');
    const detect = win32.detectFromPrint(text);
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.equal(detect.lan.addr, '192.168.1.42');
  });

  it('recovers LAN from on-link + ipconfig when VPN stole the only default', () => {
    const text = fs.readFileSync(path.join(FIX, 'win32/route-print-fulltunnel.txt'), 'utf8');
    const ipconfig = fs.readFileSync(path.join(FIX, 'win32/ipconfig-fulltunnel.txt'), 'utf8');
    const detect = win32.detectFromPrint(text, ipconfig);
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.equal(detect.lan.iface, 'Killer Wireless-n');
    assert.equal(detect.lan.addr, '192.168.1.42');
  });

  it('splits 10.x home LAN /24 from 10.x VPN /32 without relying on names', () => {
    const text = fs.readFileSync(path.join(FIX, 'win32/route-print-10lan.txt'), 'utf8');
    const detect = win32.detectFromPrint(text);
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.lan.gw, '10.0.0.1');
    assert.equal(detect.lan.addr, '10.0.0.50');
    assert.equal(detect.vpn.addr, '10.243.1.92');
  });

  it('parses Thai Windows route print headers', () => {
    const text = fs.readFileSync(path.join(FIX, 'win32/route-print-thai.txt'), 'utf8');
    const detect = win32.detectFromPrint(text);
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.equal(detect.lan.iface, 'Wi-Fi');
  });

  it('treats Parallels Shared Network as LAN when a 10.x /32 tunnel is also present', () => {
    const text = fs.readFileSync(path.join(FIX, 'win32/route-print-parallels.txt'), 'utf8');
    const ipconfig = fs.readFileSync(path.join(FIX, 'win32/ipconfig-parallels.txt'), 'utf8');
    const detect = win32.detectFromPrint(text, ipconfig);
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.vpn.addr, '10.243.1.92');
    assert.equal(detect.lan.gw, '10.211.55.1');
    assert.equal(detect.lan.addr, '10.211.55.9');
    assert.equal(detect.lan.iface, 'Ethernet');
  });

  it('does not treat Parallels Shared Network alone as VPN', () => {
    const text = fs.readFileSync(path.join(FIX, 'win32/route-print-parallels-novpn.txt'), 'utf8');
    const detect = win32.detectFromPrint(text);
    assert.equal(detect.vpn.up, false);
    assert.equal(detect.lan.gw, '10.211.55.1');
    assert.equal(detect.lan.addr, '10.211.55.9');
  });

  it('treats a public-IP VPN default next to 192.168 LAN as VPN', () => {
    const text = fs.readFileSync(path.join(FIX, 'win32/route-print-publicvpn.txt'), 'utf8');
    const detect = win32.detectFromPrint(text);
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.vpn.iface, '203.0.113.50');
    assert.equal(detect.vpn.addr, '203.0.113.50');
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.equal(detect.lan.addr, '192.168.1.42');
  });

  it('recovers 192.168 LAN when the only default is a public /24 tunnel', () => {
    const text = fs.readFileSync(path.join(FIX, 'win32/route-print-public-fulltunnel.txt'), 'utf8');
    const detect = win32.detectFromPrint(text);
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.vpn.iface, '203.0.113.50');
    assert.equal(detect.vpn.addr, '203.0.113.50');
    assert.equal(detect.lan.addr, '192.168.1.42');
    assert.equal(detect.lan.gw, '192.168.1.1');
  });

  it('strips NUL-padded route print so IPv4 defaults still parse', () => {
    const ascii = fs.readFileSync(path.join(FIX, 'win32/route-print-wifi.txt'), 'utf8');
    const padded = ascii.split('').join('\0');
    const decoded = decodeExecOutput(padded);
    assert.equal(decoded.includes('\0'), false);
    const detect = win32.detectFromPrint(padded);
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.lan.gw, '192.168.1.1');
  });

  it('decodes UTF-16LE route print buffers including a BOM', () => {
    const ascii = fs.readFileSync(path.join(FIX, 'win32/route-print-thai.txt'), 'utf8');
    const buf = Buffer.from(`\uFEFF${ascii}`, 'utf16le');
    const decoded = decodeExecOutput(buf);
    assert.equal(decoded.includes('\0'), false);
    assert.match(decoded, /0\.0\.0\.0/);
    const detect = win32.detectFromPrint(decoded);
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.lan.gw, '192.168.1.1');
  });

  it('parses Get-NetRoute line output as dual IPv4 defaults', () => {
    const text = fs.readFileSync(path.join(FIX, 'win32/get-netroute.txt'), 'utf8');
    const parsed = parseWin32NetRoute(text);
    assert.ok(parsed.routes.some((r) => r.dest === '0.0.0.0' && r.gw === '192.168.1.1'));
    assert.ok(parsed.routes.some((r) => r.dest === '0.0.0.0' && r.gw === '10.243.1.1'));
    const detect = win32.detectFromParsed(parsed, '');
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.vpn.iface, '10.243.1.92');
    assert.equal(detect.lan.gw, '192.168.1.1');
  });

  it('retries route print when -4 has no IPv4 defaults', async () => {
    const full = fs.readFileSync(path.join(FIX, 'win32/route-print-wifi.txt'), 'utf8');
    const exec = recordingExec(async (file, args) => {
      const base = path.basename(file).toLowerCase();
      if (base === 'route' && args.includes('-4')) {
        return { stdout: 'IPv4 Route Table\nActive Routes:\n  None\n', stderr: '' };
      }
      if (base === 'route') return { stdout: full, stderr: '' };
      return { stdout: '', stderr: '' };
    });
    const detect = await win32.create(exec).detect();
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.ok(exec.calls.some((c) => c.file === 'route' && c.args.includes('-4')));
    assert.ok(exec.calls.some((c) => c.file === 'route' && !c.args.includes('-4')));
  });

  it('falls back to Get-NetRoute when route print is empty', async () => {
    const ps = fs.readFileSync(path.join(FIX, 'win32/get-netroute.txt'), 'utf8');
    const exec = recordingExec(async (file, args) => {
      const base = path.basename(file).toLowerCase();
      if (base === 'route') return { stdout: '', stderr: '' };
      if (base === 'powershell' || base === 'powershell.exe') {
        assert.equal(args.includes('Get-NetRoute'), false);
        assert.ok(args.some((a) => a.includes('Get-NetRoute')));
        return { stdout: ps, stderr: '' };
      }
      return { stdout: '', stderr: '' };
    });
    const detect = await win32.create(exec).detect();
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.lan.gw, '192.168.1.1');
    assert.ok(exec.calls.some((c) => /powershell/i.test(c.file)));
  });

  it('detects VPN from UTF-16LE route print returned by exec', async () => {
    const ascii = fs.readFileSync(path.join(FIX, 'win32/route-print-wifi.txt'), 'utf8');
    const buf = Buffer.from(`\uFEFF${ascii}`, 'utf16le');
    const exec = recordingExec(async (file, args) => {
      const base = path.basename(file).toLowerCase();
      if (base === 'route' && args.includes('-4')) return { stdout: buf, stderr: Buffer.alloc(0) };
      return { stdout: '', stderr: '' };
    });
    const detect = await win32.create(exec).detect();
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.lan.gw, '192.168.1.1');
  });

  it('createExec decodes UTF-16LE buffers to parseable IPv4 text', async () => {
    const ascii = fs.readFileSync(path.join(FIX, 'win32/route-print-generic.txt'), 'utf8');
    const buf = Buffer.from(`\uFEFF${ascii}`, 'utf16le');
    const exec = createExec(async () => ({ stdout: buf, stderr: Buffer.alloc(0) }));
    const r = await exec('route', ['print', '-4']);
    assert.equal(r.stdout.includes('\0'), false);
    assert.match(r.stdout, /0\.0\.0\.0/);
    const detect = win32.detectFromPrint(r.stdout);
    assert.equal(detect.vpn.up, true);
  });

  it('darwin applyDns points system DNS at 127.0.0.1 and restore never leaves it', async () => {
    const scutil = fs.readFileSync(path.join(FIX, 'darwin/scutil-dns.txt'), 'utf8');
    const order = fs.readFileSync(path.join(FIX, 'darwin/networksetup-order.txt'), 'utf8');
    const exec = recordingExec(async (file, args) => {
      const base = path.basename(file);
      const joined = args.join(' ');
      if (base === 'scutil') return { stdout: scutil, stderr: '' };
      if (base === 'networksetup') {
        if (joined.includes('listnetworkserviceorder')) return { stdout: order, stderr: '' };
        if (joined.includes('getdnsservers')) return { stdout: '10.230.8.8\n', stderr: '' };
        if (joined.includes('getsearchdomains')) return { stdout: 'corp.example\n', stderr: '' };
        return { stdout: '', stderr: '' };
      }
      if (base === 'ps') return { stdout: 'node src/core/dnsForwarder.js dns-forwarder.json', stderr: '' };
      return { stdout: '', stderr: '' };
    });
    const home = tmpHome();
    const platform = darwin.create(exec, {
      isAdmin: async () => true,
      startForwarder: async () => 4242,
      stopForwarder: async () => {},
    });
    const owned = await platform.applyDns({ detect: sampleDetect(), paths: getPaths(home) });
    assert.equal(owned.mode, 'split');
    assert.equal(owned.listen, '127.0.0.1');
    assert.ok(exec.calls.some((c) => c.args.includes('-setdnsservers') && c.args.includes('127.0.0.1')));
    await platform.restoreDns(owned);
    const setCalls = exec.calls.filter((c) => c.args.includes('-setdnsservers'));
    const last = setCalls[setCalls.length - 1];
    assert.equal(last.args.includes('127.0.0.1'), false);
    assert.ok(last.args.includes('10.230.8.8') || last.args.includes('Empty'));
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('linux applyDns no-ops without resolvectl and does not rewrite resolv.conf', async () => {
    const exec = recordingExec(async () => {
      const err = new Error('not found');
      err.code = 'ENOENT';
      throw err;
    });
    const platform = linux.create(exec, { isAdmin: async () => true });
    const result = await platform.applyDns({ detect: sampleDetect() });
    assert.equal(result.mode, 'skipped');
    assert.equal(exec.calls.some((c) => c.joined.includes('resolv.conf')), false);
  });

  it('win32 applyDns does not call netsh dns', async () => {
    const exec = recordingExec();
    const platform = win32.create(exec, { isAdmin: async () => true });
    const result = await platform.applyDns({ detect: sampleDetect() });
    assert.equal(result.mode, 'unsupported');
    assert.equal(exec.calls.length, 0);
    assert.equal(exec.calls.some((c) => /netsh|set dns/i.test(c.joined)), false);
  });

  it('win32 addCidr uses route add mask gw and does not touch a live table', async () => {
    const exec = recordingExec(async () => ({ stdout: '', stderr: '' }));
    const platform = win32.create(exec, { isAdmin: async () => true });
    await platform.addCidr({ dest: '0.0.0.0', prefix: 1, gw: '192.168.1.1' });
    await platform.addHost({ dest: '1.1.1.1', gw: '192.168.1.1' });
    assert.deepEqual(exec.calls[0].args, ['add', '0.0.0.0', 'mask', '128.0.0.0', '192.168.1.1']);
    assert.deepEqual(exec.calls[1].args, ['add', '1.1.1.1', 'mask', '255.255.255.255', '192.168.1.1']);
  });

  it('linux detect uses shared topology for unnamed eth1', async () => {
    const routeTxt = fs.readFileSync(path.join(FIX, 'linux/ip-route-unnamed.txt'), 'utf8');
    const addrTxt = fs.readFileSync(path.join(FIX, 'linux/ip-addr-unnamed.txt'), 'utf8');
    const exec = recordingExec(async (file, args) => {
      const joined = [file, ...args].join(' ');
      if (joined.includes('route') && args.includes('-4')) return { stdout: routeTxt, stderr: '' };
      if (joined.includes('addr')) return { stdout: addrTxt, stderr: '' };
      return { stdout: '', stderr: '' };
    });
    const detect = await linux.create(exec).detect();
    assert.equal(detect.vpn.up, true);
    assert.equal(detect.vpn.iface, 'eth1');
    assert.equal(detect.lan.gw, '192.168.1.1');
  });

  it('maps android to linux and BSD to the darwin-like route adapter', () => {
    assert.equal(resolveOs('android'), 'linux');
    assert.equal(resolveOs('freebsd'), 'bsd');
    assert.equal(resolveOs('darwin'), 'darwin');
    const exec = recordingExec(async () => ({ stdout: '', stderr: '' }));
    assert.equal(typeof getPlatform({ os: 'android', exec, isAdmin: async () => true }).detect, 'function');
    assert.equal(typeof getPlatform({ os: 'freebsd', exec, isAdmin: async () => true }).detect, 'function');
    assert.throws(() => getPlatform({ os: 'aix', exec }), (err) => err.code === 'EUNSUPPORTED');
  });
});
