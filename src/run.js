'use strict';

const readline = require('readline');
const { spawn } = require('child_process');
const { parseArgv } = require('./cli');
const { t, normalizeLocale } = require('./i18n');
const { Service } = require('./core/service');
const { startServer, assertLoopbackHost } = require('./server');
const { AppError, fail } = require('./core/errors');
const { createElevate } = require('./core/elevate');
const { runElevateHelper } = require('./core/helper');
const pkg = require('../package.json');

function print(msg) {
  process.stdout.write(`${msg}\n`);
}

function printErr(msg) {
  process.stderr.write(`${msg}\n`);
}

function formatError(locale, err) {
  const code = err && err.code ? err.code : 'EFAIL';
  if (code === 'EINVAL') {
    return t(locale, 'error.EINVAL', { message: err.message || '' });
  }
  return t(locale, `error.${code}`, {
    message: err && err.message ? err.message : '',
    host: err && err.extra && err.extra.host ? err.extra.host : '',
  });
}

function confirmPrompt(question) {
  if (!process.stdin.isTTY) return Promise.resolve(false);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(/^\s*y(es)?\s*$/i.test(answer || ''));
    });
  });
}

function openBrowser(url) {
  let child;
  if (process.platform === 'darwin') {
    child = spawn('open', [url], { detached: true, stdio: 'ignore' });
  } else if (process.platform === 'win32') {
    child = spawn('cmd.exe', ['/c', 'start', '', url], { detached: true, stdio: 'ignore', windowsHide: true });
  } else {
    child = spawn('xdg-open', [url], { detached: true, stdio: 'ignore' });
  }
  child.unref();
}

function formatDns(locale, dns) {
  if (!dns || !dns.mode) return t(locale, 'status.dns.none');
  const modeKey = `status.dns.${dns.mode}`;
  let line = t(locale, modeKey);
  if (line === modeKey) line = String(dns.mode);
  const bits = [];
  if (dns.listen) bits.push(dns.listen);
  if (dns.lanServers && dns.lanServers.length) bits.push(`LAN ${dns.lanServers.join(',')}`);
  if (dns.vpnServers && dns.vpnServers.length) bits.push(`VPN ${dns.vpnServers.join(',')}`);
  if (dns.suffixes && dns.suffixes.length) bits.push(dns.suffixes.join(','));
  if (bits.length) line += ` (${bits.join('; ')})`;
  if (dns.hijacked) line += ` — ${t(locale, 'status.hijacked')}`;
  return line;
}

function yn(locale, v) {
  return v ? t(locale, 'status.yes') : t(locale, 'status.no');
}

function formatStatus(locale, st) {
  const vpn = st.vpn || {};
  const lan = st.lan || {};
  const lines = [
    `${t(locale, 'status.os')}: ${st.os}`,
    `${t(locale, 'status.admin')}: ${yn(locale, st.hasAdmin)}`,
    `${t(locale, 'status.vpn')}: ${vpn.up ? t(locale, 'status.up') : t(locale, 'status.down')}`
      + (vpn.iface ? ` ${vpn.iface}` : '')
      + (vpn.addr ? ` (${vpn.addr})` : ''),
    `${t(locale, 'status.lan')}: ${lan.iface || '-'}`
      + (lan.gw ? ` gw ${lan.gw}` : '')
      + (lan.addr ? ` (${lan.addr})` : ''),
    `${t(locale, 'status.mode')}: ${st.mode || '-'}`,
    `${t(locale, 'status.applied')}: ${st.applied ? yn(locale, true) : t(locale, 'status.idle')}`,
    `${t(locale, 'status.dns')}: ${formatDns(locale, st.dns)}`,
    `${t(locale, 'status.watch')}: ${yn(locale, st.watch)}`,
    `${t(locale, 'status.repair')}: ${yn(locale, st.repairActive)}`,
    `${t(locale, 'status.locale')}: ${st.locale}`,
    ...(st.hijacked ? [t(locale, 'status.hijacked')] : []),
    '',
    ...(st.warnings || []),
  ];
  return lines.join('\n');
}

async function main(argv, deps = {}) {
  let parsed;
  try {
    parsed = parseArgv(argv);
  } catch (err) {
    const locale = normalizeLocale(process.env.VPN_BYPASS_LANG) || 'th';
    printErr(formatError(locale, err));
    printErr(t(locale, 'help'));
    return 1;
  }

  if (parsed.flags.version) {
    print(pkg.version);
    return 0;
  }

  const ServiceImpl = deps.Service || Service;
  const service = deps.service || new ServiceImpl({
    home: deps.home,
    platform: deps.platform,
    exec: deps.exec,
    resolveDns: deps.resolveDns,
    probeTls: deps.probeTls,
  });
  let locale = normalizeLocale(parsed.lang) || normalizeLocale(process.env.VPN_BYPASS_LANG) || 'th';
  let cfg;
  try {
    cfg = service.getConfig();
  } catch (err) {
    printErr(formatError(locale, err instanceof AppError ? err : err));
    return err && err.code === 'EPRIV' ? 13 : 1;
  }
  locale = normalizeLocale(parsed.lang) || cfg.locale || locale;
  service.localeOverride = locale;

  if (parsed.flags.help || parsed.command === 'help' || !parsed.command) {
    print(t(locale, 'help'));
    return 0;
  }

  const confirm = deps.confirm || confirmPrompt;

  try {
    switch (parsed.command) {
      case 'lang': {
        const next = normalizeLocale(parsed.args[0]);
        if (!parsed.args[0]) {
          print(t(locale, 'lang.current', { locale: cfg.locale }));
          return 0;
        }
        if (!next) throw Object.assign(new Error('locale must be th or en'), { code: 'EINVAL' });
        service.putConfig({ locale: next });
        print(t(next, 'lang.set', { locale: next }));
        return 0;
      }
      case 'status': {
        const st = await service.getStatus();
        print(formatStatus(locale, st));
        return 0;
      }
      case 'on': {
        const result = await service.on({
          mode: parsed.flags.mode || undefined,
          dryRun: parsed.flags.dryRun,
        });
        if (result.dryRun) {
          print(t(locale, 'on.dryRun'));
          for (const a of result.actions) {
            print(`  ${a.op} ${a.dest}/${a.prefix} via ${a.gw || a.iface || ''} (${a.kind})`);
          }
          if (result.dns) {
            print(`  dns ${result.dns.mode || ''} lan ${(result.dns.lanServers || []).join(',')} vpn ${(result.dns.vpnServers || []).join(',')} suffixes ${(result.dns.suffixes || []).join(',')}`);
          }
          return 0;
        }
        print(t(locale, 'on.done', { mode: result.mode }));
        return 0;
      }
      case 'off': {
        await service.off();
        print(t(locale, 'off.done'));
        return 0;
      }
      case 'domain': {
        const sub = parsed.args[0];
        if (sub === 'list' || !sub) {
          const list = service.listDomains();
          print(list.length ? list.join('\n') : t(locale, 'domain.empty'));
          return 0;
        }
        if (sub === 'add') {
          const host = parsed.args[1];
          const domains = await service.addDomain(host);
          print(t(locale, 'domain.added', { host: host || '' }));
          print(domains.join('\n'));
          return 0;
        }
        if (sub === 'rm' || sub === 'remove' || sub === 'del') {
          const host = parsed.args[1];
          await service.removeDomain(host);
          print(t(locale, 'domain.removed', { host: host || '' }));
          return 0;
        }
        throw Object.assign(new Error('domain add|rm|list'), { code: 'EINVAL' });
      }
      case 'lookup': {
        const host = parsed.args[0];
        const result = await service.lookupHost(host);
        print(t(locale, 'lookup.title', { host: result.host }));
        for (const hit of result.hits) {
          print(`  ${hit.ip} → ${t(locale, `lookup.via.${hit.via}`)} ${hit.iface || ''} ${hit.gw || ''} ${hit.cidr || ''}`.trim());
        }
        return 0;
      }
      case 'try': {
        const host = parsed.args[0];
        const result = await service.tryHost(host);
        if (result.ok) {
          print(t(locale, 'try.ok', { host: result.host }));
          return 0;
        }
        print(t(locale, 'try.fail', { host: result.host, error: result.error || '' }));
        const yes = await confirm(t(locale, 'confirm.allowVpn', { host: result.host }));
        if (!yes) {
          print(t(locale, 'confirm.cancelled'));
          return 1;
        }
        await service.allowHost(result.host);
        print(t(locale, 'allow.done', { host: result.host }));
        return 0;
      }
      case 'allow': {
        const host = parsed.args[0];
        await service.allowHost(host);
        print(t(locale, 'allow.done', { host }));
        return 0;
      }
      case 'deny': {
        const host = parsed.args[0];
        await service.denyHost(host);
        print(t(locale, 'deny.done', { host }));
        return 0;
      }
      case 'watch': {
        const sub = parsed.args[0];
        if (sub === 'off') {
          await service.setWatch(false);
          print(t(locale, 'watch.off'));
          return 0;
        }
        await service.setWatch(true);
        print(t(locale, 'watch.on'));
        service.startWatchLoop({ unref: false });
        await new Promise(() => {});
        return 0;
      }
      case 'elevate-helper': {
        const admin = await service.platform.isAdmin();
        if (!admin) throw fail('EPRIV', 'administrator privileges required');
        await (deps.runElevateHelper || runElevateHelper)(service);
        return 0;
      }
      case 'ui': {
        if (typeof process.getuid === 'function' && process.getuid() === 0) {
          throw fail('EACCES', 'UI must run unprivileged; if config is root-owned: sudo chown -R "$(whoami)" ~/.config/vpn-bypass');
        }
        assertLoopbackHost('127.0.0.1');
        const elevate = deps.elevate || (deps.createElevate || createElevate)({
          paths: service.paths,
          spawnImpl: deps.spawn,
          platform: process.platform,
        });
        service.elevate = elevate;
        const started = await (deps.startServer || startServer)({
          host: '127.0.0.1',
          service,
        });
        service.enableSessionRepair();
        const url = `http://127.0.0.1:${started.port}`;
        print(t(locale, 'ui.hint', { url, token: started.token }));
        const stopHelper = () => {
          if (elevate && typeof elevate.quit === 'function') {
            elevate.quit().catch(() => {});
          }
        };
        process.once('SIGINT', () => { stopHelper(); process.exit(0); });
        process.once('SIGTERM', () => { stopHelper(); process.exit(0); });
        try {
          openBrowser(url);
        } catch {
          // user can open manually
        }
        await new Promise(() => {});
        return 0;
      }
      default:
        printErr(t(locale, 'unknown.command', { command: parsed.command }));
        return 1;
    }
  } catch (err) {
    printErr(formatError(locale, err instanceof AppError ? err : err));
    return err && err.code === 'EPRIV' ? 13 : 1;
  }
}

module.exports = { main, formatStatus, formatDns, confirmPrompt };
