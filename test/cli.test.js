'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { parseArgv } = require('../src/cli');
const { t, normalizeLocale } = require('../src/i18n');
const { Service } = require('../src/core/service');
const { tmpHome, mockPlatform } = require('./helpers');
const fs = require('fs');

describe('cli parse + i18n', () => {
  it('parses --lang, mode, dry-run and domain args', () => {
    const p = parseArgv(['--lang', 'en', 'on', '--mode', 'domains', '--dry-run']);
    assert.equal(p.lang, 'en');
    assert.equal(p.command, 'on');
    assert.equal(p.flags.mode, 'domains');
    assert.equal(p.flags.dryRun, true);
    const d = parseArgv(['domain', 'add', 'example.com']);
    assert.equal(d.command, 'domain');
    assert.deepEqual(d.args, ['add', 'example.com']);
    const l = parseArgv(['lang', 'th']);
    assert.equal(l.command, 'lang');
    assert.deepEqual(l.args, ['th']);
  });

  it('default locale is th and messages exist in both languages', () => {
    assert.equal(normalizeLocale('TH'), 'th');
    assert.equal(normalizeLocale('en'), 'en');
    assert.match(t('th', 'help'), /vpn-bypass/);
    assert.match(t('en', 'help'), /Usage:/);
    assert.match(t('th', 'confirm.allowVpn', { host: 'x.com' }), /\[y\/N\]/);
    assert.match(t('en', 'confirm.allowVpn', { host: 'x.com' }), /\[y\/N\]/);
    assert.match(t('th', 'error.EPRIV'), /sudo/);
    assert.match(t('en', 'error.EPRIV'), /sudo/);
  });

  it('config locale defaults to th and can be set', () => {
    const home = tmpHome();
    const svc = new Service({ home, platform: mockPlatform() });
    assert.equal(svc.getConfig().locale, 'th');
    svc.putConfig({ locale: 'en' });
    assert.equal(svc.getConfig().locale, 'en');
    fs.rmSync(home, { recursive: true, force: true });
  });
});
