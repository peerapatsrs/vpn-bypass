'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { expandWwwApex } = require('../src/core/net');
const { Service } = require('../src/core/service');
const { tmpHome, mockPlatform } = require('./helpers');

describe('www/apex expansion', () => {
  it('adds www when given apex and apex when given www', () => {
    assert.deepEqual(expandWwwApex('example.com'), ['example.com', 'www.example.com']);
    assert.deepEqual(expandWwwApex('www.example.com'), ['www.example.com', 'example.com']);
    assert.deepEqual(expandWwwApex('EXAMPLE.COM.'), ['example.com', 'www.example.com']);
  });

  it('domain add expands www and apex into config', async () => {
    const home = tmpHome();
    const svc = new Service({ home, platform: mockPlatform() });
    const domains = await svc.addDomain('Example.com');
    assert.deepEqual(domains, ['example.com', 'www.example.com']);
    const again = await svc.addDomain('www.example.com');
    assert.deepEqual(again, ['example.com', 'www.example.com']);
    fs.rmSync(home, { recursive: true, force: true });
  });
});
