import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

test('optional collector has no persistent host access or page-wide content script', async () => {
  const manifest = JSON.parse(await readFile(new URL('../extension/manifest.json', import.meta.url)));
  assert.deepEqual(manifest.permissions.sort(), ['activeTab', 'scripting', 'storage']);
  assert.equal(manifest.host_permissions, undefined);
  assert.equal(manifest.content_scripts, undefined);
});

test('collector launch persists the clicked target, never replaces it with the focused tool tab', async () => {
  let clicked; const stored = {}; const tabs = [];
  const chrome = { action: { onClicked: { addListener: fn => { clicked = fn; } } }, storage: { session: { get: async () => stored, set: async values => Object.assign(stored, values), remove: async keys => keys.forEach(key => delete stored[key]) } }, tabs: { create: async data => tabs.push(data) }, runtime: { getURL: value => `chrome-extension://fixture/${value}` } };
  vm.runInNewContext(await readFile(new URL('../extension/worker.js', import.meta.url), 'utf8'), { chrome, crypto: { randomUUID: () => 'fixture' } });
  await clicked({ id: 4, url: 'chrome://extensions' }); assert.equal(tabs.length, 0);
  await clicked({ id: 123, url: 'https://target.test/approved' });
  assert.equal(stored.target_fixture.tabId, 123);
  assert.equal(stored.target_fixture.url, 'https://target.test/approved');
  assert.equal(tabs[0].url, 'chrome-extension://fixture/collector.html?session=fixture');
  assert.ok(!tabs[0].url.includes('target.test'));
});
