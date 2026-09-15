import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { createApp } from '../src/server.mjs';
import { Store } from '../src/store.mjs';

const mockAI = { status: async () => ({ available: true, models: [{ name: 'fixture:local' }] }), analyze: async ({ findings, model }) => ({ model, modelDigest: 'a'.repeat(64), promptVersion: 'fixture', suggestions: findings.map(f => ({ findingId: f.id, assessment: '관찰 범위 확인', remediation: '설정 개선', verification: '같은 경로 재점검', confidence: 'low' })), limitations: 'fixture only' }) };
async function setup(t, options = {}) {
  const app = createApp({ dataFile: ':memory:', ollama: mockAI, runnerOptions: { intervalMs: 0 }, ...options });
  const origin = await app.listen(0);
  t.after(() => app.close());
  const { token } = await (await fetch(`${origin}/api/session`)).json();
  const call = (path, body, method = body === undefined ? 'GET' : 'POST') => fetch(`${origin}${path}`, { method, headers: { 'X-Pentri-Token': token, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  return { app, origin, token, call };
}
async function target(t, handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
async function until(fn) {
  for (let i = 0; i < 200; i++) { const result = await fn(); if (result) return result; await delay(10); }
  throw new Error('Timed out waiting for fixture state');
}
async function startAndWait(call, projectId) {
  const response = await call(`/api/projects/${projectId}/runs`, { approved: true });
  assert.equal(response.status, 202);
  const { run } = await response.json();
  return until(async () => { const { run: current } = await (await call(`/api/runs/${run.id}`)).json(); return !['queued', 'running'].includes(current.status) && current; });
}
function raw(origin, path, headers = {}) {
  return new Promise((resolve, reject) => { const req = http.get(`${origin}/`, { path, headers }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); }); req.on('error', reject); });
}

test('local API rejects foreign Host/Origin, cross-site normalized session routes, and missing token', async t => {
  const { origin, call } = await setup(t);
  assert.equal((await fetch(`${origin}/api/projects`)).status, 401);
  assert.equal(await raw(origin, '/api/session', { Host: 'evil.test' }), 403);
  assert.equal(await raw(origin, '/api/session', { Origin: 'https://evil.test' }), 403);
  for (const path of ['/api/session', '/outside/../api/session', '/outside/%2e%2e/api/session']) {
    assert.equal(await raw(origin, path, { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate' }), 403);
  }
  assert.equal(await raw(origin, '/', { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate' }), 200);
  assert.equal((await call('/api/projects')).status, 200);
  const bad = await call('/api/projects', { name: 'bad', origin, paths: ['/'] });
  assert.equal(bad.status, 400, 'app cannot scan its own API');
});

test('project lifecycle preserves evidence, review, inconclusive and remediation retests, reports and deletion', async t => {
  let mode = 'vulnerable';
  const seen = [];
  const targetOrigin = await target(t, (req, res) => {
    seen.push(req.url);
    res.writeHead(mode === 'error' ? 500 : 200, { 'Content-Type': 'text/html', 'Set-Cookie': mode === 'fixed' ? 'session=TOP_SECRET; HttpOnly; SameSite=Lax' : 'session=TOP_SECRET', ...(mode === 'fixed' ? { 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'", 'X-Content-Type-Options': 'nosniff' } : {}) });
    res.end('<html><title>fixture</title><p>token="TOP_SECRET"</p></html>');
  });
  const { call } = await setup(t);
  const { project } = await (await call('/api/projects', { name: '<script>alert(1)</script>', origin: targetOrigin, paths: ['/'], networkPolicy: 'private' })).json();
  assert.equal((await call(`/api/projects/${project.id}/runs`, { approved: false })).status, 400);
  const first = await startAndWait(call, project.id);
  assert.equal(first.status, 'completed');
  let detail = await (await call(`/api/projects/${project.id}`)).json();
  assert.equal(detail.findings.length, 4);
  assert.equal(detail.evidence.length, 1);
  assert.ok(!JSON.stringify(detail).includes('TOP_SECRET'));
  assert.equal(detail.integrity.valid, true);
  const finding = detail.findings.find(f => f.ruleId === 'headers.csp');
  assert.equal((await call(`/api/findings/${finding.id}/review`, { status: 'fixed', note: '' })).status, 400);
  await call(`/api/findings/${finding.id}/review`, { status: 'fixed', note: '수동 확인 기록' });
  await startAndWait(call, project.id);
  detail = await (await call(`/api/projects/${project.id}`)).json();
  assert.equal(detail.findings.find(f => f.id === finding.id).status, 'candidate', 'recurrence reopens a fixed finding');
  assert.ok(detail.events.some(event => event.type === 'finding.reopened'));
  mode = 'fixed';
  await startAndWait(call, project.id);
  detail = await (await call(`/api/projects/${project.id}`)).json();
  assert.equal(detail.findings.find(f => f.id === finding.id).retestStatus, 'not_observed');
  assert.equal(detail.findings.find(f => f.id === finding.id).status, 'candidate', 'pass never grants fixed review status');
  mode = 'error';
  const failed = await startAndWait(call, project.id);
  assert.ok(failed.checks.every(check => check.outcome === 'unknown'));
  detail = await (await call(`/api/projects/${project.id}`)).json();
  assert.equal(detail.findings.find(f => f.id === finding.id).retestStatus, 'inconclusive');
  const html = await (await call(`/api/projects/${project.id}/report?format=html`)).text();
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(!html.includes('<script>alert'));
  const report = await (await call(`/api/projects/${project.id}/report?format=json`)).json();
  assert.equal(report.findings.length, detail.findings.length);
  assert.equal(report.evidence.length, 4);
  assert.equal(report.integrity.valid, true);
  assert.deepEqual(seen, ['/', '/', '/', '/']);
  assert.equal((await call(`/api/projects/${project.id}`, undefined, 'DELETE')).status, 200);
  assert.equal((await call(`/api/projects/${project.id}`)).status, 404);
  assert.deepEqual((await (await call('/api/projects')).json()).projects, []);
});

test('cancellation stops later requests and an active project cannot be deleted', async t => {
  const seen = [];
  const targetOrigin = await target(t, (req, res) => { seen.push(req.url); res.writeHead(200, { 'Content-Type': 'text/html' }); res.write('pending'); });
  const { call } = await setup(t);
  const { project } = await (await call('/api/projects', { name: 'cancel', origin: targetOrigin, paths: ['/', '/later'] })).json();
  const { run } = await (await call(`/api/projects/${project.id}/runs`, { approved: true })).json();
  await until(() => seen.length === 1);
  assert.equal((await call(`/api/projects/${project.id}`, undefined, 'DELETE')).status, 409);
  assert.equal((await call(`/api/projects/${project.id}/runs`, { approved: true })).status, 409);
  await call(`/api/runs/${run.id}/cancel`, {});
  await until(async () => (await (await call(`/api/runs/${run.id}`)).json()).run.status === 'cancelled');
  assert.deepEqual(seen, ['/']);
});

test('AI receives minimized findings, batches observations, persists advice separately, and can be cancelled', async t => {
  const received = [];
  let wait = false;
  const ai = { ...mockAI, analyze: async args => {
    received.push(args);
    if (wait) await delay(10000, undefined, { signal: args.signal });
    return mockAI.analyze(args);
  } };
  const targetOrigin = await target(t, (_req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<p>PRIVATE_BUSINESS_TEXT</p>'); });
  const { call } = await setup(t, { ollama: ai });
  const { project } = await (await call('/api/projects', { name: 'AI', origin: targetOrigin, paths: ['/', '/two'] })).json();
  const run = await startAndWait(call, project.id);
  assert.equal((await call(`/api/runs/${run.id}/analyze`, { model: 'fixture:local' })).status, 202);
  await until(async () => (await (await call(`/api/runs/${run.id}`)).json()).run.ai?.status === 'completed');
  assert.equal(received.length, 2);
  assert.ok(!JSON.stringify(received).includes(targetOrigin));
  assert.ok(!JSON.stringify(received).includes('PRIVATE_BUSINESS_TEXT'));
  assert.ok(received.every(args => args.findings.length <= 4));
  wait = true;
  await call(`/api/runs/${run.id}/analyze`, { model: 'fixture:local' });
  assert.equal((await call(`/api/projects/${project.id}`, undefined, 'DELETE')).status, 409);
  await call(`/api/runs/${run.id}/cancel`, {});
  await until(async () => (await (await call(`/api/runs/${run.id}`)).json()).run.ai?.status === 'failed');
  const detail = await (await call(`/api/projects/${project.id}`)).json();
  assert.ok(detail.findings.every(f => f.status === 'candidate'));
});

test('snapshot imports stay inert and within origin/path scope', async t => {
  const { call } = await setup(t);
  const { project } = await (await call('/api/projects', { name: 'import', origin: 'http://127.0.0.1:9999', paths: ['/'] })).json();
  const snapshot = { schemaVersion: 1, url: 'http://127.0.0.1:9999/', title: 'fixture', comments: ['token=TOP_SECRET', '<script>bad()</script>'], endpoints: ['https://unapproved.test/'], forms: [] };
  assert.equal((await call(`/api/projects/${project.id}/import`, { snapshot })).status, 201);
  assert.equal((await call(`/api/projects/${project.id}/import`, { snapshot: { ...snapshot, url: 'http://127.0.0.1:9999/other' } })).status, 400);
  const detail = await (await call(`/api/projects/${project.id}`)).json();
  assert.equal(detail.imports.length, 1);
  assert.equal(detail.runs.length, 0);
  assert.ok(!JSON.stringify(detail).includes('TOP_SECRET'));
});

test('SQLite restart preserves records, marks interrupted jobs, and detects an edited audit event', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'pentri-store-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'db.sqlite');
  let store = new Store(path);
  store.save('project', { id: 'p', name: 'persist' });
  store.save('run', { id: 'r', projectId: 'p', status: 'running' });
  store.event('p', 'test', { cookie: 'TOP_SECRET' });
  if (process.platform !== 'win32') for (const file of [path, `${path}-wal`, `${path}-shm`]) assert.equal((await stat(file)).mode & 0o777, 0o600);
  store.close(); store = new Store(path);
  assert.equal(store.get('project', 'p').name, 'persist');
  assert.equal(store.get('run', 'r').status, 'interrupted');
  assert.equal(store.verify('p').valid, true);
  store.db.prepare('UPDATE events SET data=? WHERE seq=1').run(JSON.stringify({ altered: true }));
  assert.equal(store.verify('p').valid, false);
  store.close();
});
