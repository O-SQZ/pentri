import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import dns from 'node:dns/promises';
import { createHash } from 'node:crypto';
import { requestTarget, validatePlan } from '../src/network.mjs';

async function fixture(t, handler, host = '127.0.0.1') {
  const server = http.createServer(handler);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, host, resolve); });
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  return `http://${host.includes(':') ? `[${host}]` : host}:${server.address().port}`;
}

test('plans normalize origin and deduplicate exact approved paths', () => {
  assert.deepEqual(validatePlan({ origin: 'http://127.0.0.1:80/', paths: ['/', '/login', '/login'] }),
    { origin: 'http://127.0.0.1', paths: ['/', '/login'], networkPolicy: 'private' });
  assert.equal(validatePlan({ origin: 'https://INTRANET.example/', paths: ['/a%20b'] }).origin, 'https://intranet.example');
  assert.equal(validatePlan({ origin: 'http://[::1]', paths: ['/'] }).origin, 'http://[::1]');
});

test('plans reject scope ambiguity, credentials, unsupported schemes and excessive paths', () => {
  const origins = ['file:///tmp/test', 'ftp://127.0.0.1', 'http:127.0.0.1', 'http://user:pass@127.0.0.1',
    'http://@127.0.0.1', 'http://127.0.0.1/admin', 'http://127.0.0.1/?', 'http://127.0.0.1/#',
    'http://127.0.0.1\\@8.8.8.8', 'http://127.0.0.1:0', 'http://127.0.0.1:8787', 'http://127.0.0.1:11434'];
  for (const origin of origins) assert.throws(() => validatePlan({ origin, paths: ['/'] }), origin);
  const paths = ['https://evil.test/', '//evil.test/', '/a?x=y', '/a#fragment', '/a/../b', '/a/%2e%2e/b',
    '/%2fadmin', '/%5cadmin', '/%0d%0aHeader', '/a\\b', '/a b', '/%', '/a\u0000b'];
  for (const path of paths) assert.throws(() => validatePlan({ origin: 'http://127.0.0.1', paths: [path] }), path);
  assert.throws(() => validatePlan({ origin: 'http://127.0.0.1', paths: [] }));
  assert.throws(() => validatePlan({ origin: 'http://127.0.0.1', paths: Array(21).fill('/') }));
  assert.throws(() => validatePlan({ origin: 'http://127.0.0.1', paths: ['/'], networkPolicy: 'anything' }));
  assert.throws(() => validatePlan({ origin: 'http://127.0.0.1:4321', paths: ['/'] }, { blockedPorts: [4321] }));
});

test('private policy permits only loopback, RFC1918 and ULA literal addresses', () => {
  for (const host of ['127.0.0.2', '10.255.255.254', '172.16.1.1', '172.31.255.254', '192.168.2.3', '[::1]', '[fc00::1]', '[fdab::1]']) {
    assert.doesNotThrow(() => validatePlan({ origin: `http://${host}`, paths: ['/'] }), host);
  }
  for (const host of ['8.8.8.8', '172.15.1.1', '172.32.1.1', '169.254.169.254', '[2606:4700:4700::1111]']) {
    assert.throws(() => validatePlan({ origin: `http://${host}`, paths: ['/'] }), host);
  }
});

test('public policy permits public unicast and still blocks metadata, reserved and mapped addresses', () => {
  for (const host of ['8.8.8.8', '1.1.1.1', '[2606:4700:4700::1111]', '10.0.0.1']) {
    assert.doesNotThrow(() => validatePlan({ origin: `https://${host}`, paths: ['/'], networkPolicy: 'public' }), host);
  }
  for (const host of ['0.0.0.0', '100.100.100.200', '169.254.169.254', '168.63.129.16', '192.0.0.192',
    '192.0.2.1', '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '255.255.255.255',
    '[::]', '[::ffff:127.0.0.1]', '[::ffff:7f00:1]', '[::127.0.0.1]', '[64:ff9b::7f00:1]',
    '[fe80::1]', '[ff02::1]', '[2001:db8::1]', '[2002:7f00:1::]', '[fd00:ec2::254]', '[3fff::1]']) {
    assert.throws(() => validatePlan({ origin: `http://${host}`, paths: ['/'], networkPolicy: 'public' }), host);
  }
});

test('request returns exact GET evidence and preserves distinct cookie headers', async (t) => {
  const seen = [];
  const content = '<!doctype html><title>진단 fixture</title>';
  const origin = await fixture(t, (req, res) => {
    seen.push({ method: req.method, path: req.url, encoding: req.headers['accept-encoding'], cookie: req.headers.cookie });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': ['a=secret; HttpOnly', 'b=other; Secure'] });
    res.end(content);
  });
  const result = await requestTarget(`${origin}/approved%20path`);
  assert.deepEqual(seen, [{ method: 'GET', path: '/approved%20path', encoding: 'identity', cookie: undefined }]);
  assert.equal(result.status, 200);
  assert.equal(result.body, content);
  assert.equal(result.bytes, Buffer.byteLength(content));
  assert.equal(result.truncated, false);
  assert.equal(result.sha256, createHash('sha256').update(content).digest('hex'));
  assert.equal(result.remoteAddress, '127.0.0.1');
  assert.equal(result.headers['set-cookie'].length, 2);
  assert.ok(result.durationMs >= 0);
});

test('redirects are evidence and are never followed', async (t) => {
  const seen = [];
  const origin = await fixture(t, (req, res) => {
    seen.push(req.url);
    res.writeHead(302, { Location: '/unapproved' });
    res.end('redirect');
  });
  const result = await requestTarget(`${origin}/approved`);
  assert.equal(result.status, 302);
  assert.equal(result.headers.location, '/unapproved');
  assert.deepEqual(seen, ['/approved']);
});

test('response byte cap destroys the stream and hashes only retained bytes', async (t) => {
  const origin = await fixture(t, (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.write('12345678901234567890');
    // An unending server must still finish immediately at the byte cap.
  });
  const result = await requestTarget(`${origin}/`, { maxBytes: 10, timeoutMs: 1000 });
  assert.equal(result.truncated, true);
  assert.equal(result.bytes, 10);
  assert.equal(result.body, '1234567890');
  assert.equal(result.sha256, createHash('sha256').update('1234567890').digest('hex'));
});

test('a complete body exactly at the cap is not incorrectly marked truncated', async (t) => {
  const origin = await fixture(t, (_req, res) => res.end('12345'));
  const result = await requestTarget(`${origin}/`, { maxBytes: 5 });
  assert.equal(result.bytes, 5);
  assert.equal(result.truncated, false);
});

test('whole-request deadline stops a response that keeps sending data', async (t) => {
  const origin = await fixture(t, (_req, res) => {
    res.writeHead(200);
    const interval = setInterval(() => res.write('x'), 10);
    res.on('close', () => clearInterval(interval));
  });
  await assert.rejects(requestTarget(`${origin}/`, { timeoutMs: 80 }), /timed out/iu);
});

test('cancellation stops an in-flight response and pre-abort sends no request', async (t) => {
  let requests = 0;
  const origin = await fixture(t, (_req, res) => { requests++; res.writeHead(200); res.write('waiting'); });
  const before = new AbortController();
  before.abort(new Error('Cancelled before request'));
  await assert.rejects(requestTarget(`${origin}/`, { signal: before.signal }), /Cancelled before/);
  assert.equal(requests, 0);
  const during = new AbortController();
  const request = requestTarget(`${origin}/`, { signal: during.signal });
  const timer = setTimeout(() => during.abort(new Error('Cancelled during request')), 40);
  t.after(() => clearTimeout(timer));
  await assert.rejects(request, /Cancelled during/);
  assert.equal(requests, 1);
});

test('target validation blocks public, metadata and protected ports before a connection', async () => {
  for (const target of ['http://8.8.8.8/', 'http://169.254.169.254/', 'http://127.0.0.1:8787/',
    'http://127.0.0.1:11434/', 'http://127.0.0.1/a/../b', 'http://127.0.0.1/?token=x', 'http://@127.0.0.1/']) {
    await assert.rejects(requestTarget(target));
  }
  await assert.rejects(requestTarget('http://169.254.169.254/', { networkPolicy: 'public' }));
});

test('localhost DNS lookup is pinned to a validated loopback answer', async (t) => {
  // Listening on IPv6 without ipv6Only accepts both localhost address families.
  const server = http.createServer((_req, res) => res.end('localhost'));
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen({ port: 0, host: '::', ipv6Only: false }, resolve); });
  } catch (error) {
    t.skip(`IPv6 is unavailable: ${error.code}`);
    return;
  }
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  const result = await requestTarget(`http://localhost:${server.address().port}/`);
  assert.equal(result.body, 'localhost');
  assert.ok(['::1', '127.0.0.1', '::ffff:127.0.0.1'].includes(result.remoteAddress));
});

test('every DNS answer is validated before opening a connection', async (t) => {
  let requests = 0;
  const origin = await fixture(t, (_req, res) => { requests++; res.end('unexpected'); });
  const resolver = t.mock.method(dns, 'lookup', async () => [
    { address: '127.0.0.1', family: 4 }, { address: '169.254.169.254', family: 4 },
  ]);
  const target = `${origin.replace('127.0.0.1', 'mixed.fixture.invalid')}/`;
  await assert.rejects(requestTarget(target, { networkPolicy: 'public' }), /DNS returned/);
  assert.equal(resolver.mock.callCount(), 1);
  assert.equal(requests, 0);
});

test('socket lookup uses the validated address without a second DNS resolution', async (t) => {
  let observedHost;
  const origin = await fixture(t, (req, res) => { observedHost = req.headers.host; res.end('pinned'); });
  const resolver = t.mock.method(dns, 'lookup', async () => {
    if (resolver.mock.callCount() > 1) return [{ address: '169.254.169.254', family: 4 }];
    return [{ address: '127.0.0.1', family: 4 }];
  });
  const target = `${origin.replace('127.0.0.1', 'pinned.fixture.invalid')}/`;
  const result = await requestTarget(target);
  assert.equal(result.body, 'pinned');
  assert.equal(result.remoteAddress, '127.0.0.1');
  assert.equal(resolver.mock.callCount(), 1);
  assert.equal(observedHost, new URL(target).host);
});

test('deadline and cancellation also bound a DNS lookup that never resolves', async (t) => {
  t.mock.method(dns, 'lookup', () => new Promise(() => {}));
  await assert.rejects(requestTarget('http://slow.fixture.invalid/', { timeoutMs: 30 }), /timed out/);
  const controller = new AbortController();
  const request = requestTarget('http://slow.fixture.invalid/', { signal: controller.signal });
  controller.abort(new Error('DNS cancelled'));
  await assert.rejects(request, /DNS cancelled/);
});

test('subsequent requests reject DNS set changes within one approved run', async t => {
  let requests = 0;
  const origin = await fixture(t, (_req, res) => { requests++; res.end('first'); });
  t.mock.method(dns, 'lookup', async () => [{ address: requests ? '127.0.0.2' : '127.0.0.1', family: 4 }]);
  const url = origin.replace('127.0.0.1', 'changing.fixture.invalid');
  const first = await requestTarget(`${url}/`);
  assert.deepEqual(first.resolvedAddresses, ['127.0.0.1']);
  await assert.rejects(requestTarget(`${url}/next`, { pinnedAddresses: first.resolvedAddresses }), /DNS addresses changed/);
  assert.equal(requests, 1);
});
