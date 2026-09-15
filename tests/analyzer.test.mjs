import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeResponse, RULES_VERSION } from '../src/analyzer.mjs';

test('empty HTML response cannot establish successful remediation even with protective headers', () => {
  const result = analyzeResponse({ url: 'https://fixture.test/', status: 200, body: '', truncated: false, headers: { 'content-type': 'text/html', 'content-security-policy': "default-src 'none'; frame-ancestors 'none'", 'x-content-type-options': 'nosniff' } });
  assert.ok(result.checks.every(check => check.outcome === 'unknown'));
});

function response(overrides = {}) {
  return { url: 'https://fixture.test/', status: 200, headers: { 'content-type': 'text/html' }, body: '<!doctype html><title>Fixture</title>', bytes: 42, truncated: false, ...overrides };
}

function secureHeaders(extra = {}) {
  return { 'content-type': 'text/html', 'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff', 'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'set-cookie': ['session=supersecret; Secure; HttpOnly; SameSite=Lax'], ...extra };
}

function check(result, ruleId) { return result.checks.find((item) => item.ruleId === ruleId); }

test('a fully configured fixture passes its applicable checks', () => {
  const result = analyzeResponse(response({ headers: secureHeaders() }));
  assert.match(RULES_VERSION, /^\d+\.\d+\.\d+$/u);
  assert.equal(result.checks.length, 6);
  assert.ok(result.checks.every((item) => item.outcome === 'pass'));
  for (const item of result.checks) {
    for (const field of ['ruleId', 'title', 'severity', 'description', 'remediation', 'evidence']) assert.equal(typeof item[field], 'string');
  }
  assert.equal(JSON.stringify(result).includes('supersecret'), false);
});

test('missing headers produce configuration candidates and absent cookies remain unknown', () => {
  const result = analyzeResponse(response());
  for (const id of ['headers.csp', 'headers.frame-protection', 'headers.nosniff', 'headers.hsts']) assert.equal(check(result, id).outcome, 'fail');
  assert.equal(check(result, 'cookies.flags').outcome, 'unknown');
});

test('non-success statuses and truncated evidence never establish successful remediation', () => {
  for (const overrides of [{ status: 302 }, { status: 403 }, { status: 500 }, { truncated: true }]) {
    const result = analyzeResponse(response({ headers: secureHeaders(), ...overrides }));
    assert.ok(result.checks.every((item) => item.outcome === 'unknown'), JSON.stringify(overrides));
    assert.ok(result.observations.some((item) => item.kind === 'assessment-limitation'));
  }
});

test('non-HTML and compressed responses do not pass HTML checks', () => {
  for (const headers of [secureHeaders({ 'content-type': 'application/json' }), secureHeaders({ 'content-encoding': 'gzip' }), secureHeaders({ 'content-type': '' })]) {
    const result = analyzeResponse(response({ headers }));
    assert.ok(result.checks.filter((item) => item.ruleId !== 'cookies.flags').every((item) => item.outcome === 'unknown'));
    assert.equal(check(result, 'cookies.flags').outcome, 'pass');
  }
});

test('HSTS is HTTPS only and rejects disabled, malformed or duplicated max-age', () => {
  assert.equal(check(analyzeResponse(response({ url: 'http://fixture.test/', headers: secureHeaders() })), 'headers.hsts').outcome, 'unknown');
  for (const hsts of ['max-age=0', 'max-age=abc', 'max-age=-1', 'max-age=1; max-age=2', 'max-age=1, max-age=2', 'max-age="123', 'max-age=123"']) {
    assert.equal(check(analyzeResponse(response({ headers: secureHeaders({ 'strict-transport-security': hsts }) })), 'headers.hsts').outcome, 'fail', hsts);
  }
});

test('report-only CSP is not enforcement and frame-ancestors supersedes XFO', () => {
  const reportOnly = analyzeResponse(response({ headers: { 'content-type': 'text/html', 'content-security-policy-report-only': "frame-ancestors 'none'" } }));
  assert.equal(check(reportOnly, 'headers.csp').outcome, 'fail');
  assert.equal(check(reportOnly, 'headers.frame-protection').outcome, 'fail');
  for (const value of ['DENY', 'sameorigin']) {
    const result = analyzeResponse(response({ headers: { 'content-type': 'text/html', 'x-frame-options': value } }));
    assert.equal(check(result, 'headers.frame-protection').outcome, 'pass');
  }
  const permissive = analyzeResponse(response({ headers: secureHeaders({ 'content-security-policy': 'frame-ancestors *', 'x-frame-options': 'DENY' }) }));
  assert.equal(check(permissive, 'headers.frame-protection').outcome, 'fail');
  const restricted = analyzeResponse(response({ headers: secureHeaders({ 'content-security-policy': "frame-ancestors 'self' https://*.trusted.test" }) }));
  assert.equal(check(restricted, 'headers.frame-protection').outcome, 'pass');
});

test('cookie evidence describes flags and never includes cookie names or values', () => {
  const result = analyzeResponse(response({ headers: secureHeaders({ 'set-cookie': ['secretName=secretValue; Path=/; SameSite=None', 'second=anotherSecret; Secure; HttpOnly; SameSite=Strict'] }) }));
  const cookie = check(result, 'cookies.flags');
  assert.equal(cookie.outcome, 'fail');
  assert.match(cookie.evidence, /Cookie #1: Secure=no, HttpOnly=no, SameSite=none/u);
  for (const secret of ['secretName', 'secretValue', 'anotherSecret']) assert.equal(JSON.stringify(result).includes(secret), false);
  const http = analyzeResponse(response({ url: 'http://fixture.test/', headers: secureHeaders({ 'set-cookie': ['a=b; HttpOnly; SameSite=Lax'] }) }));
  assert.equal(check(http, 'cookies.flags').outcome, 'pass');
});

test('mixed active resources are advisory, omit resource URLs and ignore passive images/comments', () => {
  const body = '<!-- <script src="http://ignored.test/comment"></script> --><img src="http://image.test/x"><script src="http://fixture.test/a?token=secret"></script><link rel="stylesheet" href="http://fixture.test/style.css"><iframe src=http://fixture.test/frame></iframe>';
  const mixed = check(analyzeResponse(response({ body })), 'content.mixed-active-resources');
  assert.equal(mixed.outcome, 'fail');
  assert.match(mixed.evidence, /3 explicit HTTP/);
  assert.match(mixed.evidence, /Advisory only/);
  assert.equal(mixed.evidence.includes('secret'), false);
  assert.equal(check(analyzeResponse(response({ body: '<img src="http://image.test/x"><script src="https://fixture.test/a"></script>' })), 'content.mixed-active-resources').outcome, 'pass');
  assert.equal(check(analyzeResponse(response({ body: '<script>const markup = \'<iframe src="http://fake.test/">\';</script><textarea><script src="http://fake.test/"></script></textarea>' })), 'content.mixed-active-resources').outcome, 'pass');
  assert.equal(check(analyzeResponse(response({ url: 'http://fixture.test/', body })), 'content.mixed-active-resources').outcome, 'unknown');
});

test('source map comments are unverified observations, never confirmed exposure', () => {
  const body = '<script>\n//# sourceMappingURL=app.js.map?secret=hidden\n</script><style>/*# sourceMappingURL=app.css.map */</style>';
  const result = analyzeResponse(response({ body }));
  const sourceMap = result.observations.find((item) => item.kind === 'source-map-reference');
  assert.equal(sourceMap.count, 2);
  assert.equal(sourceMap.assessment, 'reference_only');
  assert.equal(JSON.stringify(result).includes('hidden'), false);
  assert.equal(result.checks.some((item) => /source.?map/iu.test(item.ruleId)), false);
  const script = analyzeResponse(response({ headers: { 'content-type': 'application/javascript' }, body: '//# sourceMappingURL=app.js.map' }));
  assert.equal(script.observations.find((item) => item.kind === 'source-map-reference').assessment, 'reference_only');
});
