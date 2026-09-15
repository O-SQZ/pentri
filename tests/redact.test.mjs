import test from 'node:test';
import assert from 'node:assert/strict';
import { redact } from '../src/redact.mjs';
test('redaction removes structured credentials and common body/query credentials without mutating input', () => {
  const input = { Cookie: 'a=SECRET', authorization: 'Bearer SECRET', list: [{ password: 'SECRET' }], body: 'token="SECRET" /?foo=SECRET&key=SECRET email person@example.org', note: 'safe text' };
  const output = redact(input);
  assert.ok(!JSON.stringify(output).includes('SECRET'));
  assert.equal(output.note, 'safe text');
  assert.equal(input.Cookie, 'a=SECRET');
  assert.deepEqual(redact(output), output);
});
test('Basic auth redaction preserves ordinary prose while removing encoded credentials', () => {
  assert.equal(redact('Implement a basic CSP policy'), 'Implement a basic CSP policy');
  assert.equal(redact('Basic dXNlcjpwYXNz'), '[REDACTED_AUTH]');
  assert.equal(redact('Bearer shorttoken'), '[REDACTED_AUTH]');
});
