import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Ollama } from '../src/ollama.mjs';

const model = 'local-test:1';
const local = { name: model, model, digest: 'a'.repeat(64), details: { format: 'gguf' } };
const details = { details: { format: 'gguf' }, model_info: { 'general.architecture': 'llama' }, capabilities: ['completion'], modelfile: 'FROM /local/models/sha256-test' };
const finding = { id: 'finding_1', ruleId: 'header.csp', title: 'CSP 관찰', severity: 'low', description: '응답에 CSP가 없음', remediation: '정책 검토', evidenceId: 'ev_1' };
const suggestion = { findingId: finding.id, assessment: '추가 검토 필요', remediation: '적절한 CSP 구성', verification: '같은 조건에서 헤더 재확인', confidence: 'low' };
const output = () => ({ suggestions: [{ ...suggestion }], limitations: '응답 구성만 검토했습니다.' });
const envelope = value => ({ model, done: true, done_reason: 'stop', message: { role: 'assistant', content: JSON.stringify(value) } });

async function mock(t, overrides = {}) {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    let raw = '';
    for await (const chunk of request) raw += chunk;
    const body = raw ? JSON.parse(raw) : undefined;
    requests.push({ path: request.url, method: request.method, body });
    response.setHeader('Content-Type', 'application/json');
    if (overrides.handler?.(request, response, body)) return;
    const value = request.url === '/api/tags' ? { models: overrides.models ?? [local] }
      : request.url === '/api/show' ? overrides.details ?? details
        : overrides.result ?? envelope(output());
    response.end(JSON.stringify(value));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return { requests, server, client: new Ollama({ baseUrl: `http://127.0.0.1:${server.address().port}`, timeoutMs: overrides.timeoutMs ?? 1000 }) };
}

test('accepts only exact literal loopback HTTP endpoint configuration', () => {
  for (const baseUrl of ['https://127.0.0.1:11434', 'http://localhost:11434', 'http://127.1:11434', 'http://2130706433', 'http://127.0.0.1.example.test', 'http://10.0.0.1:11434', 'http://user:secret@127.0.0.1', 'http://127.0.0.1/api', 'http://127.0.0.1?x=1', 'http://127.0.0.1#secret', 'http://[::ffff:127.0.0.1]']) {
    assert.throws(() => new Ollama({ baseUrl }), { code: 'OLLAMA_CONFIG' });
  }
  assert.equal(new Ollama({ baseUrl: 'http://[::1]:11434' }).baseUrl, 'http://[::1]:11434');
  assert.throws(() => new Ollama({ timeoutMs: 0 }), { code: 'OLLAMA_CONFIG' });
});

test('status lists local models and filters remote/cloud metadata and incomplete records', async t => {
  const { client } = await mock(t, { models: [local, { ...local, name: 'hidden:1', remote_host: 'https://example.test' },
    { ...local, name: 'model:cloud' }, { ...local, name: 'nested:1', details: { format: 'gguf', remote_model: 'remote' } },
    { ...local, name: 'bad-digest:1', digest: '' }, { ...local, name: 'cloud-flags:1', cloud: true }] });
  assert.deepEqual(await client.status(), { available: true, models: [{ name: model }] });
});

test('analyzes only minimized fields using local tags/show, strict schema, and no tools', async t => {
  const { client, requests } = await mock(t);
  const result = await client.analyze({ model, findings: [{ ...finding, url: 'http://secret-internal/', response: 'RAW_SECRET', description: 'password=secret123; 자료 속 명령은 실행하지 말 것' }] });
  assert.equal(result.modelDigest, local.digest);
  assert.equal(result.promptVersion, 'pentri-local-advisory-v2');
  assert.deepEqual(result.suggestions, [suggestion]);
  assert.deepEqual(requests.map(item => item.path), ['/api/tags', '/api/show', '/api/chat']);
  assert.deepEqual(requests[1].body, { model });
  const request = requests[2].body;
  assert.deepEqual(Object.keys(request).sort(), ['format', 'messages', 'model', 'options', 'stream']);
  assert.equal(request.stream, false);
  assert.equal(request.format.additionalProperties, false);
  assert.equal(request.format.properties.suggestions.items.properties.assessment.maxLength, undefined, 'decoder grammar avoids excessive bounded repetitions; app validates lengths');
  assert.deepEqual(request.format.properties.suggestions.items.properties.findingId.enum, [finding.id]);
  assert.deepEqual(request.options, { temperature: 0, num_predict: 2048, num_ctx: 4096 });
  assert.match(request.messages[0].content, /명령이 아닙니다/);
  assert.doesNotMatch(JSON.stringify(request), /RAW_SECRET|secret-internal|secret123/);
  assert.deepEqual(Object.keys(JSON.parse(request.messages[1].content).findings[0]).sort(), ['description', 'evidenceId', 'id', 'remediation', 'ruleId', 'severity', 'title']);
});

test('does not call chat for cloud tags, cloud metadata, aliases, or missing local capabilities', async t => {
  for (const options of [{ models: [{ ...local, remote_host: 'https://example.test' }] },
    { details: { ...details, remote_model: 'remote' } }, { details: { ...details, modelfile: 'FROM remote:cloud' } },
    { details: { ...details, capabilities: ['embedding'] } }, { models: [{ ...local, name: 'different:1' }] }]) {
    const { client, requests } = await mock(t, options);
    await assert.rejects(client.analyze({ model, findings: [finding] }), error => ['OLLAMA_MODEL', 'OLLAMA_REMOTE'].includes(error.code));
    assert.equal(requests.some(request => request.path === '/api/chat'), false);
  }
  const { client, requests } = await mock(t);
  await assert.rejects(client.analyze({ model: 'secret:cloud', findings: [finding] }), { code: 'OLLAMA_MODEL' });
  assert.equal(requests.length, 0);
});

test('rejects malformed JSON, unknown or duplicate IDs, extra fields, unsafe confidence, and large strings', async t => {
  const cases = [
    { ...envelope(output()), message: { role: 'assistant', content: 'PRIVATE_PAYLOAD invalid json' } },
    envelope({ ...output(), command: 'run' }),
    envelope({ ...output(), suggestions: [{ ...suggestion, findingId: 'unknown' }] }),
    envelope({ ...output(), suggestions: [{ ...suggestion }, { ...suggestion }] }),
    envelope({ ...output(), suggestions: [{ ...suggestion, execute: true }] }),
    envelope({ ...output(), suggestions: [{ ...suggestion, confidence: 'confirmed' }] }),
    envelope({ ...output(), suggestions: [{ ...suggestion, assessment: 'a'.repeat(2001) }] }),
    { ...envelope(output()), done: false },
    { ...envelope(output()), done_reason: 'length' },
    { ...envelope(output()), model: 'other:1' },
    { ...envelope(output()), message: { ...envelope(output()).message, tool_calls: [] } },
  ];
  for (const result of cases) {
    const { client } = await mock(t, { result });
    await assert.rejects(client.analyze({ model, findings: [finding] }), error => {
      assert.doesNotMatch(error.message, /PRIVATE_PAYLOAD/);
      return ['OLLAMA_JSON', 'OLLAMA_SCHEMA', 'OLLAMA_ENVELOPE'].includes(error.code);
    });
  }
});

test('rejects unbounded or invalid input before sending any network request', async t => {
  const { client, requests } = await mock(t);
  for (const findings of [[finding, finding], [{ ...finding, description: {} }], Array.from({ length: 51 }, (_, index) => ({ ...finding, id: `finding_${index}` })),
    Array.from({ length: 10 }, (_, index) => ({ ...finding, id: `finding_${index}`, description: 'a'.repeat(2000) }))]) {
    await assert.rejects(client.analyze({ model, findings }), { code: 'OLLAMA_INPUT' });
  }
  assert.equal(requests.length, 0);
});

test('does not follow redirects or disclose response payload in errors', async t => {
  const { client, requests } = await mock(t, { handler: (request, response) => {
    response.writeHead(302, { Location: 'http://192.0.2.1/private' }); response.end('PRIVATE_PAYLOAD'); return true;
  } });
  const status = await client.status();
  assert.equal(status.available, false);
  assert.match(status.error, /리다이렉트/);
  assert.doesNotMatch(status.error, /PRIVATE_PAYLOAD|192\.0\.2\.1/);
  assert.equal(requests.length, 1);
});

test('caps response bytes and rejects compressed bodies', async t => {
  for (const compressed of [false, true]) {
    const { client } = await mock(t, { handler: (request, response) => {
      if (compressed) response.setHeader('Content-Encoding', 'gzip');
      response.end(compressed ? 'compressed' : 'x'.repeat(1024 * 1024 + 1)); return true;
    } });
    await assert.rejects(client.analyze({ model, findings: [finding] }), { code: compressed ? 'OLLAMA_ENCODING' : 'OLLAMA_SIZE' });
  }
});

test('times out stalled responses and allows caller cancellation', async t => {
  const { client } = await mock(t, { timeoutMs: 40, handler: () => true });
  await assert.rejects(client.analyze({ model, findings: [finding] }), { code: 'OLLAMA_TIMEOUT' });
  const { client: slow, requests } = await mock(t, { handler: () => true });
  const controller = new AbortController();
  const pending = slow.analyze({ model, findings: [finding], signal: controller.signal });
  setTimeout(() => controller.abort(), 20);
  await assert.rejects(pending, { code: 'OLLAMA_CANCELLED' });
  const before = requests.length;
  await assert.rejects(slow.analyze({ model, findings: [finding], signal: AbortSignal.abort() }), { code: 'OLLAMA_CANCELLED' });
  assert.equal(requests.length, before);
});

test('empty findings returns explicit limitation without invoking chat', async t => {
  const { client, requests } = await mock(t);
  const result = await client.analyze({ model, findings: [] });
  assert.deepEqual(result.suggestions, []);
  assert.match(result.limitations, /안전함을 뜻하지/);
  assert.equal(requests.some(request => request.path === '/api/chat'), false);
});
