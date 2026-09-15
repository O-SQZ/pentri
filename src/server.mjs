import http from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { join, resolve } from 'node:path';
import { Store, id, now, hash } from './store.mjs';
import { validatePlan } from './network.mjs';
import { Runner } from './runner.mjs';
import { Ollama } from './ollama.mjs';
import { redact } from './redact.mjs';
import { reportData, reportHTML } from './report.mjs';

const version = '1.20.0-alpha.1';
const webDir = fileURLToPath(new URL('../web/', import.meta.url));
const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const string = (value, name, max = 1000) => {
  if (typeof value !== 'string' || !value.trim() || value.length > max) throw fail(`${name}: 1~${max}자 문자열이 필요합니다.`);
  return value.trim();
};
async function bodyJSON(req) {
  if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] ?? '')) throw fail('application/json 요청이 필요합니다.', 415);
  const chunks = []; let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length; if (bytes > 524288) throw fail('요청 자료는 512 KiB 이하여야 합니다.', 413);
    chunks.push(chunk);
  }
  try {
    const data = JSON.parse(Buffer.concat(chunks));
    if (!data || Array.isArray(data) || typeof data !== 'object') throw new Error();
    return data;
  } catch { throw fail('올바른 JSON 객체가 필요합니다.'); }
}
export function normalizeSnapshot(raw, project) {
  if (!raw || typeof raw !== 'object' || raw.schemaVersion !== 1) throw fail('지원하는 schemaVersion: 1 수집 파일이 필요합니다.');
  let url;
  try { url = new URL(string(raw.url, '수집 URL', 4096)); } catch { throw fail('수집 URL이 올바르지 않습니다.'); }
  if (url.origin !== project.origin || url.username || url.password || !project.paths.includes(url.pathname)) throw fail('수집 URL이 프로젝트의 origin/허용 경로와 일치하지 않습니다.');
  const result = { schemaVersion: 1, url: redact(url.href), title: redact(String(raw.title ?? '').slice(0, 500)), capturedAt: String(raw.capturedAt ?? '').slice(0, 40), source: 'untrusted-browser-import' };
  for (const key of ['endpoints', 'comments', 'forms']) {
    if (raw[key] !== undefined && !Array.isArray(raw[key])) throw fail(`${key}는 배열이어야 합니다.`);
    result[key] = (raw[key] ?? []).slice(0, 100).map(entry => {
      // Treat imported data as inert strings; never execute or auto-fetch a supplied URL.
      const serialized = typeof entry === 'string' ? entry : JSON.stringify(entry);
      return redact(serialized.slice(0, 2000));
    });
  }
  return result;
}
export function createApp({ dataFile = join(process.env.PENTRI_DATA_DIR || '.pentri', 'pentri.sqlite'), ollamaUrl = process.env.PENTRI_OLLAMA_URL || 'http://127.0.0.1:11434', ollama, runnerOptions = {} } = {}) {
  const ai = ollama ?? new Ollama({ baseUrl: ollamaUrl });
  const store = new Store(dataFile, { recover: false });
  const token = randomBytes(32).toString('hex');
  const analyses = new Map();
  let appOrigin;
  const ollamaPort = Number(new URL(ollamaUrl).port || (new URL(ollamaUrl).protocol === 'https:' ? 443 : 80));
  const runner = new Runner(store, { ...runnerOptions, onAI: analyzeRun });
  async function analyzeRun(runId, model) {
    const run = store.get('run', runId);
    if (!run) throw fail('실행을 찾을 수 없습니다.', 404);
    if (['queued', 'running'].includes(run.status)) throw fail('진단이 완료된 후 AI 검토를 실행하세요.', 409);
    if (analyses.size) throw fail('AI 검토가 실행 중입니다.', 409);
    const selected = string(model, '모델', 200);
    const findings = run.checks.filter(c => c.outcome === 'fail').map(c => {
      const finding = store.list('finding', run.projectId).find(f => f.ruleId === c.ruleId && f.url === c.url);
      return finding && { id: finding.id, ruleId: c.ruleId, title: c.title, severity: c.severity, description: c.description, remediation: c.remediation, evidenceId: c.evidenceId };
    }).filter(Boolean);
    if (!findings.length) throw fail('AI가 검토할 관찰 사항이 없습니다.');
    const controller = new AbortController();
    analyses.set(run.projectId, { controller, runId });
    run.ai = { status: 'running', model: selected, startedAt: now() }; store.save('run', run);
    store.event(run.projectId, 'ai.started', { runId, model: selected, findingIds: findings.map(f => f.id), dataPolicy: 'normalized-rule-findings-only-no-url-or-body' });
    try {
      const batches = [];
      for (let index = 0; index < findings.length; index += 4) {
        controller.signal.throwIfAborted();
        batches.push(await ai.analyze({ model: selected, findings: findings.slice(index, index + 4), signal: controller.signal }));
        store.save('run', { ...store.get('run', runId), ai: { ...run.ai, progress: { done: Math.min(index + 4, findings.length), total: findings.length } } });
      }
      const result = { ...batches[0], generatedAt: now(), suggestions: batches.flatMap(batch => batch.suggestions), limitations: [...new Set(batches.map(batch => batch.limitations))].join('\n'), batches: batches.map(({ modelDigest, promptVersion }) => ({ modelDigest, promptVersion })) };
      store.save('run', { ...store.get('run', runId), ai: { ...redact(result), status: 'completed' } });
      store.event(run.projectId, 'ai.completed', { runId, model: selected, resultHash: hash(result), modelDigest: result.modelDigest, promptVersion: result.promptVersion });
    } catch (error) {
      store.save('run', { ...store.get('run', runId), ai: { status: 'failed', model: selected, error: redact(error.message), finishedAt: now() } });
      store.event(run.projectId, 'ai.failed', { runId, error: error.message });
      throw error;
    } finally { analyses.delete(run.projectId); }
    return store.get('run', runId);
  }
  function json(res, status, value) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(value)); }
  function secure(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    if (!appOrigin || req.headers.host !== new URL(appOrigin).host) throw fail('허용되지 않은 Host입니다. 127.0.0.1 주소로 접속하세요.', 403);
    if (req.headers.origin && req.headers.origin !== appOrigin) throw fail('다른 origin의 요청은 허용하지 않습니다.', 403);
    const site = req.headers['sec-fetch-site'];
    // Cross-site top-level navigation may open the UI, but cannot obtain session/API data.
    if (site && !['none', 'same-origin'].includes(site) && (new URL(req.url, appOrigin).pathname.startsWith('/api/') || req.headers['sec-fetch-mode'] !== 'navigate')) throw fail('교차 사이트 요청을 차단했습니다.', 403);
  }
  const server = http.createServer(async (req, res) => {
    try {
      secure(req, res);
      const url = new URL(req.url, appOrigin);
      const path = url.pathname;
      if (req.method === 'GET' && path === '/api/session') return json(res, 200, { token });
      if (path.startsWith('/api/')) {
        const provided = req.headers['x-pentri-token'];
        if (typeof provided !== 'string' || !/^[a-f0-9]{64}$/.test(provided) || !timingSafeEqual(Buffer.from(provided), Buffer.from(token))) throw fail('세션이 만료되었거나 인증되지 않았습니다. 페이지를 새로고침하세요.', 401);
        if (req.method === 'GET' && path === '/api/status') return json(res, 200, { version, ollama: await ai.status(), limits: { maxPaths: 20, maxResponseBytes: 262144, timeoutMs: 8000, intervalMs: runner.intervalMs, bind: appOrigin, activeRun: runner.active?.runId ?? null } });
        if (path === '/api/projects') {
          if (req.method === 'GET') return json(res, 200, { projects: store.list('project') });
          if (req.method === 'POST') {
            const body = await bodyJSON(req);
            const plan = validatePlan(body, { blockedPorts: runner.blockedPorts });
            const project = { id: id('project'), name: string(body.name, '프로젝트 이름', 120), ...plan, createdAt: now() };
            store.save('project', project); store.event(project.id, 'project.created', { scope: plan });
            return json(res, 201, { project });
          }
        }
        const pm = path.match(/^\/api\/projects\/([^/]+)(?:\/(runs|report|import))?$/);
        if (pm) {
          const project = store.get('project', pm[1]); if (!project) throw fail('프로젝트를 찾을 수 없습니다.', 404);
          if (!pm[2] && req.method === 'GET') return json(res, 200, store.detail(project.id));
          if (!pm[2] && req.method === 'DELETE') {
            if (runner.active?.projectId === project.id || analyses.has(project.id)) throw fail('진단/AI 검토가 끝난 후 삭제하세요.', 409);
            store.deleteProject(project.id); return json(res, 200, { deleted: true });
          }
          if (pm[2] === 'runs' && req.method === 'POST') {
            const body = await bodyJSON(req);
            if (body.approved !== true) throw fail('대상과 정확한 경로 목록에 대한 점검 승인이 필요합니다.');
            if (body.ai !== undefined && typeof body.ai !== 'boolean') throw fail('ai는 boolean이어야 합니다.');
            if (body.ai) string(body.model, '모델', 200);
            return json(res, 202, { run: runner.start(project, body) });
          }
          if (pm[2] === 'report' && req.method === 'GET') {
            const format = url.searchParams.get('format') ?? 'json';
            if (!['json', 'html'].includes(format)) throw fail('보고서 형식은 json 또는 html입니다.');
            store.event(project.id, 'report.exported', { format });
            const detail = store.detail(project.id);
            res.setHeader('Content-Disposition', `attachment; filename="pentri-${project.id}.${format}"`);
            if (format === 'json') return json(res, 200, reportData(detail));
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(reportHTML(detail));
          }
          if (pm[2] === 'import' && req.method === 'POST') {
            const body = await bodyJSON(req); const snapshot = normalizeSnapshot(body.snapshot, project);
            const imported = { id: id('import'), projectId: project.id, createdAt: now(), snapshot, sha256: hash(snapshot) };
            store.save('import', imported); store.event(project.id, 'snapshot.imported', { importId: imported.id, sha256: imported.sha256, source: snapshot.source });
            return json(res, 201, { imported });
          }
        }
        const rm = path.match(/^\/api\/runs\/([^/]+)(?:\/(cancel|analyze))?$/);
        if (rm) {
          const run = store.get('run', rm[1]); if (!run) throw fail('실행을 찾을 수 없습니다.', 404);
          if (req.method === 'GET' && !rm[2]) return json(res, 200, { run });
          if (req.method === 'POST' && rm[2] === 'cancel') {
            await bodyJSON(req);
            const activeAI = analyses.get(run.projectId);
            if (activeAI?.runId === run.id) {
              activeAI.controller.abort(new Error('AI 검토를 중단했습니다.'));
              store.event(run.projectId, 'ai.cancel_requested', { runId: run.id });
            } else runner.cancel(run.id);
            return json(res, 202, { cancelling: true });
          }
          if (req.method === 'POST' && rm[2] === 'analyze') {
            const body = await bodyJSON(req);
            // Return immediately for long local model inference; progress stays persistent.
            const promise = analyzeRun(run.id, body.model);
            await Promise.race([promise, new Promise(resolve => setImmediate(resolve))]);
            promise.catch(() => {});
            return json(res, 202, { run: store.get('run', run.id) });
          }
        }
        const fm = path.match(/^\/api\/findings\/([^/]+)\/review$/);
        if (fm && req.method === 'POST') {
          const finding = store.get('finding', fm[1]); if (!finding) throw fail('관찰 사항을 찾을 수 없습니다.', 404);
          const body = await bodyJSON(req);
          if (!['candidate', 'confirmed', 'dismissed', 'fixed'].includes(body.status)) throw fail('허용되지 않은 판단 상태입니다.');
          const note = redact(string(body.note, '판단 근거', 4000));
          const updated = { ...finding, status: body.status, reviewNote: note, reviewedAt: now(), reviewedBy: 'local-operator' };
          store.save('finding', updated); store.event(finding.projectId, 'finding.reviewed', { findingId: finding.id, before: finding.status, status: body.status, note });
          return json(res, 200, { finding: updated });
        }
        throw fail('API 경로 또는 메서드를 찾을 수 없습니다.', 404);
      }
      if (req.method !== 'GET') throw fail('허용되지 않은 메서드입니다.', 405);
      const files = { '/': ['index.html', 'text/html'], '/index.html': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/style.css': ['style.css', 'text/css'], '/styles.css': ['styles.css', 'text/css'] };
      const file = files[path]; if (!file) throw fail('파일을 찾을 수 없습니다.', 404);
      const content = await readFile(join(webDir, file[0])); res.writeHead(200, { 'Content-Type': `${file[1]}; charset=utf-8` }); res.end(content);
    } catch (error) {
      if (!res.headersSent) json(res, error.status ?? 400, { error: redact(error.message ?? '요청을 처리하지 못했습니다.') });
      else res.end();
    }
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000;
  return { server, store, runner, analyses,
    async listen(port = 8787) {
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
      const actualPort = server.address().port;
      appOrigin = `http://127.0.0.1:${actualPort}`;
      store.recoverJobs();
      runner.blockedPorts = [...new Set([actualPort, 8787, 11434, ollamaPort])];
      return appOrigin;
    },
    async close() {
      await runner.stop();
      for (const { controller } of analyses.values()) controller.abort();
      while (analyses.size) await new Promise(resolve => setTimeout(resolve, 10));
      await new Promise(resolve => server.close(resolve)); store.close();
    }
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const port = Number(process.env.PENTRI_PORT || 8787);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PENTRI_PORT는 1~65535 정수여야 합니다.');
  const app = createApp();
  console.log(`PenTri Local ${version}\n${await app.listen(port)}\n종료: Ctrl+C · 진단 자료는 .pentri/ 또는 PENTRI_DATA_DIR에 저장됩니다.`);
  let closing = false;
  for (const event of ['SIGINT', 'SIGTERM']) process.on(event, async () => { if (!closing) { closing = true; await app.close(); process.exit(0); } });
}
