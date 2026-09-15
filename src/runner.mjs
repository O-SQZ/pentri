import { setTimeout as delay } from 'node:timers/promises';
import { requestTarget } from './network.mjs';
import { analyzeResponse, RULES_VERSION } from './analyzer.mjs';
import { redact } from './redact.mjs';
import { id, now, hash } from './store.mjs';

export class Runner {
  constructor(store, { blockedPorts = [8787, 11434], intervalMs = 500, request = requestTarget, onAI } = {}) {
    this.store = store; this.blockedPorts = blockedPorts; this.intervalMs = intervalMs; this.request = request; this.onAI = onAI; this.active = null;
  }
  start(project, { ai = false, model } = {}) {
    if (this.active) throw Object.assign(new Error('다른 진단이 실행 중입니다. 완료 또는 중단 후 시작하세요.'), { status: 409 });
    const run = { id: id('run'), projectId: project.id, status: 'queued', startedAt: now(), finishedAt: null, progress: { done: 0, total: project.paths.length }, checks: [], errors: [], ai: null, scope: { origin: project.origin, paths: [...project.paths], networkPolicy: project.networkPolicy }, rulesVersion: RULES_VERSION };
    this.store.save('run', run);
    this.store.event(project.id, 'run.approved', { runId: run.id, scope: run.scope, ai, model });
    const controller = new AbortController();
    this.active = { runId: run.id, projectId: project.id, controller, promise: null };
    this.active.promise = this.execute(project, run, controller.signal, { ai, model });
    return this.store.get('run', run.id);
  }
  cancel(runId) {
    if (this.active?.runId !== runId) throw Object.assign(new Error('실행 중인 진단이 아닙니다.'), { status: 409 });
    this.active.controller.abort();
    this.store.event(this.active.projectId, 'run.cancel_requested', { runId });
  }
  async execute(project, run, signal, options) {
    try {
      run.status = 'running'; this.store.save('run', run);
      for (const finding of this.store.list('finding', project.id)) this.store.save('finding', { ...finding, retestStatus: 'not_checked' });
      for (const path of project.paths) {
        signal.throwIfAborted();
        const url = new URL(path, project.origin).href;
        this.store.event(project.id, 'request.started', { runId: run.id, url });
        try {
          const response = await this.request(url, { signal, blockedPorts: this.blockedPorts, networkPolicy: project.networkPolicy, pinnedAddresses: run.resolvedAddresses });
          run.resolvedAddresses ??= response.resolvedAddresses;
          signal.throwIfAborted();
          const analysis = analyzeResponse(response);
          const excerpt = redact(response.body.slice(0, 16000));
          const evidence = { id: id('ev'), projectId: project.id, runId: run.id, url, status: response.status, headers: redact(response.headers), excerpt, sha256: response.sha256, hashScope: response.truncated ? 'received-prefix' : 'received-response-body', bytes: response.bytes, truncated: response.truncated, excerptTruncated: response.body.length > 16000, remoteAddress: response.remoteAddress, durationMs: response.durationMs, createdAt: now(), observations: redact(analysis.observations) };
          evidence.storedSha256 = hash({ headers: evidence.headers, excerpt, observations: evidence.observations });
          this.store.atomic(() => {
            this.store.save('evidence', evidence);
            for (const check of analysis.checks) {
              run.checks.push({ ...redact(check), url, evidenceId: evidence.id });
              const existing = this.store.list('finding', project.id).find(f => f.ruleId === check.ruleId && f.url === url);
              if (check.outcome === 'fail') {
                const finding = { ...(existing ?? {}), id: existing?.id ?? id('finding'), projectId: project.id, ruleId: check.ruleId, url, title: check.title, severity: check.severity, status: existing?.status === 'fixed' ? 'candidate' : existing?.status ?? 'candidate', description: redact(check.description), remediation: redact(check.remediation), evidenceId: evidence.id, firstSeen: existing?.firstSeen ?? now(), lastSeen: now(), retestStatus: existing ? 'still_observed' : 'first_observed', reviewNote: existing?.reviewNote ?? '' };
                this.store.save('finding', finding);
                if (existing?.status === 'fixed') this.store.event(project.id, 'finding.reopened', { findingId: finding.id, runId: run.id });
              } else if (existing) {
                this.store.save('finding', { ...existing, retestStatus: check.outcome === 'pass' ? 'not_observed' : 'inconclusive', retestEvidenceId: evidence.id, retestAt: now() });
              }
            }
            this.store.event(project.id, 'request.completed', { runId: run.id, evidenceId: evidence.id, status: response.status, bytes: response.bytes, truncated: response.truncated, sha256: evidence.sha256, storedSha256: evidence.storedSha256 });
          });
        } catch (error) {
          if (signal.aborted) throw error;
          run.errors.push({ url, message: redact(error.message) });
          for (const finding of this.store.list('finding', project.id).filter(f => f.url === url)) this.store.save('finding', { ...finding, retestStatus: 'inconclusive', retestAt: now() });
          this.store.event(project.id, 'request.failed', { runId: run.id, url, error: error.message });
        }
        run.progress.done++; this.store.save('run', run);
        if (run.progress.done < run.progress.total) await delay(this.intervalMs, undefined, { signal });
      }
      run.status = run.errors.length === project.paths.length ? 'failed' : 'completed';
      if (run.errors.length) run.error = `${run.errors.length}개 요청 실패. 실패 항목은 정상 또는 조치 완료로 판단하지 않습니다.`;
    } catch (error) {
      run.status = signal.aborted ? 'cancelled' : 'failed'; run.error = redact(error.message);
    } finally {
      run.finishedAt = now(); this.store.save('run', run);
      this.store.event(project.id, `run.${run.status}`, { runId: run.id, progress: run.progress, errors: run.errors });
      this.active = null;
    }
    if (options.ai && run.status === 'completed' && this.onAI) {
      try { await this.onAI(run.id, options.model); }
      catch { /* The AI adapter records its own failure; completed HTTP evidence remains available. */ }
    }
  }
  async stop() { if (this.active) { const active = this.active; active.controller.abort(); await active.promise; } }
}
