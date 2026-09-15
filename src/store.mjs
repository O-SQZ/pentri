import { DatabaseSync } from 'node:sqlite';
import { randomUUID, createHash } from 'node:crypto';
import { mkdirSync, chmodSync, openSync, closeSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { redact } from './redact.mjs';

export const id = prefix => `${prefix}_${randomUUID()}`;
export const now = () => new Date().toISOString();
export const hash = value => createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');

export class Store {
  constructor(file, { recover = true } = {}) {
    if (file !== ':memory:') {
      mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
      closeSync(openSync(file, 'a', 0o600));
      // Set permissions before SQLite creates journal sidecars.
      if (process.platform !== 'win32') for (const path of [file, `${file}-wal`, `${file}-shm`]) if (existsSync(path)) chmodSync(path, 0o600);
    }
    this.db = new DatabaseSync(file);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;
      CREATE TABLE IF NOT EXISTS objects (id TEXT PRIMARY KEY, kind TEXT NOT NULL, parent TEXT, data TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS objects_parent ON objects(kind,parent);
      CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, data TEXT NOT NULL, hash TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS events_project ON events(project,seq);
      PRAGMA user_version=1;`);
    if (file !== ':memory:' && process.platform !== 'win32') chmodSync(file, 0o600);
    if (recover) this.recoverJobs();
  }
  recoverJobs() {
    for (const run of this.list('run').filter(r => ['running', 'queued'].includes(r.status))) {
      this.save('run', { ...run, status: 'interrupted', finishedAt: now(), error: '앱 종료로 실행이 중단되었습니다. 재검사가 필요합니다.' });
      this.event(run.projectId, 'run.interrupted', { runId: run.id });
    }
    for (const run of this.list('run').filter(r => r.ai?.status === 'running')) {
      this.save('run', { ...run, ai: { ...run.ai, status: 'failed', error: 'AI 분석 중 앱이 종료되었습니다.' } });
    }
  }
  save(kind, value) {
    this.db.prepare('INSERT INTO objects(id,kind,parent,data) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,parent=excluded.parent')
      .run(value.id, kind, value.projectId ?? null, JSON.stringify(value));
    return value;
  }
  get(kind, key) {
    const row = this.db.prepare('SELECT data FROM objects WHERE kind=? AND id=?').get(kind, key);
    return row ? JSON.parse(row.data) : null;
  }
  list(kind, parent) {
    const rows = parent === undefined ? this.db.prepare('SELECT data FROM objects WHERE kind=? ORDER BY rowid DESC').all(kind)
      : this.db.prepare('SELECT data FROM objects WHERE kind=? AND parent=? ORDER BY rowid DESC').all(kind, parent);
    return rows.map(r => JSON.parse(r.data));
  }
  atomic(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); this.db.exec('COMMIT'); return result; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  event(projectId, type, data = {}) {
    const previous = this.db.prepare('SELECT hash FROM events WHERE project=? ORDER BY seq DESC LIMIT 1').get(projectId)?.hash ?? '0'.repeat(64);
    const event = { projectId, type, at: now(), data: redact(data), previous };
    const digest = hash(event);
    const result = this.db.prepare('INSERT INTO events(project,data,hash) VALUES(?,?,?)').run(projectId, JSON.stringify(event), digest);
    return { ...event, seq: Number(result.lastInsertRowid), hash: digest };
  }
  events(projectId) {
    return this.db.prepare('SELECT seq,data,hash FROM events WHERE project=? ORDER BY seq').all(projectId)
      .map(row => ({ ...JSON.parse(row.data), seq: row.seq, hash: row.hash }));
  }
  verify(projectId) {
    let previous = '0'.repeat(64);
    const events = this.events(projectId);
    for (const { seq, hash: digest, ...event } of events) {
      if (event.previous !== previous || hash(event) !== digest) return { valid: false, failedAt: seq, count: events.length };
      previous = digest;
    }
    return { valid: true, count: events.length, head: previous, limitation: '외부 서명 없는 로컬 해시 체인입니다. DB 전체 재작성이나 끝부분 삭제를 증명할 수 없습니다.' };
  }
  detail(projectId) {
    const project = this.get('project', projectId);
    if (!project) return null;
    return { project, runs: this.list('run', projectId), findings: this.list('finding', projectId), evidence: this.list('evidence', projectId), imports: this.list('import', projectId), events: this.events(projectId), integrity: this.verify(projectId) };
  }
  deleteProject(projectId) {
    this.atomic(() => {
      this.db.prepare('DELETE FROM objects WHERE parent=? OR id=?').run(projectId, projectId);
      this.db.prepare('DELETE FROM events WHERE project=?').run(projectId);
    });
    this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  }
  close() { this.db.close(); }
}
