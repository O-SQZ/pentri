import { now, hash } from './store.mjs';
import { redact } from './redact.mjs';
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export function reportData(detail) {
  return redact({ schemaVersion: 1, product: 'PenTri Local', version: '1.20.0-alpha.1', exportedAt: now(), limitations: [
    '명시된 경로의 HTTP 구성 관찰이며 전체 웹 취약점 진단을 완료했다는 의미가 아닙니다.',
    'candidate는 검토 전 관찰, confirmed/fixed는 검토자 판단입니다. AI 의견은 실행 권한이나 확정 판정이 없습니다.',
    'not_observed는 재검사에서 해당 규칙이 통과한 상태이며 전체 조치 완료를 증명하지 않습니다. 실패·미검사는 별도 표시합니다.',
    '본문은 최대 256 KiB 수신 후 최대 16,000자를 마스킹해 보관합니다. 개인정보/업무기밀의 완전한 제거를 보장하지 않습니다.',
    '원문 응답 전체는 보관하지 않습니다. sha256은 수신 본문(잘린 경우 prefix), storedSha256은 저장 증적을 식별합니다.',
    '로컬 감사 해시 체인은 외부 서명이 없으며 DB 전체 재작성/끝부분 삭제를 탐지하지 못합니다.',
    '브라우저 수집 JSON은 검증되지 않은 참고 자료이며 서버 직접 관찰과 구별합니다.'
  ], ...detail });
}
export function reportHTML(detail) {
  const data = reportData(detail);
  const rows = data.findings.map(f => `<tr><td>${escapeHTML(f.severity)}</td><td>${escapeHTML(f.title)}<br><small>${escapeHTML(f.ruleId)} · ${escapeHTML(f.url)}</small></td><td>${escapeHTML(f.status)}<br>${escapeHTML(f.retestStatus)}</td><td>${escapeHTML(f.description)}<br><strong>조치안:</strong> ${escapeHTML(f.remediation)}<br><strong>검토:</strong> ${escapeHTML(f.reviewNote)}<br><small>증적 ${escapeHTML(f.evidenceId)}</small></td></tr>`).join('');
  const runs = data.runs.map(r => `<article><h3>${escapeHTML(r.id)} — ${escapeHTML(r.status)}</h3><p>${escapeHTML(r.startedAt)} / ${escapeHTML(r.finishedAt)} · ${r.progress.done}/${r.progress.total} 요청 · 실패 ${r.errors.length}</p><pre>${escapeHTML(JSON.stringify({ scope: r.scope, error: r.error, errors: r.errors, checks: r.checks, ai: r.ai }, null, 2))}</pre></article>`).join('');
  const evidence = data.evidence.map(e => `<details><summary>${escapeHTML(e.id)} · ${escapeHTML(e.url)} · HTTP ${escapeHTML(e.status)}</summary><pre>${escapeHTML(JSON.stringify(e, null, 2))}</pre></details>`).join('');
  return `<!doctype html><html lang="ko"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PenTri · ${escapeHTML(data.project.name)}</title><style>body{font:15px/1.7 system-ui,sans-serif;max-width:1120px;margin:40px auto;padding:0 24px;color:#182b3a}h1,h2{color:#124f5b}table{width:100%;border-collapse:collapse}td,th{border:1px solid #c6d2d8;padding:12px;text-align:left;vertical-align:top}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f7;padding:16px;font:12px/1.6 monospace}small{color:#536873}article,details{margin:18px 0}footer{border-top:1px solid #ccd;margin-top:40px;font-size:12px}@media print{details{display:block}pre{font-size:10px}body{margin:0}}</style><h1>PenTri 진단 기록</h1><p>${escapeHTML(data.project.name)} · ${escapeHTML(data.project.origin)} · ${escapeHTML(data.project.networkPolicy)}</p><p>내보내기 ${escapeHTML(data.exportedAt)} · v${data.version}</p><h2>범위와 한계</h2><pre>${escapeHTML(JSON.stringify(data.project.paths, null, 2))}</pre><ul>${data.limitations.map(v => `<li>${escapeHTML(v)}</li>`).join('')}</ul><h2>발견 사항 및 이행 확인</h2><table><thead><tr><th>심각도</th><th>관찰</th><th>판단/재검사</th><th>근거 및 조치</th></tr></thead><tbody>${rows || '<tr><td colspan="4">등록된 관찰 없음. 실행 범위와 검사 상태를 확인하세요.</td></tr>'}</tbody></table><h2>실행·규칙 결과·AI 의견</h2>${runs}<h2>증적</h2>${evidence}<h2>브라우저 참고 자료</h2><pre>${escapeHTML(JSON.stringify(data.imports, null, 2))}</pre><h2>감사 기록</h2><pre>${escapeHTML(JSON.stringify({ integrity: data.integrity, events: data.events }, null, 2))}</pre><footer>보고서 데이터 SHA256: ${hash(data)} · JSON 내보내기의 exportedAt은 각 요청 시 생성됩니다.</footer></html>`;
}
