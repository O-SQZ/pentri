const $ = selector => document.querySelector(selector);
const state = { token: null, status: null, projects: [], detail: null, projectId: null, tab: 'recon', findingId: null, runId: null, model: '', approved: false, automaticAI: false, drafts: new Map(), busy: false, loading: false };
const runLabels = { queued: '대기 중', running: '진단 중', completed: '진단 완료', cancelled: '중단됨', failed: '실행 실패', interrupted: '앱 종료로 중단' };
const reviewLabels = { candidate: '검토 후보', confirmed: '확인됨', dismissed: '제외됨', fixed: '조치 확인' };
const retestLabels = { not_checked: '재검사 대기', still_observed: '계속 관찰됨', first_observed: '최초 관찰', not_observed: '이번에 관찰되지 않음', inconclusive: '확인 불충분' };
const date = value => value ? new Date(value).toLocaleString('ko-KR', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
const array = value => Array.isArray(value) ? value : [];
function node(tag, attrs = {}, children = []) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'class') el.className = value;
    else if (key === 'text') el.textContent = value ?? '';
    else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else if (key in el && !key.startsWith('aria-')) el[key] = value;
    else el.setAttribute(key, value);
  }
  for (const child of [].concat(children)) if (child != null) el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return el;
}
const pill = (text, tone = '') => node('span', { class: `pill ${tone}`, text });
const empty = (title, text = '') => node('div', { class: 'empty' }, [node('strong', { text: title }), text]);
const panel = (title, children, aside) => node('section', { class: 'panel' }, [node('div', { class: 'panel-title' }, [node('h2', { text: title }), aside]), ...children]);
const button = (text, action, className = '', disabled = false) => node('button', { type: 'button', text, class: className, onclick: action, disabled });
const jsonDetails = (title, data) => node('details', {}, [node('summary', { text: title }), node('pre', { text: JSON.stringify(data, null, 2) })]);
const isActive = run => ['queued', 'running'].includes(run?.status);
function notify(message, error = false) {
  $('#notice').hidden = !message;
  $('#notice').textContent = message;
  $('#notice').className = error ? 'error' : '';
}
async function api(path, options = {}) {
  const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store', ...options, headers: { 'X-Pentri-Token': state.token, ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers } });
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try { const data = await response.json(); message = data.error?.message || data.error || data.message || message; } catch { /* Preserve HTTP status. */ }
    throw new Error(typeof message === 'string' ? message : JSON.stringify(message));
  }
  return options.raw ? response : response.status === 204 ? {} : response.json();
}
async function action(fn, message = '') {
  if (state.busy) return;
  state.busy = true;
  try { await fn(); if (message) notify(message); await refreshDetail(); }
  catch (error) { notify(error.message, true); }
  finally { state.busy = false; renderPane(); }
}
async function refreshStatus() {
  state.status = await api('/api/status');
  const ollama = state.status.ollama || {};
  $('#model-status').textContent = ollama.available ? `Ollama · ${array(ollama.models).length}개 로컬 모델` : 'Ollama · 연결 대기';
  $('#model-status').className = `pill ${ollama.available ? 'good' : ''}`;
  $('#version').textContent = `v${state.status.version || '1.20 alpha'}`;
  const models = array(ollama.models).map(item => typeof item === 'string' ? item : item.name).filter(Boolean);
  if (!models.includes(state.model)) state.model = models[0] || '';
}
async function refreshProjects() {
  const data = await api('/api/projects');
  state.projects = array(data.projects ?? data);
  renderProjects();
}
async function selectProject(id) {
  state.projectId = id; state.detail = null; state.findingId = null; state.runId = null; state.approved = false;
  renderProjects(); $('#pane').replaceChildren(empty('프로젝트를 불러오는 중입니다.'));
  await refreshDetail();
}
async function refreshDetail({ polling = false } = {}) {
  if (!state.projectId || state.loading) return;
  const id = state.projectId;
  state.loading = true;
  try {
    const detail = await api(`/api/projects/${encodeURIComponent(id)}`);
    if (state.projectId !== id) return;
    const changed = JSON.stringify(detail) !== JSON.stringify(state.detail);
    state.detail = detail;
    renderOverview();
    const editing = ['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement?.tagName);
    if (!polling || (changed && !editing)) renderPane();
  } finally { state.loading = false; }
}
function renderProjects() {
  $('#projects').replaceChildren(...state.projects.map(project => button('', () => selectProject(project.id).catch(error => notify(error.message, true)), `project-button ${project.id === state.projectId ? 'active' : ''}`)));
  [...$('#projects').children].forEach((el, index) => {
    el.append(node('span', { class: 'project-glyph', text: '◈' }), node('span', { text: state.projects[index].name }));
    if (state.projects[index].id === state.projectId) el.setAttribute('aria-current', 'page');
  });
  $('#welcome').hidden = state.projects.length > 0;
  $('#workspace').hidden = !state.projectId;
}
function renderOverview() {
  if (!state.detail) return;
  const { project, findings, evidence, runs } = state.detail;
  $('#welcome').hidden = true; $('#workspace').hidden = false;
  $('#project-title').textContent = project.name;
  $('#project-origin').textContent = project.origin;
  $('#network-badge').textContent = project.networkPolicy === 'public' ? '외부망 포함 · 지정 대상' : '내부망 · 지정 대상';
  const active = array(runs).find(isActive);
  const metrics = [
    ['지정된 경로', array(project.paths).length, '정확한 GET 요청 범위'],
    ['검토할 발견 사항', array(findings).filter(f => ['candidate', 'confirmed'].includes(f.status)).length, '관찰과 검토 결과를 구분', true],
    ['보관된 증적', array(evidence).length, '마스킹 · 해시 · 수집 시각'],
    ['진단 실행', array(runs).length, active ? `${active.progress?.done || 0} / ${active.progress?.total || 0} 진행 중` : '이전 실행과 재검사 이력']
  ];
  $('#metrics').replaceChildren(...metrics.map(([label, value, note, accent]) => node('div', { class: 'metric' }, [node('small', { text: label }), node('strong', { text: value, class: accent ? 'metric-accent' : '' }), node('span', { class: 'metric-note', text: note })])));
}
function switchTab(tab) {
  state.tab = tab;
  document.querySelectorAll('[data-tab]').forEach(el => {
    el.classList.toggle('active', el.dataset.tab === tab);
    if (el.dataset.tab === tab) el.setAttribute('aria-current', 'page'); else el.removeAttribute('aria-current');
  });
  renderPane();
}
function modelSelect() {
  const select = node('select', { 'aria-label': 'Ollama 로컬 모델', onchange: event => { state.model = event.target.value; } });
  const models = array(state.status?.ollama?.models);
  if (!models.length) select.append(node('option', { text: '설치된 로컬 모델 없음', value: '' }));
  for (const model of models) { const name = typeof model === 'string' ? model : model.name; select.append(node('option', { text: name, value: name })); }
  select.value = state.model;
  return select;
}
function scopeList(project) {
  return node('div', { class: 'scope-list' }, array(project.paths).map(path => node('div', { class: 'scope-row' }, [node('span', { class: 'method', text: 'GET' }), node('span', { class: 'mono', text: `${project.origin}${path}` })])));
}
function renderRecon() {
  const { project } = state.detail;
  const runs = array(state.detail.runs);
  const active = runs.find(isActive);
  const latest = runs.find(r => r.id === state.runId) || runs[0];
  const startButton = button(runs.length ? '같은 범위로 재검사' : '진단 시작', () => action(async () => {
    if (!state.approved) throw new Error('실행할 경로를 확인하고 승인 항목을 선택하세요.');
    const result = await api(`/api/projects/${project.id}/runs`, { method: 'POST', body: JSON.stringify({ approved: true, ai: state.automaticAI, model: state.model || undefined }) });
    state.runId = result.run?.id || result.id || null; state.approved = false;
  }, '진단을 시작했습니다. 진행 상태와 증적이 자동으로 갱신됩니다.'), 'primary', state.busy || !!active || !state.approved);
  const approval = node('label', { class: 'check-label' }, [node('input', { type: 'checkbox', checked: state.approved, onchange: event => { state.approved = event.target.checked; startButton.disabled = !state.approved || !!active || state.busy; } }), '이 대상의 진단 권한과 위 GET 요청 경로를 확인했습니다. GET으로 상태가 바뀌는 경로는 제외했습니다.']);
  const automaticAI = node('label', { class: 'check-label' }, [node('input', { type: 'checkbox', checked: state.automaticAI, disabled: !state.model, onchange: event => { state.automaticAI = event.target.checked; } }), '완료 후 선택한 로컬 모델로 분석 보조']);
  const controls = panel('실행 범위', [node('p', { text: '지정한 경로의 응답을 순서대로 수집하고 HTTP 구성 점검을 수행합니다.' }), scopeList(project), node('div', { class: 'select-row' }, [modelSelect()]), automaticAI, approval, node('div', { class: 'actions' }, [startButton, ...(active ? [button('진단 중단', () => action(() => api(`/api/runs/${active.id}/cancel`, { method: 'POST', body: '{}' }), '중단을 요청했습니다.'), 'danger', state.busy)] : [])]), node('p', { class: 'help', text: '리다이렉트·새 경로는 자동 추적하지 않습니다. AI 의견은 관찰 근거와 함께 별도로 기록합니다.' })], pill(project.networkPolicy === 'public' ? 'PUBLIC' : 'PRIVATE'));
  const historyChildren = runs.length ? runs.slice(0, 8).map(run => node('div', { class: 'run-item' }, [node('div', {}, [node('p', { text: date(run.startedAt) }), node('small', { text: `${run.progress?.done || 0} / ${run.progress?.total || 0}개 요청 · ${array(run.checks).length}개 검사` })]), button(runLabels[run.status] || run.status, () => { state.runId = run.id; renderPane(); }, run.id === latest?.id ? 'quiet active' : 'quiet')])) : [empty('아직 실행 이력이 없습니다.', '첫 진단을 시작하면 진행 상태가 여기에 표시됩니다.')];
  const right = node('div', {}, [panel('실행 이력', historyChildren, node('small', { text: `${runs.length} RUNS` }))]);
  if (latest) right.append(renderRunStatus(latest));
  const layout = node('div', { class: 'two-column' }, [controls, right]);
  if (latest) layout.append(node('div', { class: 'span-all' }, [renderChecks(latest)]));
  return layout;
}
function renderRunStatus(run) {
  const done = run.progress?.done || 0, total = run.progress?.total || 0;
  const fill = node('div', { class: 'progress-fill' }); fill.style.width = `${total ? Math.min(100, done / total * 100) : 0}%`;
  return panel('실행 상태', [node('div', { class: 'row-between' }, [pill(runLabels[run.status] || run.status, run.status === 'completed' ? 'good' : run.status === 'failed' ? 'bad' : 'warn'), node('span', { class: 'subtle', text: `${done} / ${total}` })]), node('div', { class: 'progress', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': String(total || 1), 'aria-valuenow': String(done), 'aria-label': '진단 진행률' }, [fill]), ...(run.error ? [node('p', { class: 'inline-error', text: run.error })] : []), ...array(run.errors).map(error => node('p', { class: 'inline-error', text: `${error.url || ''} · ${error.message || error.error || ''}` })), node('p', { class: 'help', text: `시작 ${date(run.startedAt)}${run.finishedAt ? ` · 종료 ${date(run.finishedAt)}` : ''}` }), ...(run.ai ? [pill(`AI ${run.ai.status === 'completed' ? '분석 완료' : run.ai.status === 'running' ? '분석 중' : '분석 실패'}`, run.ai.status === 'completed' ? 'good' : 'warn')] : [])]);
}
function renderChecks(run) {
  const checks = array(run.checks);
  if (!checks.length) return panel('규칙별 검사 결과', [empty('완료된 검사가 없습니다.', '응답을 받으면 통과·관찰·확인 불충분 결과를 표시합니다.')]);
  const table = node('table', {}, [node('thead', {}, [node('tr', {}, ['검사 항목', '결과', '대상 경로', '근거'].map(text => node('th', { text })))]), node('tbody', {}, checks.map(check => node('tr', {}, [node('td', {}, [node('strong', { text: check.title || check.ruleId }), node('div', { class: 'evidence-id', text: check.ruleId })]), node('td', {}, [pill(({ pass: '통과', fail: '관찰됨', unknown: '확인 불충분' })[check.outcome] || check.outcome, check.outcome === 'pass' ? 'good' : 'warn')]), node('td', { class: 'mono', text: check.url }), node('td', { text: typeof check.evidence === 'string' ? check.evidence : JSON.stringify(check.evidence ?? '') })])))]);
  return panel('규칙별 검사 결과', [node('div', { class: 'table-wrap' }, [table])], node('small', { text: `${checks.length} CHECKS` }));
}
function renderAnalyze() {
  const findings = array(state.detail.findings);
  const selected = findings.find(item => item.id === state.findingId) || findings[0];
  state.findingId = selected?.id || null;
  const list = panel('발견 사항', findings.length ? findings.map(finding => {
    const item = button('', () => { state.findingId = finding.id; renderPane(); }, `finding-item ${finding.id === state.findingId ? 'active' : ''}`);
    item.append(node('div', { class: 'finding-badges' }, [pill(finding.severity || 'info', ['critical', 'high'].includes(finding.severity) ? 'bad' : 'warn'), pill(reviewLabels[finding.status] || finding.status)]), node('strong', { text: finding.title }), node('span', { class: 'mono', text: finding.url }));
    return item;
  }) : [empty('검토할 발견 사항이 없습니다.', 'Recon에서 진단을 실행하세요. 요청 실패나 검사 누락은 통과 판정이 아닙니다.')], node('small', { text: `${findings.length} FINDINGS` }));
  const layout = node('div', { class: 'findings-layout' }, [list, selected ? renderFinding(selected) : panel('근거와 판단', [empty('왼쪽에서 발견 사항을 선택하세요.', '관찰 내용·조치안·재검사 증적을 확인할 수 있습니다.')])]);
  layout.append(node('div', { class: 'span-all' }, [renderAI()]));
  return layout;
}
function evidenceView(evidence, title = '수집 증적') {
  if (!evidence) return node('p', { class: 'help', text: '연결된 증적을 찾을 수 없습니다.' });
  return node('details', {}, [node('summary', { text: `${title} · HTTP ${evidence.status} · ${date(evidence.createdAt)}` }), node('p', { class: 'mono subtle', text: evidence.url }), node('div', { class: 'finding-badges' }, [pill(`${evidence.bytes || 0} bytes`), ...(evidence.truncated ? [pill('응답 제한 도달', 'warn')] : []), ...(evidence.excerptTruncated ? [pill('발췌본', 'warn')] : [])]), node('pre', { text: JSON.stringify(evidence.headers || {}, null, 2) }), node('pre', { text: evidence.excerpt || '(본문 없음)' }), node('div', { class: 'hash', text: `수집 원문 SHA-256 (${evidence.hashScope || 'body'}): ${evidence.sha256 || '—'}` }), node('div', { class: 'hash', text: `마스킹 보관 자료 SHA-256: ${evidence.storedSha256 || '—'}` }), node('div', { class: 'evidence-id', text: evidence.id })]);
}
function renderFinding(finding) {
  const evidence = array(state.detail.evidence).find(item => item.id === finding.evidenceId);
  const retestEvidence = array(state.detail.evidence).find(item => item.id === finding.retestEvidenceId);
  const draft = state.drafts.get(finding.id) || { status: finding.status, note: finding.reviewNote || '' };
  const select = node('select', { 'aria-label': '검토 결과', onchange: event => { draft.status = event.target.value; state.drafts.set(finding.id, draft); } }, Object.entries(reviewLabels).map(([value, text]) => node('option', { value, text })));
  select.value = draft.status;
  const note = node('textarea', { value: draft.note, rows: 4, placeholder: '확인한 근거, 제외 사유 또는 이행 조치 검증 내용을 기록하세요.', oninput: event => { draft.note = event.target.value; state.drafts.set(finding.id, draft); } });
  const content = [node('div', { class: 'finding-badges' }, [pill(finding.severity), pill(retestLabels[finding.retestStatus] || finding.retestStatus || '최초 관찰')]), node('p', { class: 'section-label', text: '관찰 내용' }), node('p', { class: 'copy', text: finding.description }), node('p', { class: 'mono subtle', text: finding.url }), evidenceView(evidence), ...(retestEvidence ? [evidenceView(retestEvidence, '재검사 증적')] : []), node('p', { class: 'section-label', text: '조치·개선 제안' }), node('p', { class: 'copy', text: finding.remediation || '추가 검토가 필요합니다.' }), node('div', { class: 'callout', text: '재검사에서 관찰되지 않아도 조치 완료를 뜻하지 않습니다. 접근 가능 여부와 변경 증적을 확인한 뒤 검토자가 판단하세요.' }), node('label', {}, ['검토 결과', select]), node('label', {}, ['판단 근거 · 메모', note]), node('div', { class: 'actions' }, [button('판단 저장', () => action(async () => {
    await api(`/api/findings/${finding.id}/review`, { method: 'POST', body: JSON.stringify({ status: select.value, note: note.value }) });
    state.drafts.delete(finding.id);
  }, '검토 판단과 메모를 기록했습니다.'), 'primary', state.busy)]), node('p', { class: 'help', text: `최초 ${date(finding.firstSeen)} · 마지막 관찰 ${date(finding.lastSeen)}` })];
  const el = panel(finding.title, content); el.classList.add('finding-detail'); return el;
}
function renderAI() {
  const runs = array(state.detail.runs);
  const eligible = runs.find(run => run.status === 'completed');
  const withAI = runs.find(run => run.ai);
  const ai = withAI?.ai;
  const content = [node('p', { text: '수집된 근거를 설치된 Ollama 모델이 검토합니다. 모델의 의견은 실행 명령이나 취약성 확정으로 사용되지 않습니다.' }), node('div', { class: 'select-row' }, [modelSelect(), button(ai?.status === 'running' ? 'AI 분석 중…' : '최근 완료 진단 분석', () => action(() => api(`/api/runs/${eligible.id}/analyze`, { method: 'POST', body: JSON.stringify({ model: state.model }) }), '로컬 AI 분석 요청을 처리했습니다.'), 'primary', !eligible || !state.model || state.busy || ai?.status === 'running')])];
  if (!state.status?.ollama?.available) content.push(node('p', { class: 'help', text: state.status?.ollama?.error || 'Ollama를 시작하고 로컬 모델을 준비한 뒤 상단 새로고침을 누르세요.' }));
  if (ai) {
    content.push(node('hr'), pill(`${ai.model || 'Ollama'} · ${ai.status}`, ai.status === 'completed' ? 'good' : 'warn'));
    if (ai.status === 'running') content.push(button('AI 분석 중단', () => action(() => api(`/api/runs/${withAI.id}/cancel`, { method: 'POST', body: '{}' }), 'AI 분석 중단을 요청했습니다.'), 'danger'));
    if (ai.limitations) content.push(node('p', { class: 'help', text: ai.limitations }));
    if (ai.error) content.push(node('p', { class: 'inline-error', text: ai.error }));
    if (ai.summary) content.push(node('p', { class: 'copy', text: ai.summary }));
    for (const suggestion of array(ai.suggestions ?? ai.result?.suggestions)) content.push(node('div', { class: 'import-item' }, [node('h3', { text: suggestion.title || suggestion.ruleId || '분석 의견' }), node('p', { class: 'copy', text: suggestion.assessment || suggestion.analysis || suggestion.explanation || suggestion.description || suggestion.rationale || '' }), node('p', { class: 'copy', text: suggestion.remediation || suggestion.recommendation || '' }), jsonDetails('검증된 의견과 근거 참조', suggestion)]));
    if (ai.status === 'completed' && !array(ai.suggestions ?? ai.result?.suggestions).length) content.push(jsonDetails('AI 분석 결과 보기', ai));
  }
  return panel('로컬 AI 분석 보조', content, pill('OLLAMA', state.status?.ollama?.available ? 'good' : ''));
}
async function downloadReport(format) {
  const response = await api(`/api/projects/${state.projectId}/report?format=${format}`, { raw: true });
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = node('a', { href: url, download: `pentri-${state.projectId}-${new Date().toISOString().slice(0, 10)}.${format}` });
  document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function renderReport() {
  const { project, integrity } = state.detail;
  const findings = array(state.detail.findings), evidence = array(state.detail.evidence), events = array(state.detail.events);
  const downloads = panel('프로젝트 보고서', [node('p', { text: '진단 범위, 검사 결과, 증적, 검토 판단과 재검사 상태를 같은 프로젝트 기록으로 내보냅니다.' }), node('div', { class: 'report-summary' }, [node('strong', { text: findings.length }), node('span', {}, ['발견 사항', node('br'), `${findings.filter(item => item.status === 'confirmed').length}개 확인 · ${findings.filter(item => item.status === 'fixed').length}개 조치 확인`])]), ...[['html', 'HTML 보고서', '브라우저에서 열어 검토하고 인쇄할 수 있습니다.'], ['json', 'JSON 기록', '후속 검토와 다른 도구 연계용 구조화 자료입니다.']].map(([format, title, text]) => node('div', { class: 'download-card' }, [node('div', {}, [node('h3', { text: title }), node('p', { text })]), button('다운로드 ↓', () => action(() => downloadReport(format)), '', state.busy)])), node('p', { class: 'help', text: '내보내기 파일에는 대상 정보와 진단 증적이 포함됩니다. 공유 전에 내용과 마스킹을 확인하세요.' })]);
  const audit = panel('감사 기록', [node('div', { class: 'row-between' }, [pill(integrity ? integrity.valid ? '해시 체인 일치' : '무결성 확인 실패' : '검증 정보 없음', integrity?.valid ? 'good' : 'warn'), node('small', { text: `${integrity?.count ?? events.length} EVENTS` })]), ...(integrity?.limitation ? [node('p', { class: 'help', text: integrity.limitation })] : []), node('ul', { class: 'audit' }, [...events].reverse().slice(0, 100).map(event => node('li', {}, [node('div', { class: 'row-between' }, [node('span', { text: event.type }), node('small', { text: `#${event.seq}` })]), node('small', { text: date(event.at || event.createdAt) }), jsonDetails('이벤트 내용', event.data)]))), ...(integrity?.head ? [node('div', { class: 'hash', text: `HEAD ${integrity.head}` })] : [])]);
  const layout = node('div', { class: 'two-column' }, [downloads, audit]);
  layout.append(node('div', { class: 'span-all' }, [panel('증적 보관함', evidence.length ? evidence.map(item => evidenceView(item)) : [empty('보관된 HTTP 증적이 없습니다.', 'Recon에서 진단을 실행하면 수집됩니다.')], node('small', { text: `${evidence.length} EVIDENCE` }))]));
  return layout;
}
function renderTools() {
  const fileInput = node('input', { type: 'file', accept: '.json,application/json', class: 'file-input', 'aria-label': 'PenTri 확장 관찰 JSON' });
  const importButton = button('관찰 JSON 가져오기', () => action(async () => {
    const file = fileInput.files?.[0];
    if (!file) throw new Error('확장 수집기에서 내보낸 JSON 파일을 선택하세요.');
    if (file.size > 500 * 1024) throw new Error('관찰 파일은 500 KiB 이하여야 합니다.');
    let snapshot;
    try { snapshot = JSON.parse(await file.text()); } catch { throw new Error('유효한 JSON 파일이 아닙니다.'); }
    await api(`/api/projects/${state.projectId}/import`, { method: 'POST', body: JSON.stringify({ snapshot }) });
  }, '브라우저 관찰을 가져왔습니다. 관찰 자료로 보관되며 추가 요청을 실행하지 않습니다.'), 'primary', state.busy);
  const imports = array(state.detail.imports);
  const importPanel = panel('브라우저 관찰 가져오기', [node('p', { text: '선택 확장 수집기에서 대상 페이지의 DOM 메타데이터를 JSON으로 내보내고 이 프로젝트에 연결하세요.' }), node('ol', { class: 'subtle' }, [node('li', { text: '대상 페이지에서 PenTri 확장 아이콘을 눌러 수집 탭을 엽니다.' }), node('li', { text: '대상 URL과 관찰 내용을 확인한 뒤 JSON을 저장합니다.' }), node('li', { text: '같은 origin의 프로젝트에서 해당 파일을 가져옵니다.' })]), fileInput, node('div', { class: 'actions' }, [importButton]), node('p', { class: 'help', text: '폼의 입력 값·쿠키·브라우저 저장소는 수집하지 않습니다. URL·제목·주석에 포함된 민감정보는 파일 공유 전에 직접 확인하세요.' })]);
  const records = panel('가져온 관찰', imports.length ? imports.map(item => {
    const snapshot = item.snapshot || item.data || item;
    return node('div', { class: 'import-item' }, [node('h3', { text: snapshot.title || '브라우저 관찰' }), node('p', { class: 'mono', text: snapshot.url || item.url || '' }), node('small', { text: date(item.createdAt || snapshot.capturedAt) }), jsonDetails('관찰 내용 보기', snapshot)]);
  }) : [empty('가져온 관찰이 없습니다.', '확장 수집기는 선택 기능입니다. 독립 앱 진단은 설치 없이 사용할 수 있습니다.')]);
  const removal = panel('프로젝트 데이터 삭제', [node('p', { text: '이 프로젝트의 실행, 증적, 검토, AI 의견과 감사 기록을 함께 삭제합니다. 별도로 다운로드한 보고서는 남습니다.' }), button('프로젝트 삭제', () => {
    if (!window.confirm(`“${state.detail.project.name}” 프로젝트와 보관된 기록을 삭제할까요?`)) return;
    action(async () => {
      await api(`/api/projects/${state.projectId}`, { method: 'DELETE' });
      state.projectId = null; state.detail = null; state.drafts.clear();
      await refreshProjects();
      if (state.projects.length) await selectProject(state.projects[0].id);
    }, '프로젝트 데이터를 삭제했습니다.');
  }, 'danger', state.busy || array(state.detail.runs).some(isActive))]);
  removal.classList.add('danger-zone');
  return node('div', { class: 'two-column' }, [importPanel, records, node('div', { class: 'span-all' }, [removal])]);
}
function renderPane() {
  if (!state.detail) return;
  const renders = { recon: renderRecon, analyze: renderAnalyze, report: renderReport, tools: renderTools };
  $('#pane').replaceChildren(renders[state.tab]());
}
function showProjectDialog() { $('#create-error').textContent = ''; previewProject(); $('#project-dialog').showModal(); }
function previewProject() {
  const form = $('#project-form');
  const origin = form.elements.origin.value.trim().replace(/\/$/, '');
  const paths = form.elements.paths.value.split('\n').map(value => value.trim()).filter(Boolean);
  $('#create-preview').replaceChildren(...(paths.length ? paths.slice(0, 20).map(path => node('div', { class: 'mono', text: `GET ${origin || '(origin)'}${path}` })) : [node('span', { text: '실행할 경로를 입력하세요.' })]));
}
$('#new-project').addEventListener('click', showProjectDialog);
$('#welcome-create').addEventListener('click', showProjectDialog);
$('#close-dialog').addEventListener('click', () => $('#project-dialog').close());
$('#project-form').addEventListener('input', previewProject);
$('#project-form').addEventListener('submit', async event => {
  event.preventDefault(); const form = event.currentTarget; const submit = form.querySelector('[type="submit"]'); submit.disabled = true;
  try {
    const result = await api('/api/projects', { method: 'POST', body: JSON.stringify({ name: form.elements.name.value.trim(), origin: form.elements.origin.value.trim(), paths: form.elements.paths.value.split('\n').map(value => value.trim()).filter(Boolean), networkPolicy: form.elements.networkPolicy.value }) });
    const project = result.project || result;
    await refreshProjects(); await selectProject(project.id); switchTab('recon');
    $('#project-dialog').close(); form.reset(); notify('프로젝트를 만들었습니다. 요청 경로를 확인한 뒤 진단을 시작하세요.');
  } catch (error) { $('#create-error').textContent = error.message; }
  finally { submit.disabled = false; }
});
document.querySelectorAll('[data-tab]').forEach(el => el.addEventListener('click', () => switchTab(el.dataset.tab)));
$('#refresh').addEventListener('click', async () => {
  const el = $('#refresh'); el.disabled = true;
  try { await refreshStatus(); await refreshProjects(); await refreshDetail(); notify('프로젝트와 로컬 모델 상태를 갱신했습니다.'); }
  catch (error) { notify(error.message, true); }
  finally { el.disabled = false; }
});
async function start() {
  try {
    const response = await fetch('/api/session', { cache: 'no-store', credentials: 'same-origin' });
    if (!response.ok) throw new Error('로컬 앱 세션을 만들 수 없습니다.');
    state.token = (await response.json()).token;
    if (!state.token) throw new Error('세션 토큰이 없습니다. 앱 주소에서 다시 접속하세요.');
    await Promise.all([refreshStatus(), refreshProjects()]);
    if (state.projects.length) await selectProject(state.projects[0].id);
  } catch (error) { notify(`앱 연결 실패: ${error.message}`, true); }
}
setInterval(() => {
  if (document.hidden || !state.token || !state.projectId || state.busy) return;
  refreshDetail({ polling: true }).catch(error => notify(`상태 갱신 실패: ${error.message}`, true));
}, 2500);
start();
