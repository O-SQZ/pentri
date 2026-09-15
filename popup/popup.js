// popup/popup.js — PenTri v1.10
'use strict';

let scanData    = null;
let collectData = null;
let headers     = {};
let smVerified  = new Set();
let smResults   = new Map();
let settings    = { orTarget: 'attacker.com' };
let allComments = []; // DOM + 외부 JS
let allJsHits   = { patterns:[], sensitive:[], filter:[], crypto:[], paths:[] };
let currentTabId = null; // Path Scan 결과 저장용 탭 ID

// 토글 상태
let showExtSusp=false, showApiEp=false, showExtEp=false;
let showCmSusp=false, showSmConfirm=false;

// ── 부트 ──────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  initTabs();
  initCipher();
  initCheatSheet();
  initJsAnalysis();
  initScan();
  initUpload();
  initToggles();
  initRobots();
  initSourceMap();
  initComments();
  initExport();

  document.getElementById('btn-rescan').onclick = () => {
    setStatus('스캔 중...');
    chrome.runtime.sendMessage({ type:'RESCAN' }, (resp) => {
      if (resp?.ok === false) setStatus(resp.err || '스캔 실패');
      loadAll();
    });
  };

  chrome.tabs.query({ active:true, currentWindow:true }, ([tab]) => {
    if (tab?.url?.startsWith('http')) document.getElementById('tgt-url').textContent = tab.url;
    currentTabId = tab?.id ?? null;
    loadAll();
    restorePathScan();
  });
});

// Path Scan 결과 복원 (session storage)
function restorePathScan() {
  if (currentTabId == null) return;
  chrome.runtime.sendMessage({ type:'GET_PATHSCAN', tabId: currentTabId }, (resp) => {
    if (chrome.runtime.lastError) return;
    if (resp?.data?.length) {
      scanResults = resp.data;
      renderScanResults();
      const found = scanResults.filter(isInterestingPathResult).length;
      const wrap = document.getElementById('scan-progress-bar-wrap');
      if (wrap) {
        wrap.style.display = 'block';
        updateProgress(scanResults.length, scanResults.length, found);
      }
    }
  });
}

function loadSettings() {
  chrome.runtime.sendMessage({ type:'GET_SETTINGS' }, (resp) => {
    if (resp?.data?.orTarget) settings.orTarget = resp.data.orTarget;
    const el = document.getElementById('or-target');
    if (el) el.value = settings.orTarget;
  });
}

// ── 데이터 로드 ───────────────────────────────────────────────────
function loadAll() {
  chrome.runtime.sendMessage({ type:'GET_ALL_DATA' }, (resp) => {
    if (chrome.runtime.lastError) return;
    scanData    = resp?.scan    || null;
    collectData = resp?.collect || null;
    headers     = resp?.headers || {};
    if (resp?.tabUrl) document.getElementById('tgt-url').textContent = resp.tabUrl;

    renderTech();
    renderEndpoints();
    renderExternal();
    renderSourceMaps();
    renderComments();
    renderJsPatterns();
    renderJsSensitive();
    renderUpload();
    setStatus(scanData||collectData ? '' : '스캔 버튼을 눌러주세요');
  });
}

// ── 탭 관리 ───────────────────────────────────────────────────────
const GROUP_PANES = {
  recon:   ['tech','endpoints','external','robots','sourcemap','comments','scan'],
  analyze: ['jsanalysis','upload'],
  util:    ['cipher','cheatsheet'],
};
const ALL_PANE_IDS = Object.values(GROUP_PANES).flat();

function hideAllPanes() {
  ALL_PANE_IDS.forEach(id => { const el=document.getElementById('p-'+id); if(el) el.classList.remove('on'); });
}

function initTabs() {
  // 초기화
  document.querySelectorAll('.pt-sub-group').forEach(g => g.style.display='none');
  hideAllPanes();
  const initG = document.querySelector('.pt-sub-group[data-g="recon"]');
  if (initG) { initG.style.display='contents'; document.getElementById('p-tech')?.classList.add('on'); }

  // 메인 탭
  document.querySelectorAll('.pt-main-tab').forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll('.pt-main-tab').forEach(b=>b.classList.remove('on'));
      btn.classList.add('on');
      document.querySelectorAll('.pt-sub-group').forEach(g=>g.style.display='none');
      hideAllPanes();
      const g = document.querySelector(`.pt-sub-group[data-g="${btn.dataset.m}"]`);
      if (g) {
        g.style.display='contents';
        const activeSub = g.querySelector('.pt-sub-tab.on') || g.querySelector('.pt-sub-tab');
        if (activeSub) { const pane=document.getElementById('p-'+activeSub.dataset.s); if(pane) pane.classList.add('on'); }
      }
    };
  });

  // 서브 탭
  document.querySelectorAll('.pt-sub-tab').forEach(btn => {
    btn.onclick = () => {
      const g = btn.closest('.pt-sub-group'); if(!g) return;
      g.querySelectorAll('.pt-sub-tab').forEach(b=>b.classList.remove('on')); btn.classList.add('on');
      hideAllPanes();
      document.getElementById('p-'+btn.dataset.s)?.classList.add('on');
    };
  });

  // Inner 탭 (Cipher, CheatSheet 등)
  document.querySelectorAll('[data-ci]').forEach(btn => {
    btn.onclick = () => {
      btn.closest('.pt-pane').querySelectorAll('[data-ci]').forEach(b=>b.classList.remove('on'));
      btn.classList.add('on');
      ['auto','enc','dec','hash','jwt'].forEach(id => {
        const el = document.getElementById('ci-'+id);
        if (el) el.classList.toggle('on', btn.dataset.ci===id);
      });
    };
  });

  document.querySelectorAll('[data-ch]').forEach(btn => {
    btn.onclick = () => {
      btn.closest('.pt-pane').querySelectorAll('[data-ch]').forEach(b=>b.classList.remove('on'));
      btn.classList.add('on');
      ['payloads','diagtext','settings'].forEach(id => {
        const el = document.getElementById('ch-'+id);
        if (el) el.classList.toggle('on', btn.dataset.ch===id);
      });
    };
  });

  // Robots 내부 탭
  document.querySelectorAll('[data-ri]').forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll('[data-ri]').forEach(b=>b.classList.remove('on')); btn.classList.add('on');
      ['parsed','raw'].forEach(id => {
        const el = document.getElementById('ri-'+id);
        if (el) el.classList.toggle('on', btn.dataset.ri===id);
      });
    };
  });
}

// ── 토글 ─────────────────────────────────────────────────────────
function initToggles() {
  // 라디오형 토글 (전체 ↔ 필터)
  togRadio('tog-ext-susp','tog-ext-all', ()=>{ showExtSusp=true;  renderExternal(); });
  togRadio('tog-ext-all', 'tog-ext-susp',()=>{ showExtSusp=false; renderExternal(); });
  togRadio('tog-cm-susp', 'tog-cm-all',  ()=>{ showCmSusp=true;  renderComments(); });
  togRadio('tog-cm-all',  'tog-cm-susp', ()=>{ showCmSusp=false; renderComments(); });
  togRadio('tog-sm-confirm','tog-sm-all',()=>{ showSmConfirm=true;  renderSourceMaps(); });
  togRadio('tog-sm-all','tog-sm-confirm',()=>{ showSmConfirm=false; renderSourceMaps(); });

  // 독립 토글형 (누를 때마다 on/off)
  togSwitch('tog-api',  ()=>{ showApiEp=!showApiEp; renderEndpoints(); });
  togSwitch('tog-extep',()=>{ showExtEp=!showExtEp; renderEndpoints(); });

  document.getElementById('f-ep').oninput = renderEndpoints;
}

// 라디오형: 한쪽 on → 반대쪽 off (기존 그룹 토글)
function togRadio(id, offId, cb) {
  const el=document.getElementById(id); if(!el) return;
  el.onclick=()=>{
    el.classList.add('on');
    if(offId) document.getElementById(offId)?.classList.remove('on');
    cb();
  };
}

// 스위치형: 누를 때마다 on ↔ off, 두 번 누르면 필터 해제
function togSwitch(id, cb) {
  const el=document.getElementById(id); if(!el) return;
  el.onclick=()=>{
    el.classList.toggle('on');
    cb();
  };
}

// ══ RECON 렌더러 ══════════════════════════════════════════════════

function renderTech() {
  const el = document.getElementById('tech-list');
  const stack = scanData?.techStack || [];
  const meta  = collectData?.metaTech || [];

  // 통합 (중복 제거)
  const seen = new Map();
  [...stack, ...meta].forEach(t => {
    const key = t.name.toLowerCase();
    if (!seen.has(key) || t.version !== 'detected') seen.set(key, t);
  });

  if (!seen.size) { el.innerHTML='<span class="ps-placeholder">탐지된 스택 없음 — 스캔해주세요</span>'; return; }

  const entries = Array.from(seen.values()).sort((a,b) => (b.versionExposed?1:0)-(a.versionExposed?1:0));

  el.innerHTML = entries.map(t => {
    const icon = TECH_ICONS?.[t.name] ? `<div class="tech-card-icon">${TECH_ICONS[t.name]}</div>` : '';
    const ver  = t.version && t.version!=='detected' ? `<span class="tech-ver">${esc(t.version)}</span>` : '';
    const expW = t.versionExposed ? `<span class="ps-badge b-medium" title="응답 헤더(${esc(t.headerSource||'')})에 버전 노출">⚠ 버전 노출</span>` : '';
    const src  = t.headerSource ? `<span style="font-size:8px;color:var(--text-3)">${esc(t.headerSource)}</span>` : '';
    const cveDiv = `<div class="tech-cve-list" id="cve-${esc(t.name.replace(/\s/g,'_'))}" style="display:none"></div>`;
    return `<div class="tech-card">
      ${icon}
      <div class="tech-card-body">
        <div class="tech-card-name">${esc(t.name)}</div>
        <div class="tech-card-meta">${ver}${expW}${src}</div>
        ${cveDiv}
      </div>
    </div>`;
  }).join('');
}

// CVE 조회
document.getElementById('btn-cve').onclick = () => {
  const stack = scanData?.techStack || [];
  if (!stack.length) { document.getElementById('cve-status').textContent='스택 없음'; return; }
  document.getElementById('cve-status').textContent='조회 중...';
  let done=0;
  const targets = stack.filter(t => t.version && t.version !== 'detected');
  if (!targets.length) { document.getElementById('cve-status').textContent='버전 정보 없음'; return; }
  targets.forEach(t => {
    const keyword = `${t.name} ${t.version}`;
    chrome.runtime.sendMessage({ type:'QUERY_CVE', keyword }, (resp) => {
      done++;
      const key = t.name.replace(/\s/g,'_');
      const cveEl = document.getElementById(`cve-${key}`);
      if (cveEl) {
        if (resp?.ok && resp.items?.length) {
          cveEl.style.display='block';
          cveEl.innerHTML = resp.items.map(c => {
            const sc = {CRITICAL:'b-critical',HIGH:'b-high',MEDIUM:'b-medium',LOW:'b-low'}[c.severity]||'b-info';
            return `<div class="tech-cve-item">
              <span class="ps-badge ${sc}">${c.severity}</span>
              <span style="font-family:var(--mono);font-size:10px;color:var(--accent)">${esc(c.id)}</span>
              ${c.score?`<span style="font-size:9px;color:var(--text-2)">${c.score}</span>`:''}
              <span style="font-size:10px;color:var(--text-1);flex:1">${esc(c.desc)}</span>
            </div>`;
          }).join('');
        } else if (resp?.ok && !resp.items?.length) {
          cveEl.style.display='block';
          cveEl.innerHTML='<span style="font-size:10px;color:var(--ok)">— 조회된 CVE 없음</span>';
        } else {
          cveEl.style.display='block';
          cveEl.innerHTML='<span style="font-size:10px;color:var(--text-2)">— 조회 실패 (네트워크 확인)</span>';
        }
      }
      if (done === targets.length) document.getElementById('cve-status').textContent=`완료 (${targets.length}개 조회)`;
    });
  });
};

function renderEndpoints() {
  let eps = collectData?.endpoints || [];
  const q = document.getElementById('f-ep').value.toLowerCase();
  if (q)         eps = eps.filter(e=>e.url.toLowerCase().includes(q));
  if (showApiEp) eps = eps.filter(e=>e.isApi);
  if (showExtEp) eps = eps.filter(e=>!e.sameOrigin);
  setCnt('cnt-ep', collectData?.endpoints?.length);
  const el = document.getElementById('ep-list');
  if (!eps.length) { el.innerHTML='<span class="ps-placeholder">엔드포인트 없음</span>'; return; }

  // 도메인별 그룹핑
  const groups = new Map();
  eps.forEach(e => {
    try { const d=new URL(e.url).hostname; if(!groups.has(d)) groups.set(d,[]); groups.get(d).push(e); } catch(ex){}
  });

  el.innerHTML = Array.from(groups.entries()).map(([domain, items]) => {
    const rows = items.map(e => `
      <div class="fi ${e.sameOrigin?'s-info':e.isApi?'s-low':'s-warn'}" style="margin-left:8px;margin-bottom:3px">
        <div class="fi-head">
          ${e.isApi?'<span class="ps-badge b-low">API</span>':''}
          ${!e.sameOrigin?'<span class="ps-badge b-warn">외부</span>':''}
          <span class="fi-title" style="font-family:var(--mono);font-size:10px">${esc(e.url.replace(location.origin,'').substring(0,70)||e.url.substring(0,70))}</span>
          <span class="copy-btn" data-v="${esc(e.url)}" title="복사">⎘</span>
          <span class="open-btn" data-u="${esc(e.url)}" title="새 탭">↗</span>
        </div>
        <div class="fi-meta">출처: ${esc(e.source)}</div>
      </div>`).join('');
    return `<div style="margin-bottom:8px">
      <div style="font-size:10px;font-weight:600;color:var(--text-2);padding:3px 0;border-bottom:1px solid var(--border);margin-bottom:3px">${esc(domain)} <span style="font-weight:400">(${items.length})</span></div>
      ${rows}
    </div>`;
  }).join('');

  el.querySelectorAll('[data-v]').forEach(b=>b.onclick=()=>copy(b.dataset.v));
  el.querySelectorAll('[data-u]').forEach(b=>b.onclick=()=>chrome.tabs.create({url:b.dataset.u,active:false}));
}

function renderExternal() {
  const doms = collectData?.externalDomains || [];
  const list = showExtSusp ? doms.filter(d=>d.suspicious) : doms;
  setCnt('cnt-ext', doms.length);
  const el = document.getElementById('ext-list');
  if (!list.length) { el.innerHTML='<span class="ps-placeholder">외부 도메인 없음</span>'; return; }
  el.innerHTML = list.map(d=>`
    <div class="fi ${d.suspicious?'s-medium':'s-info'}">
      <div class="fi-head">
        ${d.suspicious?'<span class="ps-badge b-medium">추적기 의심</span>':'<span class="ps-badge b-info">외부</span>'}
        <span class="fi-title">${esc(d.domain)}</span>
        <span class="fi-meta" style="margin-left:auto">${d.count}건</span>
      </div>
      <div>${d.types.map(t=>`<span class="tag">${t}</span>`).join('')}</div>
    </div>`).join('');
}

// ── Robots ────────────────────────────────────────────────────────
function initRobots() {
  document.getElementById('btn-robots').onclick  = () => fetchRobots('robots.txt');
  document.getElementById('btn-sitemap').onclick = () => fetchRobots('sitemap.xml');
}

function fetchRobots(file) {
  chrome.tabs.query({ active:true, currentWindow:true }, ([tab]) => {
    if (!tab?.url) return;
    try {
      const origin = new URL(tab.url).origin;
      const fullUrl = origin + '/' + file;

      // 버튼 active 상태 업데이트
      document.getElementById('btn-robots').classList.toggle('robots-btn-active', file==='robots.txt');
      document.getElementById('btn-sitemap').classList.toggle('robots-btn-active', file==='sitemap.xml');

      // 현재 파일 표시 바 업데이트
      const bar = document.getElementById('robots-current-bar');
      bar.style.display = 'flex';
      document.getElementById('robots-current-file').textContent = file;
      document.getElementById('robots-current-url').textContent = fullUrl;
      document.getElementById('robots-cached-badge').style.display = 'none';

      chrome.runtime.sendMessage({ type:'FETCH_ROBOTS', origin, file }, (resp) => {
        document.getElementById('robots-inner-tabs').style.display='flex';

        if (resp?.cached) {
          document.getElementById('robots-cached-badge').style.display = 'inline';
        }

        if (!resp?.ok) {
          document.getElementById('ri-parsed').innerHTML=`<span class="ps-placeholder">조회 실패: ${esc(resp?.err||'')}</span>`;
          document.getElementById('ri-raw').innerHTML='';
          return;
        }
        const text = resp.text || '';
        // 원본
        document.getElementById('ri-raw').innerHTML=`<div class="result-box">${esc(text)}</div>`;
        // 파싱
        document.getElementById('ri-parsed').innerHTML = parseRobotsDisplay(text, origin, file);
        // 파싱탭 활성화
        document.querySelectorAll('[data-ri]').forEach(b=>b.classList.remove('on'));
        document.querySelector('[data-ri="parsed"]')?.classList.add('on');
        document.getElementById('ri-parsed').classList.add('on');
        document.getElementById('ri-raw').classList.remove('on');
      });
    } catch(e) {}
  });
}

function parseRobotsDisplay(text, origin, file) {
  if (!text.trim()) return '<span class="ps-placeholder">내용 없음</span>';

  if (file === 'sitemap.xml') {
    // sitemap: URL 추출
    const urls = [];
    text.replace(/<loc>(.*?)<\/loc>/gi, (_, url) => urls.push(url.trim()));
    if (!urls.length) return `<div class="result-box">${esc(text.substring(0,500))}</div>`;
    return urls.map(url => `
      <div class="robots-line sitemap-url">
        <span style="flex:1">${esc(url)}</span>
        <span class="copy-btn" data-v="${esc(url)}" title="복사">⎘</span>
        <span class="open-btn" data-u="${esc(url)}" title="새 탭">↗</span>
      </div>`).join('');
  }

  // robots.txt 파싱
  const lines = text.split('\n');
  let html = '';
  lines.forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      if (trimmed.startsWith('#'))
        html += `<div style="font-size:10px;color:var(--text-3);padding:2px 6px">${esc(trimmed)}</div>`;
      return;
    }
    const [key, ...rest] = trimmed.split(':');
    const val = rest.join(':').trim();
    const k = key.trim().toLowerCase();

    if (k === 'disallow' && val) {
      const fullUrl = origin + val;
      html += `<div class="robots-line disallow">
        <span class="ps-badge b-medium">Disallow</span>
        <span style="font-family:var(--mono);flex:1">${esc(val)}</span>
        <span class="copy-btn" data-v="${esc(fullUrl)}" title="URL 복사">⎘</span>
        <span class="open-btn" data-u="${esc(fullUrl)}" title="이동">↗</span>
      </div>`;
    } else if (k === 'allow' && val) {
      const fullUrl = origin + val;
      html += `<div class="robots-line allow">
        <span class="ps-badge b-ok">Allow</span>
        <span style="font-family:var(--mono);flex:1">${esc(val)}</span>
        <span class="copy-btn" data-v="${esc(fullUrl)}" title="URL 복사">⎘</span>
        <span class="open-btn" data-u="${esc(fullUrl)}" title="이동">↗</span>
      </div>`;
    } else if (k === 'sitemap' && val) {
      html += `<div class="robots-line sitemap-url">
        <span class="ps-badge b-low">Sitemap</span>
        <span style="font-family:var(--mono);flex:1">${esc(val)}</span>
        <span class="open-btn" data-u="${esc(val)}" title="이동">↗</span>
      </div>`;
    } else {
      html += `<div class="robots-line">
        <span style="color:var(--text-2);min-width:60px">${esc(key.trim())}</span>
        <span style="font-family:var(--mono)">${esc(val)}</span>
      </div>`;
    }
  });

  // 이벤트 바인딩은 렌더 후 처리
  setTimeout(() => {
    document.querySelectorAll('#ri-parsed [data-v]').forEach(b=>b.onclick=()=>copy(b.dataset.v));
    document.querySelectorAll('#ri-parsed [data-u]').forEach(b=>b.onclick=()=>chrome.tabs.create({url:b.dataset.u,active:false}));
  }, 50);

  return html || '<span class="ps-placeholder">파싱 결과 없음</span>';
}


async function runLimited(items, limit, worker, onProgress) {
  const queue = [...items];
  let done = 0;
  const total = queue.length;
  const workers = Array.from({ length: Math.min(limit, total) }, async () => {
    while (queue.length) {
      const item = queue.shift();
      try {
        await worker(item);
      } finally {
        done++;
        if (onProgress) onProgress(done, total, item);
      }
    }
  });
  await Promise.all(workers);
}

// ── Source Map ────────────────────────────────────────────────────

function addSourceMapCandidate(list, seen, rawUrl, type, extra = {}) {
  if (!rawUrl) return;
  try {
    const base = extra.baseScript || collectData?.url || document.getElementById('tgt-url')?.textContent || location.href;
    const url = new URL(String(rawUrl).trim(), base).href;
    if (seen.has(url)) return;
    seen.add(url);
    list.push({ url, type, ...extra });
  } catch(e) {}
}

function parseSourceMapRefsFromJs(src, scriptUrl, sourceMapHeader) {
  const out = [];
  const seen = new Set();
  const re = /(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)\s*(?:\*\/)?/g;
  let m;
  while ((m = re.exec(src || '')) !== null) {
    addSourceMapCandidate(out, seen, m[1], 'external-comment', { raw:m[0], baseScript:scriptUrl });
  }
  if (sourceMapHeader) {
    addSourceMapCandidate(out, seen, sourceMapHeader, 'header', { baseScript:scriptUrl, raw:`SourceMap: ${sourceMapHeader}` });
  }
  return out;
}

async function enrichSourceMapCandidates(maps) {
  const merged = [...(maps || [])];
  const seen = new Set(merged.map(m => m.url));
  const scripts = (collectData?.externalScripts || []).filter(s => s.sameOrigin).slice(0, 20);

  await runLimited(scripts, 3, async (s) => {
    await new Promise(resolve => {
      chrome.runtime.sendMessage({ type:'FETCH_JS', url:s.url }, (resp) => {
        if (resp?.ok) {
          parseSourceMapRefsFromJs(resp.text, s.url, resp.sourceMapHeader).forEach(m => {
            if (!seen.has(m.url)) {
              seen.add(m.url);
              merged.push(m);
            }
          });
        } else if (resp?.sourceMapHeader) {
          addSourceMapCandidate(merged, seen, resp.sourceMapHeader, 'header', { baseScript:s.url, raw:`SourceMap: ${resp.sourceMapHeader}` });
        }
        resolve();
      });
    });
  });

  collectData.sourceMaps = merged.slice(0, 80);
  return collectData.sourceMaps;
}

function sourceMapLabel(result, map) {
  if (!result) return map?.type === 'inline-comment' ? '후보(주석)' : '후보';
  const status = result.sourceMapStatus || '';
  if (status === 'EXPOSED_WITH_SOURCE') return '원본 포함';
  if (status === 'EXPOSED') return 'Source Map 확인';
  if (status === 'FORBIDDEN') return '접근 제한';
  if (status === 'REDIRECT') return '리다이렉트';
  if (status === 'NOT_FOUND') return '없음';
  if (status === 'SOFT_404') return 'Soft 404';
  if (status === 'ERROR') return '오류';
  return `확인됨 ${result.status || 'ERR'}`;
}

function sourceMapSeverity(result, map) {
  if (!result) return map?.type === 'inline-comment' ? 'medium' : 'info';
  const status = result.sourceMapStatus || '';
  if (status === 'EXPOSED_WITH_SOURCE') return 'high';
  if (status === 'EXPOSED') return 'medium';
  if (status === 'FORBIDDEN') return 'low';
  return 'info';
}

function initSourceMap() {
  document.getElementById('btn-verify-sm').onclick = async () => {
    if (!collectData) return;
    setStatus('소스맵 후보 보강 중...');
    const maps = await enrichSourceMapCandidates(collectData.sourceMaps || []);
    if (!maps.length) { setStatus('소스맵 후보 없음'); return; }

    setStatus('소스맵 검증 중...');
    let found = 0;
    await runLimited(maps, 4, async (m) => {
      await new Promise(resolve => {
        chrome.runtime.sendMessage({ type:'VERIFY_SOURCEMAP', url:m.url }, (resp) => {
          const result = {
            ok: !!resp?.ok,
            status: resp?.status || 0,
            sourceMapStatus: resp?.sourceMapStatus || (resp?.ok ? 'EXPOSED' : 'ERROR'),
            err: resp?.err || null,
            contentType: resp?.contentType || null,
            contentLength: resp?.contentLength || null,
            sourcesCount: resp?.sourcesCount || 0,
            hasSourcesContent: !!resp?.hasSourcesContent,
            file: resp?.file || '',
            checkedAt: Date.now()
          };
          smResults.set(m.url, result);
          if (['EXPOSED','EXPOSED_WITH_SOURCE'].includes(result.sourceMapStatus)) {
            smVerified.add(m.url);
            found++;
          } else {
            smVerified.delete(m.url);
          }
          resolve();
        });
      });
    }, (done, total) => setStatus(`소스맵 검증 중... ${done}/${total}`));
    renderSourceMaps();
    setStatus(`검증 완료 — ${found}개 Source Map 확인`);
  };
}

function renderSourceMaps() {
  const maps = collectData?.sourceMaps || [];
  const list = showSmConfirm ? maps.filter(m=>smVerified.has(m.url)) : maps;
  setCnt('cnt-sm', maps.length);
  const el = document.getElementById('sm-list');
  if (!list.length) { el.innerHTML='<span class="ps-placeholder">소스맵 없음</span>'; return; }
  el.innerHTML = list.map(m => {
    const result = smResults.get(m.url);
    const sev = sourceMapSeverity(result, m);
    const badge = {high:'b-high',medium:'b-medium',low:'b-low',info:'b-info'}[sev] || 'b-info';
    const label = sourceMapLabel(result, m);
    const metaParts = result
      ? [`HTTP ${result.status || 'ERR'}`, result.sourceMapStatus, result.contentType, result.contentLength ? `size=${result.contentLength}` : '', result.sourcesCount ? `sources=${result.sourcesCount}` : '', result.hasSourcesContent ? 'sourcesContent' : '', result.err || ''].filter(Boolean)
      : ['아직 접근 확인 전', `type=${m.type}`];
    return `<div class="fi s-${sev}">
      <div class="fi-head">
        <span class="ps-badge ${badge}">${esc(label)}</span>
        <span class="fi-title" style="font-family:var(--mono);font-size:10px">${esc(m.url.substring(0,65))}</span>
        <span class="open-btn" data-u="${esc(m.url)}" title="열기">↗</span>
      </div>
      <div class="fi-meta">${esc(metaParts.join(' · '))}</div>
      ${m.baseScript?`<div class="fi-meta">base: ${esc(m.baseScript.substring(0,90))}</div>`:''}
      ${m.raw?`<div class="fi-meta">${esc(m.raw)}</div>`:''}
      ${m.scriptIndex?`<div class="fi-meta">script #${m.scriptIndex}</div>`:''}
    </div>`;
  }).join('');
  el.querySelectorAll('[data-u]').forEach(b=>b.onclick=()=>chrome.tabs.create({url:b.dataset.u,active:false}));
}

// ── Comments ──────────────────────────────────────────────────────
function initComments() {
  document.getElementById('btn-fetch-comments').onclick = async () => {
    const scripts = (collectData?.externalScripts||[]).filter(s=>s.sameOrigin);
    if (!scripts.length) { document.getElementById('comments-fetch-status').textContent='외부 JS 없음'; return; }
    const statusEl = document.getElementById('comments-fetch-status');
    statusEl.textContent = `분석 중... (0/${scripts.length})`;
    allComments = [];
    const suspRe = /password|passwd|secret|api.?key|token|todo|fixme|hack|debug|admin|credential/i;
    await runLimited(scripts, 3, async (s) => {
      await new Promise(resolve => {
        chrome.runtime.sendMessage({ type:'FETCH_JS', url:s.url }, (resp) => {
          if (resp?.ok) {
            const src = resp.text;
            const fileName = s.url.split('/').pop().split('?')[0];
            const blockRe = /\/\*[\s\S]*?\*\//g;
            let m;
            while ((m=blockRe.exec(src))!==null) {
              const text=m[0].replace(/\/\*+|\*+\//g,'').trim();
              if (text.length>3) allComments.push({ text:text.substring(0,300), suspicious:suspRe.test(text), file:fileName, type:'block' });
            }
            const lineRe = /\/\/(.+)/g;
            while ((m=lineRe.exec(src))!==null) {
              const text=m[1].trim();
              if (text.length>3) allComments.push({ text:text.substring(0,200), suspicious:suspRe.test(text), file:fileName, type:'line' });
            }
          }
          resolve();
        });
      });
    }, (done, total) => { statusEl.textContent = `분석 중... (${done}/${total})`; });
    statusEl.textContent = `완료 (${scripts.length}개 파일)`;
    renderComments();
  };
}

function renderComments() {
  // DOM 주석 + 외부 JS 주석 합치기
  const domComments = (collectData?.comments||[]).map(c=>({...c, file:'DOM', type:'block'}));
  const combined = [...domComments, ...allComments];
  const list = showCmSusp ? combined.filter(c=>c.suspicious) : combined;
  setCnt('cnt-cm', combined.length);
  const el = document.getElementById('cm-list');
  if (!list.length) { el.innerHTML='<span class="ps-placeholder">주석 없음</span>'; return; }

  // 파일별 그룹핑
  const groups = new Map();
  list.forEach(c => { if(!groups.has(c.file)) groups.set(c.file,[]); groups.get(c.file).push(c); });

  el.innerHTML = Array.from(groups.entries()).map(([file, items])=>`
    <div style="margin-bottom:8px">
      <div style="font-size:10px;font-weight:600;color:var(--text-2);padding:3px 0;border-bottom:1px solid var(--border);margin-bottom:3px">${esc(file)} <span style="font-weight:400">(${items.length})</span></div>
      ${items.map(c=>`<div class="fi ${c.suspicious?'s-medium':'s-info'}">
        <div class="fi-head">
          <span class="ps-badge ${c.suspicious?'b-medium':'b-info'}">${c.suspicious?'의심':'주석'}</span>
          <span style="font-size:9px;color:var(--text-3)">${c.type}</span>
        </div>
        <div class="fi-meta">${esc(c.text)}</div>
      </div>`).join('')}
    </div>`).join('');
}

// ══ ANALYZE ══════════════════════════════════════════════════════

function initJsAnalysis() {
  document.querySelectorAll('[data-js]').forEach(btn=>{
    btn.onclick=()=>{
      document.querySelectorAll('[data-js]').forEach(b=>b.classList.remove('on')); btn.classList.add('on');
      ['patterns','sensitive','filter','crypto','paths'].forEach(id=>{
        const el = document.getElementById('js-'+id);
        if (el) el.classList.toggle('on', btn.dataset.js===id);
      });
    };
  });

  document.getElementById('btn-fetch-js').onclick = async () => {
    const scripts = (collectData?.externalScripts||[]).filter(s=>s.sameOrigin).slice(0, 30);
    if (!scripts.length) { document.getElementById('js-fetch-status').textContent='외부 JS 없음'; return; }
    const statusEl = document.getElementById('js-fetch-status');
    statusEl.textContent=`분석 중... (0/${scripts.length})`;
    allJsHits = { patterns:[], sensitive:[], filter:[], crypto:[], paths:[] };
    await runLimited(scripts, 3, async (s) => {
      await new Promise(resolve => {
        chrome.runtime.sendMessage({ type:'FETCH_JS', url:s.url }, (resp) => {
          if (resp?.ok) analyzeExternalJs(resp.text, s.url);
          resolve();
        });
      });
    }, (done, total) => { statusEl.textContent=`분석 중... (${done}/${total})`; });
    statusEl.textContent=`완료 (${scripts.length}개)`;
    renderAllJsSections();
  };
}

function analyzeExternalJs(src, url) {
  const fileName = url.split('/').pop().split('?')[0];
  if (src.length > 800000) return; // 너무 큰 파일 스킵

  // 1. 위험 패턴 (AST 없이 정규식 — 외부 파일은 minify 상태일 수 있음)
  [
    { re: /eval\s*\(/g,               label:'eval() 사용',           sev:'high' },
    { re: /innerHTML\s*=/g,           label:'innerHTML 사용 지점',    sev:'medium' },
    { re: /document\.write\s*\(/g,    label:'document.write()',       sev:'medium' },
  ].forEach(({re,label,sev})=>{
    let m; re.lastIndex=0;
    while((m=re.exec(src))!==null && allJsHits.patterns.length<50) {
      const lineIdx=src.substring(0,m.index).split('\n').length;
      allJsHits.patterns.push({severity:sev,label,desc:'외부 파일 탐지',location:`${fileName} L${lineIdx}`,context:null});
    }
  });

  // 2. 민감정보
  [
    { re: /(api[_-]?key|apikey)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi, label:'API Key' },
    { re: /(secret|password)\s*[:=]\s*['"`]([^'"`\s]{6,})/gi,           label:'패스워드/시크릿' },
    { re: /ghp_[a-zA-Z0-9]{36}/g,                                        label:'GitHub Token' },
    { re: /-----BEGIN.*PRIVATE KEY-----/g,                                label:'Private Key' },
  ].forEach(({re,label})=>{
    let m; re.lastIndex=0;
    while((m=re.exec(src))!==null && allJsHits.sensitive.length<30)
      allJsHits.sensitive.push({label,snippet:m[0].substring(0,80),location:fileName});
  });

  // 3. 필터링 로직 탐지
  [
    { re: /(?:replace|test|match|exec)\s*\(\s*\/[^/]*(?:script|on\w+|javascript)[^/]*\//gi, label:'XSS 필터링 패턴', desc:'스크립트/이벤트 핸들러 필터 확인 필요 — 우회 가능성 검토' },
    { re: /(?:replace|test|match)\s*\(\s*\/[^/]*(?:union|select|insert|drop|where)[^/]*/gi, label:'SQLi 필터링 패턴', desc:'SQL 키워드 필터 확인 필요 — 우회 가능성 검토' },
    { re: /\bblacklist\b|\bblocked\b|\bforbidden\b/gi,                                       label:'블랙리스트 방식 필터', desc:'화이트리스트가 아닌 블랙리스트 — 우회 가능성 높음' },
    { re: /sanitize|escapeHtml|htmlspecialchars|DOMPurify/gi,                                 label:'Sanitize 함수 사용', desc:'입력값 필터링 함수 존재 — 적용 범위 수동 확인 필요' },
  ].forEach(({re,label,desc})=>{
    let m; re.lastIndex=0;
    if((m=re.exec(src))!==null) {
      const lineIdx=src.substring(0,m.index).split('\n').length;
      allJsHits.filter.push({label,desc,snippet:src.substring(Math.max(0,m.index-30),m.index+80),location:`${fileName} L${lineIdx}`});
    }
  });

  // 4. 암복호화 로직
  [
    { re: /CryptoJS\.\w+/g,       label:'CryptoJS 사용',    desc:'암호화 라이브러리 — 키값/알고리즘 확인 필요' },
    { re: /AES\.encrypt|AES\.decrypt/g, label:'AES 암복호화', desc:'AES 키 하드코딩 여부 확인 필요' },
    { re: /btoa\s*\(|atob\s*\(/g, label:'Base64 인코딩/디코딩', desc:'인코딩을 암호화로 오용하는 경우 확인' },
    { re: /\.sign\s*\(|\.verify\s*\(/g, label:'서명/검증 로직', desc:'JWT 등 서명 관련 로직 — 알고리즘 확인 필요' },
    { re: /(?:key|secret|salt)\s*[=:]\s*['"`][^'"`]{8,}/gi, label:'하드코딩된 키/시크릿', desc:'암호화 키가 소스에 노출됨' },
  ].forEach(({re,label,desc})=>{
    let m; re.lastIndex=0;
    while((m=re.exec(src))!==null && allJsHits.crypto.length<30) {
      const lineIdx=src.substring(0,m.index).split('\n').length;
      allJsHits.crypto.push({label,desc,snippet:m[0].substring(0,80),location:`${fileName} L${lineIdx}`});
    }
  });

  // 5. 내부 경로 & 다운로드 경로
  [
    { re: /['"`](\/(?:api|admin|internal|private|download|upload|file|export|report)[^'"`\s]{2,})['"`]/gi, label:'내부 경로' },
    { re: /['"`](https?:\/\/[^'"`\s]+(?:download|file|export|upload)[^'"`\s]*)['"`]/gi,                    label:'다운로드 URL' },
    { re: /require\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g,                                                       label:'require 경로' },
    { re: /import\s+.*from\s+['"`]([^'"`]+)['"`]/g,                                                         label:'import 경로' },
  ].forEach(({re,label})=>{
    let m; re.lastIndex=0;
    while((m=re.exec(src))!==null && allJsHits.paths.length<50) {
      allJsHits.paths.push({label,path:m[1],location:fileName});
    }
  });
}

function renderAllJsSections() {
  renderJsPatterns();
  renderJsSensitive();
  renderJsSection('filter');
  renderJsSection('crypto');
  renderJsPaths();
}

function renderJsPatterns() {
  const items = [...(scanData?.domPatterns||[]), ...allJsHits.patterns];
  setCnt('cnt-patterns', items.length);
  const el = document.getElementById('js-patterns');
  if (!items.length) { el.innerHTML='<span class="ps-placeholder">위험 패턴 없음</span>'; return; }
  el.innerHTML = items.map(p=>`<div class="fi s-${p.severity}">
    <div class="fi-head"><span class="ps-badge b-${p.severity}">${p.severity.toUpperCase()}</span><span class="fi-title">${esc(p.label)}</span></div>
    <div class="fi-desc">${esc(p.desc)}</div>
    <div class="fi-meta">${esc(p.location)}</div>
    ${p.context?`<pre class="code-ctx">${esc(p.context)}</pre>`:''}
  </div>`).join('');
}

function renderJsSensitive() {
  const items = [...(scanData?.sensitiveStrings||[]), ...allJsHits.sensitive];
  setCnt('cnt-sensitive', items.length);
  const el = document.getElementById('js-sensitive');
  if (!items.length) { el.innerHTML='<span class="ps-placeholder">민감 정보 노출 없음</span>'; return; }
  el.innerHTML = items.map(i=>`<div class="fi s-high">
    <div class="fi-head"><span class="ps-badge b-high">HIGH</span><span class="fi-title">${esc(i.label)}</span></div>
    <div class="fi-meta">${esc(i.snippet||'')}</div>
    <div class="fi-meta">${esc(i.location)}</div>
  </div>`).join('');
}

function renderJsSection(key) {
  const items = allJsHits[key] || [];
  const el = document.getElementById('js-'+key);
  if (!items.length) { el.innerHTML='<span class="ps-placeholder">탐지 결과 없음 (외부 JS 분석 버튼 클릭)</span>'; return; }
  el.innerHTML = items.map(i=>`<div class="fi s-medium">
    <div class="fi-head"><span class="ps-badge b-medium">확인 필요</span><span class="fi-title">${esc(i.label)}</span></div>
    <div class="fi-desc">${esc(i.desc||'')}</div>
    <div class="fi-meta">${esc(i.snippet||i.path||'')}</div>
    <div class="fi-meta">${esc(i.location)}</div>
  </div>`).join('');
}

function renderJsPaths() {
  const items = allJsHits.paths || [];
  const el = document.getElementById('js-paths');
  if (!items.length) { el.innerHTML='<span class="ps-placeholder">탐지된 경로 없음 (외부 JS 분석 버튼 클릭)</span>'; return; }
  el.innerHTML = items.map(i=>`<div class="fi s-info">
    <div class="fi-head">
      <span class="ps-badge b-info">${esc(i.label)}</span>
      <span class="fi-title" style="font-family:var(--mono);font-size:10px">${esc(i.path)}</span>
      <span class="copy-btn" data-v="${esc(i.path)}" title="복사">⎘</span>
    </div>
    <div class="fi-meta">${esc(i.location)}</div>
  </div>`).join('');
  el.querySelectorAll('[data-v]').forEach(b=>b.onclick=()=>copy(b.dataset.v));
}

// ══ SCAN ══════════════════════════════════════════════════════════

let scanRunning = false;
let scanResults = [];

function initScan() {
  // 카테고리 체크박스 렌더
  const catsEl = document.getElementById('scan-cats');
  Object.entries(SCAN_PATHS).forEach(([key, cat]) => {
    const label = document.createElement('label');
    label.style.cssText = 'display:flex;align-items:center;gap:4px;font-size:10px;cursor:pointer;background:var(--bg-2);border:1px solid var(--border);border-radius:3px;padding:3px 7px';
    label.innerHTML = `<input type="checkbox" value="${key}" checked style="accent-color:var(--accent)"> ${cat.icon} ${cat.label}`;
    catsEl.appendChild(label);
  });

  document.getElementById('btn-scan-start').onclick = startScan;
  document.getElementById('btn-scan-stop').onclick  = stopScan;
  document.getElementById('btn-scan-clear').onclick = clearScan;
  document.getElementById('scan-hide-404').onchange = () => renderScanResults();
}

function startScan() {
  chrome.tabs.query({ active:true, currentWindow:true }, ([tab]) => {
    if (!tab?.url?.startsWith('http')) return;
    const origin = new URL(tab.url).origin;

    // 선택된 카테고리 경로 수집
    const selectedCats = Array.from(document.querySelectorAll('#scan-cats input:checked')).map(el=>el.value);
    if (!selectedCats.length) return;

    const entries = [];
    const seenPaths = new Set();
    selectedCats.forEach(cat => {
      (SCAN_PATHS[cat]?.paths || []).forEach(path => {
        if (seenPaths.has(path)) return;
        seenPaths.add(path);
        entries.push({ url: origin + path, path, category: cat, categoryLabel: SCAN_PATHS[cat]?.label || cat });
      });
    });

    if (!entries.length) return;

    const concurrency = +document.getElementById('scan-concurrency').value || 5;
    const timeout     = +document.getElementById('scan-timeout').value     || 4000;

    scanRunning = true;
    scanResults = [];

    document.getElementById('btn-scan-start').style.display = 'none';
    document.getElementById('btn-scan-stop').style.display  = 'inline-flex';
    document.getElementById('scan-progress-bar-wrap').style.display = 'block';
    document.getElementById('scan-result-list').innerHTML = '';

    let completed = 0;
    let found = 0;
    const total = entries.length;

    updateProgress(0, total, 0);

    // 동시 요청 제어
    let idx = 0;
    function runNext() {
      if (!scanRunning || idx >= entries.length) return;
      const entry = entries[idx++];
      const url = entry.url;
      chrome.runtime.sendMessage({ type:'SCAN_PATH', url, timeout }, (resp) => {
        if (!scanRunning) return;
        completed++;
        const status = resp?.status || 0;
        const result = { url, path: entry.path, category: entry.category, categoryLabel: entry.categoryLabel, status, method: resp?.method || 'HEAD', fallbackUsed: !!resp?.fallbackUsed, firstStatus: resp?.firstStatus || null, redirectTo: resp?.redirectTo || null, err: resp?.err || null, contentLength: resp?.contentLength || null, contentType: resp?.contentType || null, risk: classifyPathResult({ path: entry.path, category: entry.category, status }).risk };
        scanResults.push(result);

        const isInteresting = isInterestingPathResult(result);
        if (isInteresting) found++;
        appendScanResult(result);
        updateProgress(completed, total, found);

        if (completed >= total) finishScan();
        else runNext();
      });
    }

    // 동시 N개 시작
    const startCount = Math.min(concurrency, entries.length);
    for (let i=0; i<startCount; i++) runNext();
  });
}

function stopScan() {
  scanRunning = false;
  finishScan();
}

function finishScan() {
  scanRunning = false;
  document.getElementById('btn-scan-start').style.display = 'inline-flex';
  document.getElementById('btn-scan-stop').style.display  = 'none';
  savePathScan();
}

function savePathScan() {
  if (currentTabId == null) return;
  chrome.runtime.sendMessage({ type:'SAVE_PATHSCAN', tabId: currentTabId, data: scanResults });
}

function clearScan() {
  stopScan();
  scanResults = [];
  document.getElementById('scan-result-list').innerHTML = '<span class="ps-placeholder">스캔 시작 버튼을 눌러주세요</span>';
  document.getElementById('scan-progress-bar-wrap').style.display = 'none';
  if (currentTabId != null) {
    chrome.runtime.sendMessage({ type:'SAVE_PATHSCAN', tabId: currentTabId, data: [] });
  }
}


function classifyPathResult(r) {
  const status = r.status || 0;
  const path = r.path || (() => { try { return new URL(r.url).pathname; } catch(e) { return ''; } })();
  const cat = r.category || '';

  if ([200,201,204].includes(status)) {
    if (cat === 'config' || cat === 'vcs' || /\.(env|sql|bak|old|zip|tar|gz|log|config|yml|yaml|properties)$/i.test(path) || /\/\.git\/config|\/wp-config\.php|\/composer\.json|\/package\.json/i.test(path)) {
      return { risk:'high', color:'#e05252', icon:'🔴', note:'민감 파일 접근 가능 후보' };
    }
    if (cat === 'admin' || cat === 'devtools' || cat === 'backup') {
      return { risk:'medium', color:'#e8943a', icon:'🟠', note:'수동 확인 필요 경로' };
    }
    return { risk:'low', color:'#4a90d9', icon:'🔵', note:'접근 가능 경로' };
  }

  if ([401,403].includes(status)) return { risk:'medium', color:'#e8943a', icon:'🟠', note:'보호된 경로 후보' };
  if ([301,302,307,308].includes(status)) return { risk:'low', color:'#4a90d9', icon:'🔵', note:'리다이렉트 경로' };
  if (status === 405) return { risk:'medium', color:'#e8943a', icon:'🟡', note:'메서드 제한, 수동 확인 필요' };
  if (status === 404) return { risk:'info', color:'#5a6478', icon:'⚫', note:'미발견' };
  return { risk:'info', color:'#5a6478', icon:'⚫', note:'오류 또는 확인 실패' };
}

function isInterestingPathResult(r) {
  return ['high','medium','low'].includes(classifyPathResult(r).risk);
}

function appendScanResult(r) {
  const hide404 = document.getElementById('scan-hide-404').checked;
  if (hide404 && (r.status === 404 || r.status === 0)) return;

  const el = document.getElementById('scan-result-list');
  // 기존 placeholder 제거
  const ph = el.querySelector('.ps-placeholder');
  if (ph) ph.remove();

  const { color, icon, risk: sev, note } = classifyPathResult(r);
  const item = document.createElement('div');
  item.className = `fi s-${sev}`;
  item.style.marginBottom = '3px';

  const path = (() => { try { return new URL(r.url).pathname; } catch(e) { return r.url; } })();
  const redirect = r.redirectTo ? `<div class="fi-meta">→ ${esc(r.redirectTo.substring(0,70))}</div>` : '';
  const methodMeta = `<div class="fi-meta">${esc(r.categoryLabel || r.category || '')}${note ? ` · ${esc(note)}` : ''} · method=${esc(r.method || 'HEAD')}${r.fallbackUsed ? ` · HEAD ${esc(r.firstStatus || 'ERR')} → GET fallback` : ''}${r.contentLength ? ` · size=${esc(r.contentLength)}` : ''}${r.contentType ? ` · ${esc(r.contentType)}` : ''}${r.err ? ` · ${esc(r.err)}` : ''}</div>`;

  item.innerHTML = `
    <div class="fi-head">
      <span style="font-family:var(--mono);font-size:13px;min-width:20px;text-align:center">${icon}</span>
      <span class="ps-badge" style="background:${color};color:#fff;min-width:34px;text-align:center">${r.status||'ERR'}</span>
      <span class="fi-title" style="font-family:var(--mono);font-size:10px">${esc(path)}</span>
      ${r.status && r.status !== 404 ? `<span class="open-btn" data-u="${esc(r.url)}" title="열기">↗</span>` : ''}
      ${r.status && r.status !== 404 ? `<span class="copy-btn" data-v="${esc(r.url)}" title="복사">⎘</span>` : ''}
    </div>
    ${redirect}
    ${methodMeta}`;

  item.querySelectorAll('[data-u]').forEach(b=>b.onclick=()=>chrome.tabs.create({url:b.dataset.u,active:false}));
  item.querySelectorAll('[data-v]').forEach(b=>b.onclick=()=>copy(b.dataset.v));

  el.appendChild(item);
}

function renderScanResults() {
  // hide-404 토글 시 전체 재렌더
  const el = document.getElementById('scan-result-list');
  el.innerHTML = '';
  if (!scanResults.length) {
    el.innerHTML = '<span class="ps-placeholder">스캔 결과 없음</span>';
    return;
  }
  scanResults.forEach(r => appendScanResult(r));
}

function updateProgress(done, total, found) {
  const pct = total ? Math.round(done/total*100) : 0;
  document.getElementById('scan-progress-bar').style.width = pct + '%';
  document.getElementById('scan-progress-text').textContent = `${done} / ${total} (${pct}%)`;
  document.getElementById('scan-found-text').textContent = found > 0 ? `${found}개 발견` : '';
}

function statusStyle(status) {
  const r = classifyPathResult({ status });
  return { color:r.color, icon:r.icon, sev:r.risk };
}

// ══ UPLOAD ════════════════════════════════════════════════════════

function initUpload() {
  document.getElementById('btn-upload-fetch-js').onclick = () => {
    const scripts = (collectData?.externalScripts||[]).filter(s=>s.sameOrigin);
    if (!scripts.length) {
      document.getElementById('upload-js-status').textContent = '외부 JS 없음';
      return;
    }
    const statusEl = document.getElementById('upload-js-status');
    statusEl.textContent = `분석 중... (0/${scripts.length})`;
    let done = 0;
    const extJsChecks = [];
    const uploadRe = [
      { re: /\.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx|zip)/gi, label:'확장자 기반 검증', risk:'medium', desc:'확장자만 검증 — Content-Type 조작으로 우회 가능' },
      { re: /file\.type|\.type\s*===|\.type\s*!=/g,             label:'MIME 타입 검증',  risk:'low',    desc:'MIME 타입 검증 — 클라이언트 측 우회 가능' },
      { re: /file\.size|\.size\s*[><]/g,                        label:'파일 크기 제한',  risk:'info',   desc:'파일 크기 제한 로직 확인' },
      { re: /new\s+FormData|\.append\s*\(/g,                    label:'FormData 업로드', risk:'info',   desc:'비동기 업로드 — 응답에서 경로 노출 여부 확인' },
    ];
    runLimited(scripts, 3, async (s) => {
      await new Promise(resolve => {
        chrome.runtime.sendMessage({ type:'FETCH_JS', url:s.url }, (resp) => {
          done++;
          statusEl.textContent = `분석 중... (${done}/${scripts.length})`;
          if (resp?.ok) {
            const src = resp.text;
            const fileName = s.url.split('/').pop().split('?')[0];
            uploadRe.forEach(({re,label,risk,desc}) => {
              re.lastIndex=0;
              const m = re.exec(src);
              if (m) {
                const line = src.substring(0, m.index).split('\n').length;
                extJsChecks.push({ label, risk, desc, location:`${fileName} L${line}`, snippet:m[0] });
              }
            });
          }
          resolve();
        });
      });
    }).then(() => {
      statusEl.textContent = `완료 (${scripts.length}개)`;
      appendUploadJsChecks(extJsChecks);
    });
  };
}

function appendUploadJsChecks(checks) {
  const wrap = document.getElementById('upload-js-wrap');
  const list = document.getElementById('upload-js-list');
  if (!checks.length) {
    list.innerHTML = '<span class="ps-placeholder">업로드 관련 JS 로직 없음</span>';
    wrap.style.display = 'block';
    return;
  }
  wrap.style.display = 'block';
  list.innerHTML = checks.map(ch => {
    const bc = {high:'b-high',medium:'b-medium',low:'b-low',info:'b-info'}[ch.risk]||'b-info';
    const sc = {high:'s-high',medium:'s-medium',low:'s-low',info:'s-info'}[ch.risk]||'s-info';
    return `<div class="fi ${sc}">
      <div class="fi-head"><span class="ps-badge ${bc}">${ch.risk.toUpperCase()}</span><span class="fi-title">${esc(ch.label)}</span></div>
      <div class="fi-desc">${esc(ch.desc)}</div>
      <div class="fi-meta">${esc(ch.snippet)} — ${esc(ch.location)}</div>
    </div>`;
  }).join('');
}

function renderUpload() {
  const data = scanData?.uploadAnalysis;
  const wrap = document.getElementById('upload-forms-wrap');
  const noForms = document.getElementById('upload-no-forms');

  if (!data || (!data.forms?.length && !data.jsChecks?.length)) {
    noForms.style.display = 'block';
    wrap.innerHTML = '';
    return;
  }
  noForms.style.display = 'none';

  // 업로드 폼 렌더
  wrap.innerHTML = data.forms.map(f => {
    const issueHtml = f.issues.map(i => `
      <div class="fi s-${i.severity}" style="margin-top:4px">
        <div class="fi-head"><span class="ps-badge b-${i.severity}">${i.severity.toUpperCase()}</span><span class="fi-title">${esc(i.desc)}</span></div>
      </div>`).join('');
    const infoHtml = f.info.map(i => `<div class="fi-meta">${esc(i)}</div>`).join('');
    const sev = f.issues.length ? (f.issues.some(i=>i.severity==='high')?'s-high':'s-medium') : 's-ok';
    return `<div class="fi ${sev}" style="margin-bottom:6px">
      <div class="fi-head">
        <span class="ps-badge ${sev.replace('s-','b-')}">파일 입력 #${f.index}</span>
        <span class="fi-title">${esc(f.name)}</span>
        ${f.multiple?'<span class="ps-badge b-info">multiple</span>':''}
      </div>
      ${infoHtml}
      ${issueHtml}
    </div>`;
  }).join('');

  // 인라인 JS 검증 로직
  if (data.jsChecks?.length) {
    const jsWrap = document.getElementById('upload-js-wrap');
    const jsList = document.getElementById('upload-js-list');
    jsWrap.style.display = 'block';
    jsList.innerHTML = data.jsChecks.map(ch => {
      const bc = {high:'b-high',medium:'b-medium',low:'b-low',info:'b-info'}[ch.risk]||'b-info';
      const sc = {high:'s-high',medium:'s-medium',low:'s-low',info:'s-info'}[ch.risk]||'s-info';
      return `<div class="fi ${sc}">
        <div class="fi-head"><span class="ps-badge ${bc}">${ch.risk.toUpperCase()}</span><span class="fi-title">${esc(ch.label)}</span></div>
        <div class="fi-desc">${esc(ch.desc)}</div>
        <div class="fi-meta">${esc(ch.snippet)} — ${esc(ch.location)}</div>
      </div>`;
    }).join('');
  }
}

// ══ UTIL ══════════════════════════════════════════════════════════

function initCipher() {
  // Auto — 실시간 분석
  document.getElementById('auto-in').oninput = function() {
    const v = this.value.trim();
    if (!v) { document.getElementById('auto-result').innerHTML='<span class="ps-placeholder">입력값을 붙여넣으세요</span>'; return; }
    const results = autoDecode(v);
    document.getElementById('auto-result').innerHTML = results.map(r=>`
      <div class="cipher-result-row">
        <span class="cipher-result-type">${r.type}</span>
        <span class="cipher-result-val">${esc(r.value)}</span>
        <span class="copy-btn" data-v="${esc(r.value)}" title="복사">⎘</span>
      </div>`).join('') || '<span class="ps-placeholder">판별 불가</span>';
    document.getElementById('auto-result').querySelectorAll('[data-v]').forEach(b=>b.onclick=()=>copy(b.dataset.v));
  };

  document.getElementById('btn-enc').onclick=()=>{ document.getElementById('enc-out').value=doEncode(document.getElementById('enc-type').value, document.getElementById('enc-in').value); };
  document.getElementById('btn-enc-cp').onclick=()=>copy(document.getElementById('enc-out').value);
  document.getElementById('btn-dec').onclick=()=>{ document.getElementById('dec-out').value=doDecode(document.getElementById('dec-type').value, document.getElementById('dec-in').value); };
  document.getElementById('btn-dec-cp').onclick=()=>copy(document.getElementById('dec-out').value);
  document.getElementById('btn-hash').onclick=()=>{
    const v=document.getElementById('hash-in').value, t=document.getElementById('hash-type').value;
    if(t==='md5') document.getElementById('hash-out').value=md5(v);
    else sha(v,t).then(r=>{ document.getElementById('hash-out').value=r; });
  };
  document.getElementById('btn-hash-cp').onclick=()=>copy(document.getElementById('hash-out').value);
  document.getElementById('btn-jwt').onclick=parseJWT;
}

function autoDecode(v) {
  const results = [];
  // Base64 판별
  if (/^[A-Za-z0-9+/]+=*$/.test(v) && v.length % 4 === 0 && v.length >= 4) {
    try { const d=decodeURIComponent(escape(atob(v))); if(d!==v) results.push({type:'Base64 디코딩',value:d}); } catch(e){}
  }
  // URL 인코딩
  if (/%[0-9a-f]{2}/i.test(v)) {
    try { results.push({type:'URL 디코딩',value:decodeURIComponent(v)}); } catch(e){}
  }
  // HTML Entity
  if (/&[a-z]+;|&#[0-9]+;|&#x[0-9a-f]+;/i.test(v)) {
    const t=document.createElement('textarea'); t.innerHTML=v;
    results.push({type:'HTML Entity 디코딩',value:t.value});
  }
  // Hex (공백으로 구분된)
  if (/^([0-9a-f]{2}\s*)+$/i.test(v.trim())) {
    try { results.push({type:'Hex 디코딩',value:v.trim().split(/\s+/).map(h=>String.fromCharCode(parseInt(h,16))).join('')}); } catch(e){}
  }
  // JWT
  if (/^eyJ/.test(v)) {
    try {
      const parts=v.split('.');
      if(parts.length===3) {
        const payload=JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
        results.push({type:'JWT Payload',value:JSON.stringify(payload,null,2)});
      }
    } catch(e){}
  }
  // Unicode
  if (/\\u[0-9a-f]{4}/i.test(v)) {
    results.push({type:'Unicode 디코딩',value:v.replace(/\\u([0-9a-f]{4})/gi,(_,c)=>String.fromCharCode(parseInt(c,16)))});
  }
  // 타임스탬프
  if (/^\d{10}$/.test(v)) results.push({type:'Unix Timestamp',value:new Date(+v*1000).toLocaleString('ko-KR')});
  if (/^\d{13}$/.test(v)) results.push({type:'Unix Timestamp(ms)',value:new Date(+v).toLocaleString('ko-KR')});

  return results;
}

function doEncode(type,v){
  try{
    switch(type){
      case 'b64':      return btoa(unescape(encodeURIComponent(v)));
      case 'url':      return encodeURIComponent(v);
      case 'durl':     return encodeURIComponent(encodeURIComponent(v));
      case 'html':     return Array.from(v).map(c=>`&#${c.charCodeAt(0)};`).join('');
      case 'html_min': return v.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
      case 'hex':      return Array.from(v).map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join(' ');
      case 'uni':      return Array.from(v).map(c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0')).join('');
      case 'ascii':    return Array.from(v).map(c=>c.charCodeAt(0)).join(' ');
      case 'ascii_hex':return Array.from(v).map(c=>'0x'+c.charCodeAt(0).toString(16).padStart(2,'0')).join(' ');
      case 'utf8hex':  return Array.from(new TextEncoder().encode(v)).map(b=>'%'+b.toString(16).padStart(2,'0').toUpperCase()).join('');
      default: return v;
    }
  }catch(e){return '오류: '+e.message;}
}

function doDecode(type,v){
  try{
    switch(type){
      case 'b64':          return decodeURIComponent(escape(atob(v.trim())));
      case 'url':          return decodeURIComponent(v);
      case 'html':         {const t=document.createElement('textarea');t.innerHTML=v;return t.value;}
      case 'hex':          return v.trim().split(/[\s,]+/).map(h=>String.fromCharCode(parseInt(h,16))).join('');
      case 'uni':          return v.replace(/\\u([0-9a-f]{4})/gi,(_,c)=>String.fromCharCode(parseInt(c,16)));
      case 'ascii_dec':    return v.trim().split(/[\s,]+/).map(n=>String.fromCharCode(+n)).join('');
      case 'ascii_hex_dec':return v.trim().split(/[\s,]+/).map(h=>String.fromCharCode(parseInt(h,16))).join('');
      case 'utf8hex_dec':  {const bytes=(v.replace(/%/g,'').match(/.{1,2}/g)||[]).map(h=>parseInt(h,16));return new TextDecoder().decode(new Uint8Array(bytes));}
      default: return v;
    }
  }catch(e){return '오류: '+e.message;}
}

function parseJWT(){
  const token=document.getElementById('jwt-in').value.trim();
  const parts=token.split('.');
  const res=document.getElementById('jwt-result');
  if(parts.length!==3){res.style.display='none';return;}
  try{
    const dec=p=>JSON.parse(atob(p.replace(/-/g,'+').replace(/_/g,'/')));
    const header=dec(parts[0]),payload=dec(parts[1]);
    document.getElementById('jwt-h').textContent=JSON.stringify(header,null,2);
    document.getElementById('jwt-p').textContent=JSON.stringify(payload,null,2);
    document.getElementById('jwt-s').textContent=parts[2];
    const warns=[];
    if(header.alg==='none'||header.alg==='None') warns.push('⚠ alg:none — 서명 검증 없음');
    if(header.alg?.startsWith('HS')) warns.push('ℹ 대칭키(HS) — 키 노출 시 위조 가능');
    if(payload.exp&&new Date(payload.exp*1000)<new Date()) warns.push(`⚠ 만료: ${new Date(payload.exp*1000).toLocaleString('ko-KR')}`);
    document.getElementById('jwt-w').innerHTML=warns.join('<br>');
    res.style.display='flex';
  }catch(e){}
}

async function sha(str,algo){const buf=new TextEncoder().encode(str);const hash=await crypto.subtle.digest(algo,buf);return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('');}
function md5(str){function R(n,c){return(n<<c)|(n>>>(32-c));}function A(x,y){return(((x>>16)+(y>>16)+((x&65535)+(y&65535)>>16))<<16)|((x&65535)+(y&65535)&65535);}function cmn(q,aa,bb,x,ss,t){return A(R(A(A(aa,q),A(x,t)),ss),bb);}function FF(aa,bb,cc,dd,x,ss,t){return cmn((bb&cc)|((~bb)&dd),aa,bb,x,ss,t);}function GG(aa,bb,cc,dd,x,ss,t){return cmn((bb&dd)|(cc&(~dd)),aa,bb,x,ss,t);}function HH(aa,bb,cc,dd,x,ss,t){return cmn(bb^cc^dd,aa,bb,x,ss,t);}function II(aa,bb,cc,dd,x,ss,t){return cmn(cc^(bb|(~dd)),aa,bb,x,ss,t);}const x8=new Array(str.length*2);for(let i=0;i<str.length;i++)x8[i>>1]|=(str.charCodeAt(i)&255)<<((i%2)*8);x8[str.length>>1]|=128<<((str.length%2)*8);x8[(((str.length+8)>>6)<<4)+14]=str.length*8;let a=1732584193,b=-271733879,c=-1732584194,d=271733878;for(let i=0;i<x8.length;i+=16){const oa=a,ob=b,oc=c,od=d;a=FF(a,b,c,d,x8[i],7,-680876936);d=FF(d,a,b,c,x8[i+1],12,-389564586);c=FF(c,d,a,b,x8[i+2],17,606105819);b=FF(b,c,d,a,x8[i+3],22,-1044525330);a=FF(a,b,c,d,x8[i+4],7,-176418897);d=FF(d,a,b,c,x8[i+5],12,1200080426);c=FF(c,d,a,b,x8[i+6],17,-1473231341);b=FF(b,c,d,a,x8[i+7],22,-45705983);a=FF(a,b,c,d,x8[i+8],7,1770035416);d=FF(d,a,b,c,x8[i+9],12,-1958414417);c=FF(c,d,a,b,x8[i+10],17,-42063);b=FF(b,c,d,a,x8[i+11],22,-1990404162);a=FF(a,b,c,d,x8[i+12],7,1804603682);d=FF(d,a,b,c,x8[i+13],12,-40341101);c=FF(c,d,a,b,x8[i+14],17,-1502002290);b=FF(b,c,d,a,x8[i+15],22,1236535329);a=GG(a,b,c,d,x8[i+1],5,-165796510);d=GG(d,a,b,c,x8[i+6],9,-1069501632);c=GG(c,d,a,b,x8[i+11],14,643717713);b=GG(b,c,d,a,x8[i],20,-373897302);a=GG(a,b,c,d,x8[i+5],5,-701558691);d=GG(d,a,b,c,x8[i+10],9,38016083);c=GG(c,d,a,b,x8[i+15],14,-660478335);b=GG(b,c,d,a,x8[i+4],20,-405537848);a=GG(a,b,c,d,x8[i+9],5,568446438);d=GG(d,a,b,c,x8[i+14],9,-1019803690);c=GG(c,d,a,b,x8[i+3],14,-187363961);b=GG(b,c,d,a,x8[i+8],20,1163531501);a=GG(a,b,c,d,x8[i+13],5,-1444681467);d=GG(d,a,b,c,x8[i+2],9,-51403784);c=GG(c,d,a,b,x8[i+7],14,1735328473);b=GG(b,c,d,a,x8[i+12],20,-1926607734);a=HH(a,b,c,d,x8[i+5],4,-378558);d=HH(d,a,b,c,x8[i+8],11,-2022574463);c=HH(c,d,a,b,x8[i+11],16,1839030562);b=HH(b,c,d,a,x8[i+14],23,-35309556);a=HH(a,b,c,d,x8[i+1],4,-1530992060);d=HH(d,a,b,c,x8[i+4],11,1272893353);c=HH(c,d,a,b,x8[i+7],16,-155497632);b=HH(b,c,d,a,x8[i+10],23,-1094730640);a=HH(a,b,c,d,x8[i+13],4,681279174);d=HH(d,a,b,c,x8[i],11,-358537222);c=HH(c,d,a,b,x8[i+3],16,-722521979);b=HH(b,c,d,a,x8[i+6],23,76029189);a=HH(a,b,c,d,x8[i+9],4,-640364487);d=HH(d,a,b,c,x8[i+12],11,-421815835);c=HH(c,d,a,b,x8[i+15],16,530742520);b=HH(b,c,d,a,x8[i+2],23,-995338651);a=II(a,b,c,d,x8[i],6,-198630844);d=II(d,a,b,c,x8[i+7],10,1126891415);c=II(c,d,a,b,x8[i+14],15,-1416354905);b=II(b,c,d,a,x8[i+5],21,-57434055);a=II(a,b,c,d,x8[i+12],6,1700485571);d=II(d,a,b,c,x8[i+3],10,-1894986606);c=II(c,d,a,b,x8[i+10],15,-1051523);b=II(b,c,d,a,x8[i+1],21,-2054922799);a=II(a,b,c,d,x8[i+8],6,1873313359);d=II(d,a,b,c,x8[i+15],10,-30611744);c=II(c,d,a,b,x8[i+6],15,-1560198380);b=II(b,c,d,a,x8[i+13],21,1309151649);a=II(a,b,c,d,x8[i+4],6,-145523070);d=II(d,a,b,c,x8[i+11],10,-1120210379);c=II(c,d,a,b,x8[i+2],15,718787259);b=II(b,c,d,a,x8[i+9],21,-343485551);a=A(a,oa);b=A(b,ob);c=A(c,oc);d=A(d,od);}return[a,b,c,d].map(n=>(n<0?n+0x100000000:n).toString(16).padStart(8,'0').replace(/(..)(..)(..)(..)/, '$4$3$2$1')).join('');}

// ── CheatSheet ────────────────────────────────────────────────────
function initCheatSheet() {
  const catSel=document.getElementById('pl-cat');
  const subSel=document.getElementById('pl-sub');
  Object.entries(PAYLOAD_DB).forEach(([k,v])=>{
    catSel.appendChild(Object.assign(document.createElement('option'),{value:k,textContent:`${v.icon} ${v.label}`}));
  });
  const refreshSubs=()=>{
    const subs=PAYLOAD_DB[catSel.value]?.subs||{};
    subSel.innerHTML=Object.keys(subs).map(s=>`<option value="${esc(s)}">${esc(s)}</option>`).join('');
    renderPayloads();
  };
  const renderPayloads=()=>{
    const items=PAYLOAD_DB[catSel.value]?.subs[subSel.value]||[];
    const orTarget=settings.orTarget||'attacker.com';
    document.getElementById('pl-list').innerHTML=items.map(p=>{
      const display=p.replace(/TARGET_URL/g,orTarget);
      return `<div class="fi s-info pl-item" data-p="${esc(display)}" style="cursor:pointer">
        <div class="fi-head">
          <span class="fi-title" style="font-family:var(--mono);font-size:10px">${esc(display)}</span>
          <span class="copy-btn" title="복사">⎘</span>
        </div>
      </div>`;
    }).join('')||'<span class="ps-placeholder">페이로드 없음</span>';
    document.querySelectorAll('.pl-item').forEach(item=>item.onclick=()=>copy(item.dataset.p));
  };
  catSel.onchange=refreshSubs; subSel.onchange=renderPayloads;
  refreshSubs();

  // Diag Text
  document.getElementById('btn-dt-add').onclick=()=>{ document.getElementById('dt-form').style.display='block'; };
  document.getElementById('btn-dt-cancel').onclick=()=>{ document.getElementById('dt-form').style.display='none'; };
  document.getElementById('btn-dt-save').onclick=()=>{
    const label=document.getElementById('dt-label').value.trim();
    const content=document.getElementById('dt-content').value.trim();
    if(!label||!content) return;
    chrome.runtime.sendMessage({type:'SAVE_CUSTOM',key:'diagTexts',data:{label,content}},()=>{
      document.getElementById('dt-label').value=''; document.getElementById('dt-content').value='';
      document.getElementById('dt-form').style.display='none'; loadDiagTexts();
    });
  };
  loadDiagTexts();

  // Settings
  document.getElementById('btn-or-save').onclick=()=>{
    const val=document.getElementById('or-target').value.trim();
    if(!val) return;
    settings.orTarget=val;
    chrome.runtime.sendMessage({type:'SAVE_SETTINGS',data:{orTarget:val}});
    renderPayloads();
  };
}

function loadDiagTexts() {
  chrome.runtime.sendMessage({type:'GET_CUSTOM',key:'diagTexts'},(resp)=>{
    if(chrome.runtime.lastError) return;
    const data=resp?.data||[];
    const el=document.getElementById('dt-list');
    if(!data.length){el.innerHTML='<span class="ps-placeholder">저장된 진단 텍스트 없음</span>';return;}
    el.innerHTML=data.map(d=>`
      <div class="fi s-info">
        <div class="fi-head">
          <span class="fi-title">${esc(d.label)}</span>
          <div style="display:flex;gap:3px;flex-shrink:0">
            <span class="ps-btn-sm" data-copy="${d.id}" style="cursor:pointer">복사</span>
            <span class="ps-btn-sm" data-edit="${d.id}" style="cursor:pointer">수정</span>
            <span style="color:var(--text-2);cursor:pointer;padding:2px 4px" data-del="${d.id}">✕</span>
          </div>
        </div>
        <div class="fi-meta">${esc(d.content.substring(0,70))}${d.content.length>70?'...':''}</div>
      </div>`).join('');
    el.querySelectorAll('[data-copy]').forEach(b=>{b.onclick=()=>{const i=data.find(d=>d.id===b.dataset.copy);if(i)copy(i.content);};});
    el.querySelectorAll('[data-edit]').forEach(b=>{b.onclick=()=>{const i=data.find(d=>d.id===b.dataset.edit);if(!i)return;const nl=prompt('레이블:',i.label);if(nl===null)return;const nc=prompt('내용:',i.content);if(nc===null)return;chrome.runtime.sendMessage({type:'UPDATE_CUSTOM',key:'diagTexts',data:{id:i.id,label:nl.trim(),content:nc.trim()}},()=>loadDiagTexts());};});
    el.querySelectorAll('[data-del]').forEach(b=>{b.onclick=()=>chrome.runtime.sendMessage({type:'DELETE_CUSTOM',key:'diagTexts',id:b.dataset.del},()=>loadDiagTexts());});
  });
}


// ── Export ─────────────────────────────────────────────────────────
function initExport() {
  document.getElementById('btn-export-json')?.addEventListener('click', () => exportResults('json'));
  document.getElementById('btn-export-html')?.addEventListener('click', () => exportResults('html'));
}

function buildExportData() {
  return {
    tool: 'PenTri',
    version: 'v1.10',
    exportedAt: new Date().toISOString(),
    target: document.getElementById('tgt-url')?.textContent || '',
    headers,
    scanData,
    collectData,
    jsAnalysis: allJsHits,
    comments: allComments,
    sourceMapVerification: Array.from(smResults.entries()).map(([url, result]) => ({ url, ...result })),
    pathScanResults: scanResults
  };
}

function exportResults(type) {
  const data = buildExportData();
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  if (type === 'html') {
    const html = renderExportHtml(data);
    chrome.runtime.sendMessage({ type:'DOWNLOAD', filename:`pentri-v1.10-${stamp}.html`, mime:'text/html', data: html }, (resp) => {
      if (resp?.ok === false) setStatus(resp.err || 'HTML export 실패'); else setStatus('HTML export 생성됨');
    });
    return;
  }
  const json = JSON.stringify(data, null, 2);
  chrome.runtime.sendMessage({ type:'DOWNLOAD', filename:`pentri-v1.10-${stamp}.json`, mime:'application/json', data: json }, (resp) => {
    if (resp?.ok === false) setStatus(resp.err || 'JSON export 실패'); else setStatus('JSON export 생성됨');
  });
}

function renderExportHtml(data) {
  const techs = data.scanData?.techStack || [];
  const endpoints = data.collectData?.endpoints || [];
  const maps = data.collectData?.sourceMaps || [];
  const uploadData = data.scanData?.uploadAnalysis;
  const uploads = Array.isArray(uploadData) ? uploadData : (uploadData?.forms || []);
  const paths = data.pathScanResults || [];
  const externals = data.collectData?.externalDomains || [];

  // 상태코드 → 색상/라벨
  const statusBadge = (s) => {
    let bg = '#9aa5b1', label = s || 'ERR';
    if ([200,201,204].includes(s))           bg = '#2e7d32'; // 초록 - 존재
    else if ([301,302,307,308].includes(s))  bg = '#1565c0'; // 파랑 - 리다이렉트
    else if ([401,403].includes(s))          bg = '#e65100'; // 주황 - 차단
    else if (s === 405)                       bg = '#9e6a00'; // 갈주황
    else if (s === 404)                       bg = '#b71c1c'; // 빨강 - 없음
    else if (!s)                              bg = '#616161'; // 회색 - 에러
    return `<span style="display:inline-block;min-width:38px;text-align:center;padding:2px 6px;border-radius:4px;background:${bg};color:#fff;font-weight:600;font-size:11px">${esc(label)}</span>`;
  };

  const link = (url) => url ? `<a href="${esc(url)}" target="_blank" rel="noopener" style="color:#1565c0;text-decoration:none;word-break:break-all">${esc(url)}</a>` : '';

  // Path Scan 행 (색상 + 링크, 404/에러는 흐리게)
  const pathRows = paths.map(p => {
    const dim = (!p.status || p.status === 404) ? ' style="opacity:.5"' : '';
    const target = (p.status && p.status !== 404) ? link(p.url) : `<span style="color:#999;word-break:break-all">${esc(p.url)}</span>`;
    const extra = p.redirectTo ? `→ ${esc(p.redirectTo)}` : (p.err ? esc(p.err) : '');
    return `<tr${dim}><td>${statusBadge(p.status)}</td><td><code>${esc(p.method||'')}</code></td><td>${target}</td><td class="muted">${extra}</td></tr>`;
  }).join('');

  // 발견된 경로만 요약 (200/301/403 등)
  const interesting = paths.filter(p => [200,201,204,301,302,307,308,401,403,405].includes(p.status));

  return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>PenTri v1.10 Report</title>
<style>
:root{--orange:#ff8800}
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans KR',sans-serif;margin:0;padding:32px 40px;color:#1f2933;background:#fafbfc;line-height:1.5}
h1{color:var(--orange);margin:0 0 4px;font-size:26px}
.sub{color:#888;font-size:13px;margin-bottom:24px}
h2{font-size:17px;margin:30px 0 10px;padding-bottom:6px;border-bottom:2px solid #eee;display:flex;align-items:center;gap:8px}
.count{font-size:12px;color:#888;font-weight:400}
table{border-collapse:collapse;width:100%;margin:6px 0 10px;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.05);border-radius:6px;overflow:hidden}
th{background:#f4f5f7;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#666}
td,th{border-bottom:1px solid #eee;padding:8px 10px;font-size:12.5px;text-align:left;vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:#fafafa}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;background:#f4f5f7;padding:1px 5px;border-radius:3px}
a{color:#1565c0}
.muted{color:#999;font-size:11.5px}
.summary{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0 24px}
.summary .card{background:#fff;border:1px solid #eee;border-radius:8px;padding:10px 16px;min-width:90px}
.summary .num{font-size:22px;font-weight:700;color:var(--orange)}
.summary .lbl{font-size:11px;color:#888}
.legend{font-size:11px;color:#666;margin:4px 0 0}
.legend span{display:inline-block;margin-right:12px}
.dot{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:middle}
</style></head><body>
<h1>PenTri v1.10 Report</h1>
<div class="sub">${esc(data.exportedAt)} &middot; ${link(data.target)}</div>

<div class="summary">
  <div class="card"><div class="num">${techs.length}</div><div class="lbl">Tech Stack</div></div>
  <div class="card"><div class="num">${endpoints.length}</div><div class="lbl">Endpoints</div></div>
  <div class="card"><div class="num">${externals.length}</div><div class="lbl">External</div></div>
  <div class="card"><div class="num">${maps.length}</div><div class="lbl">Source Maps</div></div>
  <div class="card"><div class="num">${interesting.length}</div><div class="lbl">Path 발견</div></div>
</div>

<h2>Tech Stack <span class="count">${techs.length}</span></h2>
${table(['Name','Version','Source'], techs.map(t=>[t.name, t.version, t.headerSource||t.source||'']))}

<h2>Endpoints <span class="count">${endpoints.length}</span></h2>
${tableLinked(['URL','Source','External'], endpoints.slice(0,300).map(e=>({cells:[e.url||e.href||'', e.source||'', (e.external||!e.sameOrigin)?'Y':'N'], url:e.url||e.href})))}

<h2>External Domains <span class="count">${externals.length}</span></h2>
${table(['Domain','Count','Type','의심'], externals.map(d=>[d.domain, d.count, (d.types||[]).join(', '), d.suspicious?'⚠':'']))}

<h2>Source Maps <span class="count">${maps.length}</span></h2>
${tableLinked(['URL','Status'], maps.map(m=>{const r=smResults.get(m.url);return {cells:[m.url, r ? (r.status||'ERR') : 'candidate'], url:m.url};}))}

<h2>Upload Analysis <span class="count">${uploads.length}</span></h2>
${table(['Name','Method','Action','Issues'], uploads.map(u=>[u.name, u.method, u.action, (u.issues||[]).map(i=>i.desc).join(' / ')]))}

<h2>Path Scan Results <span class="count">${paths.length} (발견 ${interesting.length})</span></h2>
<div class="legend">
  <span><i class="dot" style="background:#2e7d32"></i>200 존재</span>
  <span><i class="dot" style="background:#1565c0"></i>3xx 리다이렉트</span>
  <span><i class="dot" style="background:#e65100"></i>401/403 차단</span>
  <span><i class="dot" style="background:#b71c1c"></i>404 없음</span>
</div>
<table><thead><tr><th>Status</th><th>Method</th><th>URL</th><th>Redirect/Error</th></tr></thead>
<tbody>${pathRows || '<tr><td colspan="4" class="muted">No data</td></tr>'}</tbody></table>

</body></html>`;
}

// 링크가 포함된 테이블 (첫 열 또는 url 필드를 링크화)
function tableLinked(headers, rows) {
  if (!rows.length) return '<p class="muted">No data</p>';
  const body = rows.map(r => {
    const cells = r.cells.map((c, i) => {
      if (i === 0 && r.url) return `<td><a href="${esc(r.url)}" target="_blank" rel="noopener" style="word-break:break-all">${esc(c)}</a></td>`;
      return `<td>${esc(c)}</td>`;
    }).join('');
    return `<tr>${cells}</tr>`;
  }).join('');
  return `<table><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${body}</tbody></table>`;
}

function table(headers, rows) {
  if (!rows.length) return '<p class="muted">No data</p>';
  return `<table><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${r.map(c=>`<td>${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}

// ── 공통 유틸 ─────────────────────────────────────────────────────
function setCnt(id,n){const el=document.getElementById(id);if(el)el.textContent=n>0?` (${n})`:''}
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function copy(text){navigator.clipboard.writeText(text).then(()=>setStatus('복사됨'));}
function setStatus(msg){/* 상태바 없음 */console.log('[PenTri]',msg);}
