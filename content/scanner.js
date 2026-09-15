// content/scanner.js — PenTri v1.10
(function () {
  'use strict';
  if (window.__PT_SCANNER__) return;
  window.__PT_SCANNER__ = true;

  let _headers = {};

  // ── AST 분석 ─────────────────────────────────────────────────────
  function astScan(src, scriptIndex) {
    const hits = [];
    if (!src || src.length < 5 || src.length > 600000) return hits;
    let ast;
    try {
      ast = acorn.parse(src, {
        ecmaVersion: 'latest', sourceType: 'module',
        locations: true, allowReturnOutsideFunction: true, allowHashBang: true
      });
    } catch(e) { return regexFallback(src, scriptIndex); }

    const srcLines = src.split('\n');

    function loc(node) {
      const l = node.loc?.start;
      return l ? `inline #${scriptIndex} L${l.line}:${l.column}` : `inline #${scriptIndex}`;
    }

    function getContext(node) {
      const l = node.loc?.start;
      if (!l) return null;
      const li = l.line - 1;
      const s = Math.max(0, li - 2), e = Math.min(srcLines.length - 1, li + 2);
      return Array.from({length: e - s + 1}, (_, i) => {
        const n = s + i + 1;
        return `${s+i === li ? '▶' : ' '} ${String(n).padStart(4)} | ${srcLines[s+i].substring(0,120)}`;
      }).join('\n');
    }

    function push(severity, label, desc, node) {
      hits.push({ severity, label, desc, location: loc(node), context: getContext(node) });
    }

    function walk(node) {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'CallExpression' && node.callee?.name === 'eval') {
        const dyn = node.arguments?.[0]?.type !== 'Literal';
        push(dyn ? 'high' : 'low', 'eval() 사용',
          dyn ? 'eval()에 동적 값 — XSS/코드 인젝션 가능성 확인 필요' : 'eval()에 고정 문자열 (낮은 위험)', node);
      }

      if (node.type === 'AssignmentExpression') {
        const prop = node.left?.property?.name;
        if (prop === 'innerHTML' || prop === 'outerHTML') {
          const dyn = node.right?.type !== 'Literal';
          push(dyn ? 'medium' : 'low', `${prop} 직접 할당`,
            dyn ? '동적 값 할당 — XSS 가능성 확인 필요' : '고정값 할당 (낮은 위험)', node);
        }
      }

      if (node.type === 'CallExpression' &&
          node.callee?.type === 'MemberExpression' &&
          node.callee.object?.name === 'document' &&
          node.callee.property?.name === 'write') {
        push('medium', 'document.write() 사용', 'DOM 직접 조작 — XSS 가능성 확인 필요', node);
      }

      if (node.type === 'Property' && node.key?.name === 'dangerouslySetInnerHTML') {
        push('medium', 'dangerouslySetInnerHTML', 'React XSS — sanitize 여부 확인 필요', node);
      }

      if (node.type === 'AssignmentExpression' &&
          node.left?.object?.name === 'location' &&
          node.left?.property?.name === 'href' &&
          node.right?.type !== 'Literal') {
        push('low', 'location.href 동적 할당', 'Open Redirect 가능성 확인 필요', node);
      }

      for (const key of Object.keys(node)) {
        if (key === 'type') continue;
        const child = node[key];
        if (Array.isArray(child)) child.forEach(walk);
        else if (child?.type) walk(child);
      }
    }

    try { walk(ast); } catch(e) {}
    return hits;
  }

  function regexFallback(src, idx) {
    const hits = [];
    [
      { re: /eval\s*\(/g,               sev: 'high',   l: 'eval() 사용',            d: '동적 코드 실행' },
      { re: /innerHTML\s*=/g,           sev: 'medium', l: 'innerHTML 사용 지점',     d: '입력값 흐름 및 sanitize 여부 확인 필요' },
      { re: /document\.write\s*\(/g,    sev: 'medium', l: 'document.write()',        d: 'DOM XSS 가능성' },
      { re: /dangerouslySetInnerHTML/g, sev: 'medium', l: 'dangerouslySetInnerHTML', d: 'React XSS' },
    ].forEach(({ re, sev, l, d }) => {
      if (re.test(src)) hits.push({ severity: sev, label: l, desc: d, location: `inline #${idx} (regex)`, context: null });
    });
    return hits;
  }

  // ── 민감정보 스캔 ─────────────────────────────────────────────────
  function sensitiveScan(src, location) {
    const hits = [];
    [
      { re: /(api[_-]?key|apikey)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi,     label: 'API Key 하드코딩' },
      { re: /(secret|passwd|password)\s*[:=]\s*['"`]([^'"`\s]{6,})/gi,          label: '패스워드/시크릿 하드코딩' },
      { re: /eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]*/g,          label: 'JWT 토큰 노출' },
      { re: /(aws_access_key_id|aws_secret)\s*[:=]\s*['"`]?([A-Z0-9]{16,})/gi,  label: 'AWS 자격증명 노출' },
      { re: /ghp_[a-zA-Z0-9]{36}/g,                                              label: 'GitHub Token 노출' },
      { re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g,                            label: 'Private Key 노출' },
      { re: /\/\/[^:\s]*:[^@\s]{3,}@/g,                                           label: 'URL 내 자격증명' },
    ].forEach(({ re, label }) => {
      let m; re.lastIndex = 0;
      while ((m = re.exec(src)) !== null && hits.length < 40)
        hits.push({ label, snippet: m[0].substring(0, 80), location });
    });
    return hits;
  }

  // ── Wappalyzer 탐지 ──────────────────────────────────────────────
  function detectStack(headers = {}) {
    const found = [];
    const html = document.documentElement.innerHTML;
    const cookies = document.cookie;
    const scriptSrcs = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);

    for (const [name, sig] of Object.entries(WAPP_SIG || {})) {
      let detected = false, version = '';

      if (!detected && sig.js) {
        for (const [key, pat] of Object.entries(sig.js)) {
          try {
            let obj = window;
            for (const p of key.split('.')) obj = obj?.[p];
            if (obj !== undefined && obj !== null) {
              detected = true;
              const v = String(obj);
              if (/^\d[\d.]+$/.test(v)) version = v;
              break;
            }
          } catch(e) {}
        }
      }
      if (!detected && sig.html)
        for (const p of [].concat(sig.html))
          try { if (new RegExp(p.split(';')[0],'i').test(html)) { detected = true; break; } } catch(e){}
      if (!detected && sig.scriptSrc)
        for (const p of [].concat(sig.scriptSrc))
          for (const src of scriptSrcs)
            try {
              const m = src.match(new RegExp(p.split(';')[0],'i'));
              if (m) { detected = true; if (m[1]) version = m[1]; break; }
            } catch(e){}
      if (!detected && sig.cookies)
        for (const cn of Object.keys(sig.cookies))
          try { if (new RegExp(cn).test(cookies)) { detected = true; break; } } catch(e){}
      if (!detected && sig.dom)
        for (const sel of [].concat(sig.dom))
          try { if (document.querySelector(sel)) { detected = true; break; } } catch(e){}
      if (!detected && sig.headers)
        for (const [hn, hp] of Object.entries(sig.headers)) {
          const hv = headers[hn.toLowerCase()];
          if (hv) try {
            const m = hv.match(new RegExp(hp.split(';')[0],'i'));
            if (m) { detected = true; if (m[1]) version = m[1]; break; }
          } catch(e){}
        }

      if (detected) found.push({ name, version: version || 'detected', cats: sig.cats || [] });
    }

    // 헤더 직접 파싱 (타이밍 무관)
    const server = headers['server'] || '';
    const xpb    = headers['x-powered-by'] || '';
    const addH = (name, val, src) => {
      if (!val) return;
      const vm = val.match(/([\d]+\.[\d.]+)/);
      if (!found.find(f => f.name.toLowerCase() === name.toLowerCase()))
        found.push({ name, version: vm ? vm[1] : 'detected', cats: [], headerSource: src, versionExposed: !!vm });
    };
    if (/nginx/i.test(server))   addH('Nginx',   server, 'Server');
    if (/apache/i.test(server))  addH('Apache',  server, 'Server');
    if (/IIS/i.test(server))     addH('IIS',     server, 'Server');
    if (/php/i.test(xpb))        addH('PHP',     xpb,    'X-Powered-By');
    if (/asp\.net/i.test(xpb))   addH('ASP.NET', xpb,    'X-Powered-By');
    const aspver = headers['x-aspnet-version'];
    if (aspver) addH('ASP.NET Runtime', aspver, 'X-AspNet-Version');
    const xgen = headers['x-generator'];
    if (xgen && !found.find(f => f.name.toLowerCase() === xgen.split(' ')[0].toLowerCase()))
      found.push({ name: xgen.split(' ')[0], version: (xgen.match(/([\d.]+)/)||[])[1]||'detected', cats:[], headerSource:'X-Generator', versionExposed:true });
    if (headers['cf-ray'] && !found.find(f=>f.name==='Cloudflare'))
      found.push({ name:'Cloudflare', version:'detected', cats:[], headerSource:'CF-Ray', versionExposed:false });

    return found;
  }

  // ── 폼 분석 ──────────────────────────────────────────────────────
  function analyzeForms() {
    return Array.from(document.querySelectorAll('form')).map((form, i) => {
      const method = (form.method || 'get').toUpperCase();
      const action = form.action || '(현재 페이지)';
      const issues = [];
      const pw = form.querySelector('input[type="password"]');
      const csrf = form.querySelector(
        'input[name="csrf_token"],input[name="_csrf"],input[name="csrfmiddlewaretoken"],' +
        'input[name="authenticity_token"],input[name="_token"],input[name="__RequestVerificationToken"]'
      );
      if (!csrf && method !== 'GET') issues.push({ severity: 'low', desc: 'DOM 내 CSRF 토큰 미식별 — SameSite/헤더/서버 검증 여부 확인 필요' });
      if (pw && method === 'GET')    issues.push({ severity: 'high',   desc: 'GET 방식으로 패스워드 전송' });
      if (pw && !['off','new-password','current-password'].includes(pw.autocomplete))
        issues.push({ severity: 'low', desc: 'password autocomplete 미설정' });
      if (location.protocol === 'https:' && action.startsWith('http:'))
        issues.push({ severity: 'high', desc: 'HTTPS → HTTP 폼 전송' });
      return { index: i+1, method, action, issues };
    });
  }

  // ── 파일 업로드 폼 분석 ─────────────────────────────────────────
  function analyzeUploads() {
    const results = [];
    const fileInputs = Array.from(document.querySelectorAll('input[type="file"]'));
    if (!fileInputs.length) return results;

    fileInputs.forEach((input, idx) => {
      const form     = input.closest('form');
      const issues   = [];
      const info     = [];

      // accept 속성 분석
      const accept   = input.getAttribute('accept') || '';
      const multiple = input.hasAttribute('multiple');
      const action   = form?.action || '(현재 페이지)';
      const enctype  = form?.getAttribute('enctype') || '';
      const method   = (form?.method || 'get').toUpperCase();
      const name     = input.name || input.id || `(unnamed #${idx+1})`;

      if (!accept) {
        issues.push({ severity:'info', desc:'accept 속성 없음 — 클라이언트 파일 타입 안내 미설정, 서버 검증 여부 확인 필요' });
      } else {
        info.push(`허용 타입(클라이언트): ${accept}`);
        // 위험한 확장자 허용 여부
        const dangerous = ['.php','.jsp','.asp','.aspx','.exe','.sh','.py','.rb','.pl'];
        const allowedDangerous = dangerous.filter(ext => accept.includes(ext));
        if (allowedDangerous.length) {
          issues.push({ severity:'medium', desc:`위험 확장자 accept 허용 후보: ${allowedDangerous.join(', ')} — 서버 차단 여부 확인 필요` });
        }
      }

      if (enctype !== 'multipart/form-data') {
        issues.push({ severity:'info', desc:`enctype="${enctype||'미설정'}" — multipart/form-data 아님, 실제 전송 방식 확인 필요` });
      }

      if (multiple) {
        info.push('multiple: 다중 파일 업로드 허용');
      }

      // 파일 크기 제한 없음 (JS 분석은 외부에서)
      info.push(`action: ${action}`);
      info.push(`method: ${method}`);

      results.push({ index: idx+1, name, accept, multiple, action, method, enctype, issues, info });
    });

    // JS 내 업로드 검증 로직 탐지
    const jsChecks = [];
    document.querySelectorAll('script:not([src])').forEach((s, si) => {
      const src = s.textContent || '';
      [
        { re: /\.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx)/gi, label: '확장자 기반 검증', risk: 'medium', desc: '확장자만 검증 — Content-Type 조작으로 우회 가능' },
        { re: /file\.type|\.type\s*===|\.type\s*!=/g,         label: 'MIME 타입 검증',  risk: 'low',    desc: 'MIME 타입 검증 — 클라이언트 측 우회 가능, 서버 검증 필수' },
        { re: /file\.size|\.size\s*[><]/g,                    label: '파일 크기 제한',  risk: 'info',   desc: '파일 크기 제한 로직 — 서버 측 검증 여부 확인 필요' },
        { re: /FileReader|readAsDataURL|readAsArrayBuffer/g,  label: 'FileReader 사용', risk: 'info',   desc: '클라이언트에서 파일 내용 읽기 — 민감 처리 여부 확인' },
        { re: /new\s+FormData|formData\.append/g,             label: 'FormData 비동기 업로드', risk: 'info', desc: 'AJAX 업로드 — 응답에서 저장 경로 노출 여부 확인 필요' },
      ].forEach(({ re, label, risk, desc }) => {
        re.lastIndex = 0;
        const m = re.exec(src);
        if (m) {
          const line = src.substring(0, m.index).split('\n').length;
          jsChecks.push({ label, risk, desc, location: `inline #${si+1} L${line}`, snippet: m[0] });
        }
      });
    });

    return { forms: results, jsChecks };
  }

  function parseCookies() {
    return document.cookie ? document.cookie.split(';').map(c => {
      const [n, ...v] = c.trim().split('=');
      return { name: (n||'').trim(), value: v.join('=').trim().substring(0,50) };
    }).filter(c => c.name) : [];
  }

  function run(headers = {}) {
    _headers = { ..._headers, ...headers };
    const domPatterns = [], sensitiveStrings = [];
    document.querySelectorAll('script:not([src])').forEach((s, i) => {
      const src = s.textContent?.trim();
      if (!src || src.length < 5) return;
      domPatterns.push(...astScan(src, i+1));
      sensitiveStrings.push(...sensitiveScan(src, `inline script #${i+1}`));
    });
    sensitiveStrings.push(...sensitiveScan(
      document.documentElement.outerHTML.substring(0, 150000), 'HTML'));
    chrome.runtime.sendMessage({
      type: 'SCAN_RESULT',
      data: {
        url: location.href, ts: new Date().toISOString(),
        techStack: detectStack(_headers),
        domPatterns, sensitiveStrings,
        formAnalysis: analyzeForms(),
        uploadAnalysis: analyzeUploads(),
        cookies: parseCookies(),
      }
    });
  }

  run();

  chrome.runtime.onMessage.addListener((msg, sender, res) => {
    if (msg.type === 'DO_SCAN')       { run(msg.headers || {}); res?.({ ok: true }); }
    if (msg.type === 'HEADERS_READY') { run(msg.headers || {}); }
    if (msg.type === 'HIGHLIGHT_FIELD') {
      highlightField(msg.selector, msg.value);
      res?.({ ok: true });
    }
    return true;
  });

  function highlightField(selector, value) {
    document.querySelectorAll('.__pt_hl__').forEach(el => {
      el.style.outline = el.dataset.origOutline || '';
      el.classList.remove('__pt_hl__');
    });
    const el = document.querySelector(selector);
    if (!el) return;
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.dataset.origOutline = el.style.outline;
    el.style.outline = '3px solid #ff8800';
    el.classList.add('__pt_hl__');
    if (value !== undefined && value !== null) {
      el.focus(); el.value = value;
      el.dispatchEvent(new Event('input',  { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }
    setTimeout(() => { el.style.outline = el.dataset.origOutline||''; el.classList.remove('__pt_hl__'); }, 3000);
  }
})();
