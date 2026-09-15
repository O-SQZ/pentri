// content/collector.js — PenTri v1.10
(function () {
  'use strict';
  if (window.__PT_COLLECTOR__) return;
  window.__PT_COLLECTOR__ = true;

  function collect() {
    chrome.runtime.sendMessage({
      type: 'COLLECT_RESULT',
      data: {
        url:             location.href,
        ts:              new Date().toISOString(),
        inputFields:     collectInputFields(),
        hiddenFields:    collectHiddenFields(),
        endpoints:       collectEndpoints(),
        externalDomains: collectExternalDomains(),
        mixedContent:    collectMixedContent(),
        sourceMaps:      collectSourceMaps(),
        comments:        collectComments(),
        metaTech:        collectMetaTech(),
        externalScripts: collectExternalScripts(),
      }
    });
  }

  function maskValue(value) {
    const v = String(value || '');
    if (!v) return { masked: '', length: 0, hasValue: false };
    if (v.length <= 8) return { masked: '***', length: v.length, hasValue: true };
    return { masked: `${v.slice(0, 4)}...${v.slice(-4)}`, length: v.length, hasValue: true };
  }

  function collectInputFields() {
    return Array.from(document.querySelectorAll('input:not([type="hidden"]), textarea, select'))
      .map((el, idx) => {
        const form = el.closest('form');
        let selector = el.id ? `#${CSS.escape(el.id)}`
          : el.name ? `${el.tagName.toLowerCase()}[name="${CSS.escape(el.name)}"]`
          : `${el.tagName.toLowerCase()}:nth-of-type(${idx+1})`;
        return {
          tag: el.tagName.toLowerCase(), type: el.type||'', name: el.name||'',
          id: el.id||'', placeholder: el.placeholder||'', required: el.required,
          autocomplete: el.autocomplete||'', selector,
          formAction: form?.action||'', formMethod: (form?.method||'get').toUpperCase(),
        };
      });
  }

  function collectHiddenFields() {
    const suspRe = /csrf|_token|authenticity_token|session|auth_token|access_token|api.?key|secret/i;
    return Array.from(document.querySelectorAll('input[type="hidden"]')).map((el, idx) => {
      const selector = el.id ? `#${CSS.escape(el.id)}`
        : el.name ? `input[name="${CSS.escape(el.name)}"]`
        : `input[type="hidden"]:nth-of-type(${idx+1})`;
      const masked = maskValue(el.value);
      return {
        name: el.name||'', id: el.id||'',
        value: masked.masked,
        valueMasked: masked.masked,
        valueLength: masked.length,
        hasValue: masked.hasValue,
        suspicious: suspRe.test(`${el.name} ${el.id}`),
        selector, formAction: el.closest('form')?.action||'',
      };
    });
  }

  function collectEndpoints() {
    const seen = new Set(); const eps = [];
    function add(url, source) {
      if (!url||url.startsWith('#')||url.startsWith('javascript:')||url.startsWith('mailto:')||url.startsWith('data:')) return;
      try {
        const abs = new URL(url, location.href).href;
        if (seen.has(abs)) return; seen.add(abs);
        eps.push({ url: abs, source, sameOrigin: abs.startsWith(location.origin), isApi: /\/api\/|\/v[0-9]+\/|\.json(\?|$)|graphql/i.test(abs) });
      } catch(e){}
    }
    document.querySelectorAll('a[href]').forEach(el => add(el.getAttribute('href'), 'a'));
    document.querySelectorAll('form[action]').forEach(el => add(el.action, 'form'));
    document.querySelectorAll('script[src]').forEach(el => add(el.src, 'script'));
    document.querySelectorAll('script:not([src])').forEach(script => {
      const src = script.textContent||'';
      [/fetch\s*\(\s*['"`]([^'"`\s]+)['"`]/g,
       /axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`\s]+)['"`]/g,
       /['"`](\/api\/[^'"`\s]{2,})['"`]/g,
       /['"`](\/v[0-9]+\/[^'"`\s]{2,})['"`]/g,
      ].forEach(re => { let m; re.lastIndex=0; while((m=re.exec(src))!==null) add(m[1],'js-inline'); });
    });
    return eps.slice(0,300);
  }

  function collectExternalDomains() {
    const domains = new Map();
    const origin = location.hostname;
    const suspRe = /analytics|tracker|pixel|\.ad\.|\/ads\/|doubleclick|facebook\.net|hotjar|clarity\.ms|segment\.com|mixpanel/i;
    function add(url, type) {
      try {
        const h = new URL(url).hostname;
        if (!h||h===origin||h.endsWith('.'+origin)) return;
        if (!domains.has(h)) domains.set(h,{types:new Set(),count:0});
        domains.get(h).types.add(type); domains.get(h).count++;
      } catch(e){}
    }
    document.querySelectorAll('script[src]').forEach(el=>add(el.src,'script'));
    document.querySelectorAll('link[href]').forEach(el=>add(el.href,'link'));
    document.querySelectorAll('img[src]').forEach(el=>add(el.src,'image'));
    document.querySelectorAll('iframe[src]').forEach(el=>add(el.src,'iframe'));
    return Array.from(domains.entries())
      .map(([domain,info])=>({domain,types:Array.from(info.types),count:info.count,suspicious:suspRe.test(domain)}))
      .sort((a,b)=>b.count-a.count);
  }

  function collectMixedContent() {
    if (location.protocol !== 'https:') return [];
    const issues = [];
    [['script[src]','src','script'],['link[href]','href','stylesheet'],
     ['img[src]','src','image'],['iframe[src]','src','iframe'],['form[action]','action','form']]
      .forEach(([sel,attr,type])=>{
        document.querySelectorAll(sel).forEach(el=>{
          const url = el[attr]||el.getAttribute(attr);
          if (url?.startsWith('http:')) issues.push({type,url:url.substring(0,120),tag:el.tagName.toLowerCase()});
        });
      });
    return issues;
  }

  function collectSourceMaps() {
    const maps = []; const seen = new Set();

    function addMap(rawUrl, type, extra = {}) {
      if (!rawUrl) return;
      try {
        const url = new URL(rawUrl.trim(), location.href).href;
        if (seen.has(url)) return;
        seen.add(url);
        maps.push({ url, type, ...extra });
      } catch(e) {}
    }

    const smRe = /(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)\s*(?:\*\/)?/g;

    document.querySelectorAll('script:not([src])').forEach((script,idx)=>{
      let m;
      while ((m = smRe.exec(script.textContent || '')) !== null) {
        addMap(m[1], 'inline-comment', { raw:m[0], scriptIndex:idx+1 });
      }
    });

    document.querySelectorAll('script[src]').forEach(el=>{
      addMap(el.src + '.map', 'inferred', { baseScript:el.src });
    });

    return maps.slice(0,60);
  }

  function collectComments() {
    const comments = [];
    const suspRe = /password|passwd|secret|api.?key|token|todo|fixme|hack|debug|test.*account|admin|credential|database|connection/i;
    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
    let node;
    while ((node=walker.nextNode())!==null) {
      const text = node.textContent.trim();
      if (text.length < 4) continue;
      comments.push({ text: text.substring(0,300), suspicious: suspRe.test(text) });
      if (comments.length >= 60) break;
    }
    return comments;
  }

  function collectMetaTech() {
    const found = [];
    document.querySelectorAll('meta[name="generator"]').forEach(el=>{
      const content = el.getAttribute('content')||'';
      if (!content) return;
      const vm = content.match(/([\d]+\.[\d.]+)/);
      found.push({ name: content.split(' ')[0]||content, version: vm?vm[1]:'detected', source:'meta[generator]', raw:content });
    });
    if (document.querySelector('link[rel="https://api.w.org/"]') && !found.find(f=>f.name.toLowerCase()==='wordpress'))
      found.push({ name:'WordPress', version:'detected', source:'link[rel=api.w.org]', raw:'' });
    const vCommentRe = /(wordpress|drupal|joomla|typo3|magento)\s+v?([\d.]+)/i;
    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
    let node;
    while ((node=walker.nextNode())!==null) {
      const m = node.textContent.match(vCommentRe);
      if (m) found.push({ name: m[1].charAt(0).toUpperCase()+m[1].slice(1), version:m[2], source:'HTML comment', raw:node.textContent.substring(0,100) });
    }
    return found;
  }

  // 외부 JS 파일 URL 목록 수집 (분석은 popup에서 요청 시)
  function collectExternalScripts() {
    return Array.from(document.querySelectorAll('script[src]'))
      .map(el => ({ url: el.src, sameOrigin: el.src.startsWith(location.origin) }))
      .filter(s => s.url);
  }

  collect();

  chrome.runtime.onMessage.addListener((msg, sender, res) => {
    if (msg.type === 'DO_SCAN') { collect(); res?.({ ok: true }); }
    return true;
  });
})();
