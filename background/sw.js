// background/sw.js — PenTri v1.10
'use strict';

const tabHeaders  = new Map();
const tabScan     = new Map();
const tabCollect  = new Map();
const robotsCache = new Map();

let lastTabId = null;
let lastWinId = null;

chrome.tabs.onActivated.addListener((info) => {
  chrome.tabs.get(info.tabId, (tab) => {
    if (chrome.runtime.lastError) return;
    if (tab.url?.startsWith('http')) { lastTabId = info.tabId; lastWinId = info.windowId; }
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.active && tab.url?.startsWith('http')) {
    lastTabId = tabId; lastWinId = tab.windowId;
  }
});

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== 'main_frame') return;
    const h = {}; const setCookies = [];
    (details.responseHeaders || []).forEach(r => {
      const name = r.name.toLowerCase();
      if (name === 'set-cookie') setCookies.push(r.value); else h[name] = r.value;
    });
    if (setCookies.length) h['__set-cookie-list__'] = setCookies;
    tabHeaders.set(details.tabId, h);
    chrome.tabs.sendMessage(details.tabId, { type: 'HEADERS_READY', headers: h }).catch(() => {});
  },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['responseHeaders']
);

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const senderTabId = sender.tab?.id;

  switch (msg.type) {

    case 'SCAN_RESULT':
      if (senderTabId) {
        const entry = { ...msg.data, updatedAt: Date.now() };
        tabScan.set(senderTabId, entry);
        updateBadge(senderTabId, msg.data);
        chrome.storage.session.set({ [`scan_${senderTabId}`]: entry }).catch(() => {});
      }
      break;

    case 'COLLECT_RESULT':
      if (senderTabId) {
        const entry = { ...msg.data, updatedAt: Date.now() };
        tabCollect.set(senderTabId, entry);
        chrome.storage.session.set({ [`collect_${senderTabId}`]: entry }).catch(() => {});
      }
      break;

    // Path Scan 결과 저장 (탭 단위 session)
    case 'SAVE_PATHSCAN':
      if (msg.tabId != null) {
        chrome.storage.session.set({ [`pathscan_${msg.tabId}`]: msg.data }).catch(() => {});
      }
      sendResponse?.({ ok: true });
      return true;

    case 'GET_PATHSCAN': {
      const id = msg.tabId;
      if (id == null) { sendResponse({ data: null }); return true; }
      chrome.storage.session.get([`pathscan_${id}`]).then(s => {
        sendResponse({ data: s[`pathscan_${id}`] || null });
      }).catch(() => sendResponse({ data: null }));
      return true;
    }

    case 'GET_ALL_DATA': {
      chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        const id = (tabs[0]?.url?.startsWith('http') ? tabs[0].id : null) || lastTabId;
        let scan = id ? tabScan.get(id) : null;
        let collect = id ? tabCollect.get(id) : null;
        if (id && !scan) {
          try {
            const s = await chrome.storage.session.get([`scan_${id}`, `collect_${id}`]);
            scan    = s[`scan_${id}`]    || null;
            collect = s[`collect_${id}`] || null;
            if (scan)    tabScan.set(id, scan);
            if (collect) tabCollect.set(id, collect);
          } catch(e) {}
        }
        const hdrs = id ? (tabHeaders.get(id) || {}) : {};
        sendResponse({ scan, collect, headers: hdrs, tabId: id, tabUrl: id ? (scan?.url || collect?.url || '') : '' });
      });
      return true;
    }

    case 'RESCAN': {
      chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        const tab = tabs[0];
        const id = tab?.url?.startsWith('http') ? tab.id : null;
        if (!id) { sendResponse({ ok: false, err: 'HTTP/HTTPS 대상 탭 없음' }); return; }

        lastTabId = id;
        lastWinId = tab.windowId;
        const h = tabHeaders.get(id) || {};
        const received = { scan: false, collect: false };
        let done = false;

        const cleanup = (payload) => {
          if (done) return;
          done = true;
          chrome.runtime.onMessage.removeListener(listener);
          clearTimeout(timer);
          sendResponse(payload);
        };

        const listener = (m, s2) => {
          if (s2.tab?.id !== id) return;
          if (m.type === 'SCAN_RESULT') received.scan = true;
          if (m.type === 'COLLECT_RESULT') received.collect = true;
          if (received.scan && received.collect) cleanup({ ok: true, partial: false });
        };

        const timer = setTimeout(() => {
          cleanup({ ok: received.scan || received.collect, partial: true, received });
        }, 7000);

        chrome.runtime.onMessage.addListener(listener);
        try {
          await chrome.scripting.executeScript({
            target: { tabId: id, allFrames: false },
            files: [
              'assets/vendor/acorn.js',
              'assets/db/wapp_sig.js',
              'content/scanner.js',
              'content/collector.js'
            ]
          });
          chrome.tabs.sendMessage(id, { type: 'DO_SCAN', headers: h }).catch(() => {});
        } catch (e) {
          cleanup({ ok: false, err: e.message });
        }
      });
      return true;
    }

    case 'FETCH_ROBOTS': {
      const cacheKey = `${msg.origin}/${msg.file}`;
      if (robotsCache.has(cacheKey)) {
        const cached = robotsCache.get(cacheKey);
        if (Date.now() - cached.ts < 600000) {
          sendResponse({ ok: true, text: cached.text, status: cached.status, cached: true });
          return true;
        }
      }
      fetch(`${msg.origin}/${msg.file}`, { signal: AbortSignal.timeout(8000) })
        .then(r => r.text().then(text => {
          robotsCache.set(cacheKey, { text, status: r.status, ts: Date.now() });
          sendResponse({ ok: true, text, status: r.status, cached: false });
        }))
        .catch(e => sendResponse({ ok: false, err: e.message }));
      return true;
    }

    case 'FETCH_JS': {
      safeFetchText(msg.url, {
        timeoutMs: 10000,
        maxBytes: 1000000,
        allowedContentType: /javascript|ecmascript|text\/plain|application\/x-javascript/i,
      })
        .then(result => sendResponse({ ...result, url: msg.url }))
        .catch(e => sendResponse({ ok: false, err: e.message, url: msg.url }));
      return true;
    }

    case 'FETCH_URL': {
      safeFetchText(msg.url, { timeoutMs: 8000, maxBytes: 1000000 })
        .then(result => sendResponse(result))
        .catch(e => sendResponse({ ok: false, err: e.message }));
      return true;
    }

    case 'VERIFY_SOURCEMAP': {
      verifySourceMap(msg.url)
        .then(result => sendResponse(result))
        .catch(e => sendResponse({ ok: false, status: 0, sourceMapStatus: 'ERROR', err: e.message }));
      return true;
    }

    // 민감 경로 단건 요청: HEAD 우선, 405/501/0은 GET fallback
    case 'SCAN_PATH': {
      scanPathWithFallback(msg.url, msg.timeout || 4000)
        .then(result => sendResponse(result))
        .catch(e => sendResponse({ ok: false, status: 0, method: 'HEAD', fallbackUsed: false, err: e.message }));
      return true;
    }

    case 'DOWNLOAD': {
      const filename = sanitizeFilename(msg.filename || 'pentri-export.json');
      const mime = msg.mime || 'application/json';
      const data = String(msg.data || '');
      const url = 'data:' + mime + ';charset=utf-8,' + encodeURIComponent(data);
      chrome.downloads.download({ url, filename, saveAs: true }, (downloadId) => {
        if (chrome.runtime.lastError) sendResponse({ ok: false, err: chrome.runtime.lastError.message });
        else sendResponse({ ok: true, downloadId });
      });
      return true;
    }

    case 'QUERY_CVE': {
      const keyword = encodeURIComponent(msg.keyword);
      fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&resultsPerPage=5`,
        { signal: AbortSignal.timeout(10000) })
        .then(r => r.json().then(data => {
          const items = (data.vulnerabilities || []).map(v => ({
            id:       v.cve?.id || '',
            desc:     v.cve?.descriptions?.find(d => d.lang === 'en')?.value?.substring(0, 150) || '',
            severity: v.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
                      v.cve?.metrics?.cvssMetricV2?.[0]?.baseSeverity || 'UNKNOWN',
            score:    v.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ||
                      v.cve?.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || null,
          }));
          sendResponse({ ok: true, items });
        }))
        .catch(e => sendResponse({ ok: false, err: e.message, items: [] }));
      return true;
    }

    case 'SAVE_CUSTOM': {
      chrome.storage.local.get([msg.key], (r) => {
        const list = r[msg.key] || [];
        list.unshift({ id: crypto.randomUUID(), ...msg.data });
        chrome.storage.local.set({ [msg.key]: list }, () => sendResponse({ ok: true }));
      });
      return true;
    }
    case 'GET_CUSTOM': {
      chrome.storage.local.get([msg.key], (r) => sendResponse({ data: r[msg.key] || [] }));
      return true;
    }
    case 'DELETE_CUSTOM': {
      chrome.storage.local.get([msg.key], (r) => {
        const list = (r[msg.key] || []).filter(i => i.id !== msg.id);
        chrome.storage.local.set({ [msg.key]: list }, () => sendResponse({ ok: true }));
      });
      return true;
    }
    case 'UPDATE_CUSTOM': {
      chrome.storage.local.get([msg.key], (r) => {
        const list = (r[msg.key] || []).map(i => i.id === msg.data.id ? { ...i, ...msg.data } : i);
        chrome.storage.local.set({ [msg.key]: list }, () => sendResponse({ ok: true }));
      });
      return true;
    }
    case 'SAVE_SETTINGS': {
      chrome.storage.local.set({ ptSettings: msg.data }, () => sendResponse({ ok: true }));
      return true;
    }
    case 'GET_SETTINGS': {
      chrome.storage.local.get(['ptSettings'], (r) => sendResponse({ data: r.ptSettings || {} }));
      return true;
    }
  }
});


function isHttpUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch(e) {
    return false;
  }
}

async function safeFetchText(url, opts = {}) {
  const {
    timeoutMs = 8000,
    maxBytes = 1000000,
    allowedContentType = null,
  } = opts;

  if (!isHttpUrl(url)) return { ok: false, status: 0, err: 'unsupported URL scheme' };

  const r = await fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
    redirect: 'manual',
    cache: 'no-store',
  });

  const contentType = r.headers.get('content-type') || '';
  const contentLength = Number(r.headers.get('content-length') || 0);
  const sourceMapHeader = r.headers.get('sourcemap') || r.headers.get('x-sourcemap') || '';

  if (!r.ok) {
    return { ok: false, status: r.status, err: `HTTP ${r.status}`, contentType, contentLength, sourceMapHeader };
  }

  if (allowedContentType && contentType && !allowedContentType.test(contentType)) {
    return { ok: false, status: r.status, err: `unexpected content-type: ${contentType}`, contentType, contentLength, sourceMapHeader };
  }

  if (contentLength && contentLength > maxBytes) {
    return { ok: false, status: r.status, err: `response too large: ${contentLength}`, contentType, contentLength, sourceMapHeader };
  }

  let text = await r.text();
  let truncated = false;
  if (text.length > maxBytes) {
    text = text.slice(0, maxBytes);
    truncated = true;
  }

  return { ok: true, text, status: r.status, contentType, contentLength: contentLength || text.length, truncated, sourceMapHeader };
}

async function verifySourceMap(url) {
  if (!isHttpUrl(url)) return { ok: false, status: 0, sourceMapStatus: 'ERROR', err: 'unsupported URL scheme' };

  let result;
  try {
    result = await safeFetchText(url, {
      timeoutMs: 8000,
      maxBytes: 2000000,
      allowedContentType: null,
    });
  } catch (e) {
    return { ok: false, status: 0, sourceMapStatus: e.name === 'TimeoutError' ? 'ERROR' : 'ERROR', err: e.message };
  }

  const status = result.status || 0;
  const contentType = result.contentType || '';

  if (status === 401 || status === 403) return { ...result, ok: false, sourceMapStatus: 'FORBIDDEN' };
  if (status === 404) return { ...result, ok: false, sourceMapStatus: 'NOT_FOUND' };
  if ([301,302,303,307,308].includes(status)) return { ...result, ok: false, sourceMapStatus: 'REDIRECT' };
  if (!result.ok) return { ...result, ok: false, sourceMapStatus: 'UNKNOWN' };

  const text = result.text || '';
  if (/^\s*</.test(text) || /text\/html/i.test(contentType)) {
    return { ...result, text: undefined, ok: false, sourceMapStatus: 'SOFT_404', err: 'HTML response, not a source map' };
  }

  try {
    const json = JSON.parse(text);
    const isSourceMap =
      Number(json.version) >= 3 &&
      Array.isArray(json.sources) &&
      typeof json.mappings === 'string';

    if (!isSourceMap) {
      return { ...result, text: undefined, ok: false, sourceMapStatus: 'SOFT_404', err: 'JSON is not a valid source map shape' };
    }

    const hasSourcesContent = Array.isArray(json.sourcesContent) && json.sourcesContent.some(v => typeof v === 'string' && v.length > 0);
    return {
      ok: true,
      status,
      sourceMapStatus: hasSourcesContent ? 'EXPOSED_WITH_SOURCE' : 'EXPOSED',
      contentType,
      contentLength: result.contentLength,
      sourcesCount: json.sources.length,
      hasSourcesContent,
      file: typeof json.file === 'string' ? json.file : '',
      truncated: result.truncated,
    };
  } catch(e) {
    return { ...result, text: undefined, ok: false, sourceMapStatus: 'SOFT_404', err: 'invalid JSON source map' };
  }
}

async function fetchPath(url, method, timeoutMs) {
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      method,
      signal: ctrl.signal,
      redirect: 'manual',
      cache: 'no-store'
    });
    const size = r.headers.get('content-length') || null;
    const ctype = r.headers.get('content-type') || null;
    return {
      ok: true,
      status: r.status,
      method,
      redirectTo: r.headers.get('location') || null,
      contentLength: size,
      contentType: ctype,
      err: null
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function scanPathWithFallback(url, timeoutMs) {
  try {
    const head = await fetchPath(url, 'HEAD', timeoutMs);
    if (![405, 501].includes(head.status)) return { ...head, fallbackUsed: false };
    const get = await fetchPath(url, 'GET', timeoutMs);
    return { ...get, fallbackUsed: true, firstMethod: 'HEAD', firstStatus: head.status };
  } catch (e) {
    if (e.name !== 'AbortError') {
      try {
        const get = await fetchPath(url, 'GET', timeoutMs);
        return { ...get, fallbackUsed: true, firstMethod: 'HEAD', firstStatus: 0, firstError: e.message };
      } catch (e2) {
        return { ok: false, status: 0, method: 'GET', fallbackUsed: true, firstMethod: 'HEAD', firstStatus: 0, firstError: e.message, err: e2.name === 'AbortError' ? 'timeout' : e2.message };
      }
    }
    return { ok: false, status: 0, method: 'HEAD', fallbackUsed: false, err: 'timeout' };
  }
}

function sanitizeFilename(name) {
  return String(name).replace(/[\\/:*?"<>|]+/g, '_').slice(0, 120) || 'pentri-export.json';
}

function updateBadge(tabId, scan) {
  const n = [...(scan.domPatterns||[])].filter(i => i.severity==='high').length
          + (scan.sensitiveStrings||[]).length;
  chrome.action.setBadgeText({ text: n > 0 ? String(n) : '', tabId });
  chrome.action.setBadgeBackgroundColor({ color: n > 0 ? '#e05252' : '#52c87a', tabId });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  tabHeaders.delete(tabId); tabScan.delete(tabId); tabCollect.delete(tabId);
  if (lastTabId === tabId) lastTabId = null;
  // 탭 닫히면 해당 탭의 세션 데이터 삭제
  chrome.storage.session.remove([
    `scan_${tabId}`, `collect_${tabId}`, `pathscan_${tabId}`
  ]).catch(() => {});
});
