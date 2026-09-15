const $ = selector => document.querySelector(selector);
let snapshot;
function mask(value) {
  return String(value).replace(/([?&][^=\s&#]+)=([^&#\s"'<>]*)/g, '$1=[REDACTED_QUERY]')
    .replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_=.-]+/gi, '[REDACTED_AUTH]')
    .replace(/((?:password|secret|token|api[_-]?key)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s<>&,;]+)/gi, '$1[REDACTED]');
}
async function target() {
  const key = new URL(location.href).searchParams.get('session');
  const record = (await chrome.storage.session.get(`target_${key}`))[`target_${key}`];
  if (!record) throw new Error('대상 기록이 없습니다. 대상 페이지에서 아이콘을 다시 클릭하세요.');
  const tab = await chrome.tabs.get(record.tabId);
  if (tab.url !== record.url) throw new Error('대상 페이지가 이동했습니다. 새 페이지에서 아이콘을 다시 클릭하세요.');
  return record;
}
$('#collect').addEventListener('click', async () => {
  snapshot = null; $('#export').disabled = true; $('#collect').disabled = true; $('#preview').textContent = '';
  try {
    const record = await target();
    const [result] = await chrome.scripting.executeScript({ target: { tabId: record.tabId }, func: () => {
      const clip = value => String(value || '').slice(0, 500);
      const endpoints = [...document.querySelectorAll('a[href],script[src],link[href],iframe[src]')].slice(0, 100).map(el => ({ kind: el.tagName.toLowerCase(), url: clip(el.href || el.src) }));
      const comments = [];
      const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
      while (comments.length < 50 && walker.nextNode()) comments.push({ source: 'DOM', text: clip(walker.currentNode.textContent) });
      const forms = [...document.forms].slice(0, 30).map(form => ({ action: clip(form.action), method: form.method, enctype: form.enctype, fields: [...form.elements].slice(0, 50).map(el => ({ name: clip(el.name), type: clip(el.type), accept: clip(el.accept) })) }));
      return { schemaVersion: 1, url: location.href, title: clip(document.title), capturedAt: new Date().toISOString(), endpoints, comments, forms };
    } });
    await target();
    if (!result?.result || result.result.url !== record.url) throw new Error('수집 중 대상 페이지가 변경되었습니다. 다시 수집하세요.');
    snapshot = result.result;
    snapshot.url = snapshot.url.split('#')[0];
    snapshot.documentId = result.documentId;
    // Apply masking to individual values so quotation escapes cannot corrupt JSON.
    const clean = value => typeof value === 'string' ? mask(value) : Array.isArray(value) ? value.map(clean) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, val]) => [key, clean(val)])) : value;
    snapshot = clean(snapshot);
    $('#preview').textContent = JSON.stringify(snapshot, null, 2);
    $('#export').disabled = false; $('#status').textContent = '관찰을 수집했습니다. 실제 취약성의 확정 결과가 아닙니다.';
  } catch (error) { $('#status').textContent = error.message; }
  finally { $('#collect').disabled = false; }
});
$('#export').addEventListener('click', () => {
  if (!snapshot) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = 'pentri-observation.json'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
target().then(record => { $('#target').textContent = mask(record.url.split('#')[0]); }).catch(error => { $('#status').textContent = error.message; $('#collect').disabled = true; });
