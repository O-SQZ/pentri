// Optional real-browser validation. Uses synthetic localhost data, never a user's profile.
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import http from 'node:http';
import assert from 'node:assert/strict';
import { createApp } from '../src/server.mjs';

const binary = process.env.CHROME_BIN || (process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : process.platform === 'win32' ? 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' : 'google-chrome');
const profile = await mkdtemp(join(tmpdir(), 'pentri-browser-'));
const artifacts = resolve('artifacts/browser'); await mkdir(artifacts, { recursive: true });
const app = createApp({ dataFile: ':memory:', ollama: { status: async () => ({ available: false, models: [], error: 'Browser fixture: model inference tested separately.' }) }, runnerOptions: { intervalMs: 0 } });
const origin = await app.listen(0);
const target = http.createServer((_req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<h1>Synthetic browser fixture</h1>'); });
await new Promise(resolve => target.listen(0, '127.0.0.1', resolve));
const targetOrigin = `http://127.0.0.1:${target.address().port}`;
const chrome = spawn(binary, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-component-update', '--disable-sync', ...(process.platform === 'linux' && process.getuid?.() === 0 ? ['--no-sandbox'] : []), 'about:blank'], { stdio: 'ignore' });
let launchError; chrome.on('error', error => { launchError = error; });
let socket;
const exceptions = [];
try {
  let port;
  for (let i = 0; i < 150; i++) {
    if (launchError) throw launchError;
    try { port = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]; break; } catch { await delay(100); }
  }
  if (!port) throw new Error('Chrome did not start. Set CHROME_BIN to an installed Chrome/Chromium executable.');
  const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  socket = new WebSocket(pages.find(page => page.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', reject, { once: true }); });
  let nextId = 0;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const data = JSON.parse(event.data);
    if (data.method === 'Runtime.exceptionThrown') exceptions.push(data.params.exceptionDetails);
    if (pending.has(data.id)) { const { resolve, reject, timer } = pending.get(data.id); clearTimeout(timer); pending.delete(data.id); data.error ? reject(new Error(data.error.message)) : resolve(data.result); }
  });
  const call = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId; const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
    pending.set(id, { resolve, reject, timer }); socket.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async expression => {
    const result = await call('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result?.value;
  };
  const wait = async expression => { for (let i = 0; i < 100; i++) { if (await evaluate(expression)) return; await delay(100); } throw new Error(`UI wait failed: ${expression}`); };
  await call('Runtime.enable'); await call('Page.enable');
  await call('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
  await call('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: artifacts });
  await call('Page.navigate', { url: origin });
  await wait("document.querySelector('#welcome')?.hidden === false");
  await evaluate("document.querySelector('#welcome-create').click()");
  await evaluate(`(() => { const f=document.querySelector('#project-form'); f.elements.name.value='휴대형 진단 · 로컬 데모'; f.elements.origin.value=${JSON.stringify(targetOrigin)}; f.elements.paths.value='/'; f.dispatchEvent(new Event('input',{bubbles:true})); f.requestSubmit(); })()`);
  await wait("document.querySelector('#project-title')?.textContent === '휴대형 진단 · 로컬 데모'");
  await evaluate("(() => { const label=[...document.querySelectorAll('.check-label')].find(el=>el.textContent.includes('진단 권한')); const input=label.querySelector('input'); input.checked=true; input.dispatchEvent(new Event('change')); [...document.querySelectorAll('button')].find(el=>el.textContent==='진단 시작').click(); })()");
  await wait("document.querySelector('table')?.textContent.includes('관찰됨')");
  await call('Page.captureScreenshot').then(result => writeFile(join(artifacts, 'recon.png'), Buffer.from(result.data, 'base64')));
  await evaluate("document.querySelector('[data-tab=analyze]').click()");
  await wait("!!document.querySelector('.finding-detail textarea')");
  await evaluate("(() => { const select=document.querySelector('.finding-detail select'); select.value='confirmed'; select.dispatchEvent(new Event('change')); const note=document.querySelector('.finding-detail textarea'); note.value='합성 응답에서 설정 누락을 확인. 실제 취약성은 별도 검토.'; note.dispatchEvent(new Event('input')); [...document.querySelectorAll('button')].find(el=>el.textContent==='판단 저장').click(); })()");
  await wait("document.querySelector('#notice')?.textContent.includes('판단과 메모')");
  await call('Page.captureScreenshot').then(result => writeFile(join(artifacts, 'analyze.png'), Buffer.from(result.data, 'base64')));
  await evaluate("document.querySelector('[data-tab=report]').click()");
  await wait("document.querySelector('#pane')?.textContent.includes('해시 체인 일치')");
  await evaluate("document.querySelector('.download-card button').click()");
  await wait("document.querySelector('#pane')?.textContent.includes('report.exported')");
  await call('Page.captureScreenshot').then(result => writeFile(join(artifacts, 'report.png'), Buffer.from(result.data, 'base64')));
  await call('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: false });
  await call('Page.captureScreenshot').then(result => writeFile(join(artifacts, 'mobile.png'), Buffer.from(result.data, 'base64')));
  const overflow = await evaluate('document.documentElement.scrollWidth > window.innerWidth');
  assert.equal(overflow, false, 'mobile layout must not overflow horizontally');
  assert.equal(exceptions.length, 0, 'browser must have no uncaught JavaScript errors');
  console.log(JSON.stringify({ passed: true, checks: ['project creation', 'scope approval', 'HTTP run', 'evidence rendering', 'review save', 'audit rendering', 'HTML download', 'responsive layout', 'no JS exceptions'], artifacts }, null, 2));
} finally {
  socket?.close(); chrome.kill('SIGTERM');
  await new Promise(resolve => { if (chrome.exitCode !== null || launchError) resolve(); else { const timer = setTimeout(resolve, 3000); chrome.once('exit', () => { clearTimeout(timer); resolve(); }); } });
  await new Promise(resolve => { target.close(resolve); target.closeAllConnections(); });
  await app.close(); await rm(profile, { recursive: true, force: true, maxRetries: 3 });
}
