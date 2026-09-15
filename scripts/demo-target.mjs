import http from 'node:http';
const port = Number(process.env.DEMO_PORT || 9080);
const fixed = process.env.DEMO_FIXED === '1';
http.createServer((req, res) => {
  if (!['/', '/login'].includes(req.url)) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': fixed ? 'demo=synthetic; HttpOnly; SameSite=Lax' : 'demo=synthetic', ...(fixed ? { 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'", 'X-Content-Type-Options': 'nosniff' } : {}) });
  res.end(`<!doctype html><html lang="ko"><meta charset="utf-8"><title>PenTri local fixture</title><h1>PenTri 테스트 대상</h1><p>합성 자료만 사용하는 로컬 HTTP 구성 예제입니다.</p><p>모드: ${fixed ? '개선 후' : '설정 누락'}</p><a href="/login">Login example</a><!-- Synthetic comment, not a credential --></html>`);
}).listen(port, '127.0.0.1', () => console.log(`Fixture: http://127.0.0.1:${port} · ${fixed ? 'fixed' : 'missing headers'} · Ctrl+C to stop`));
