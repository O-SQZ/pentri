import { spawn } from 'node:child_process';
import { createApp } from '../src/server.mjs';
const port = Number(process.env.PENTRI_PORT || 8787);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PENTRI_PORT must be an integer from 1 to 65535.');
const app = createApp();
let origin;
try { origin = await app.listen(port); }
catch (error) { await app.close(); console.error(`시작 실패: ${error.message}`); process.exit(1); }
console.log(`PenTri Local\n${origin}\n이 창을 유지하세요. 종료: Ctrl+C`);
const [command, args] = process.platform === 'darwin' ? ['open', [origin]]
  : process.platform === 'win32' ? ['rundll32.exe', ['url.dll,FileProtocolHandler', origin]] : ['xdg-open', [origin]];
const browser = spawn(command, args, { stdio: 'ignore' });
browser.on('error', () => console.log(`브라우저에서 직접 열기: ${origin}`));
browser.unref();
let closing = false;
for (const event of ['SIGINT', 'SIGTERM']) process.on(event, async () => {
  if (!closing) { closing = true; await app.close(); process.exit(0); }
});
