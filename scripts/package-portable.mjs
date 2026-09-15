import { cp, mkdir, readFile, writeFile, chmod, readdir, access, mkdtemp, rename, rm } from 'node:fs/promises';
import { join, resolve, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
const root = resolve('.');
const version = JSON.parse(await readFile('package.json', 'utf8')).version;
const supplied = process.env.PENTRI_NODE_DIR;
const binary = supplied ? join(resolve(supplied), process.platform === 'win32' ? 'node.exe' : 'bin/node') : process.execPath;
const info = JSON.parse(execFileSync(binary, ['-p', 'JSON.stringify({version:process.versions.node,platform:process.platform,arch:process.arch,shared:Object.entries(process.config.variables).some(([k,v])=>k.startsWith("node_shared")&&v===true)})'], { encoding: 'utf8' }));
if (info.platform !== process.platform || info.arch !== process.arch || !/^24\./.test(info.version) || Number(info.version.split('.')[1]) < 14) throw new Error('현재 OS/CPU와 일치하는 Node 24.14 이상 24.x 공식 런타임이 필요합니다.');
if (info.shared) throw new Error('외부 라이브러리에 연결된 Node 빌드는 휴대용으로 묶을 수 없습니다. 공식 Node 배포판을 압축 해제하고 PENTRI_NODE_DIR로 루트 폴더를 지정하세요.');
let license;
for (const path of [join(dirname(binary), 'LICENSE'), join(dirname(binary), '..', 'LICENSE')]) {
  try { license = await readFile(path); break; } catch { /* Try the standard archive root next. */ }
}
if (!license || license.length < 1000) throw new Error('Node 공식 배포판의 LICENSE 파일을 찾지 못했습니다. PENTRI_NODE_DIR를 지정하세요.');
const destination = join(root, 'dist', `PenTri-Local-${version}-${process.platform}-${process.arch}`);
try { await access(destination); throw new Error(`이미 존재하는 배포 폴더입니다: ${destination}. 이전 결과를 보관하거나 제거한 뒤 실행하세요.`); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
await mkdir(join(root, 'dist'), { recursive: true });
const staging = await mkdtemp(join(root, 'dist', '.building-'));
try {
await mkdir(join(staging, 'runtime'));
// Explicit allowlist excludes assessments, exports, credentials, original ZIP, and Git metadata.
for (const entry of ['src', 'web', 'extension', 'docs', 'scripts', 'tests', 'package.json', 'README.md', 'CHANGELOG.md', 'THIRD_PARTY_NOTICES.md', 'Start-PenTri.command', 'Start-PenTri.cmd']) {
  await cp(join(root, entry), join(staging, entry), { recursive: true });
}
const executable = join(staging, 'runtime', process.platform === 'win32' ? 'node.exe' : 'node');
await cp(binary, executable);
if (process.platform !== 'win32') { await chmod(executable, 0o755); await chmod(join(staging, 'Start-PenTri.command'), 0o755); }
await writeFile(join(staging, 'runtime', 'NODE_LICENSE.txt'), license);
await writeFile(join(staging, 'runtime', 'build.json'), JSON.stringify({ appVersion: version, ...info }, null, 2));
const files = async dir => (await Promise.all((await readdir(dir, { withFileTypes: true })).map(async entry => entry.isDirectory() ? files(join(dir, entry.name)) : [join(dir, entry.name)]))).flat();
const checksums = [];
for (const file of (await files(staging)).sort()) checksums.push(`${createHash('sha256').update(await readFile(file)).digest('hex')}  ${file.slice(staging.length + 1).replaceAll('\\', '/')}`);
await writeFile(join(staging, 'SHA256SUMS.txt'), `${checksums.join('\n')}\n`);
await rename(staging, destination);
console.log(`Portable folder: ${destination}\nNode ${info.version} included; Ollama/model weights excluded. Launcher distribution, not a signed native installer.`);
} catch (error) { await rm(staging, { recursive: true, force: true }); throw error; }
