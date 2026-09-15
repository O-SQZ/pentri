import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
const files = dir => readdirSync(dir, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? files(join(dir, entry.name)) : [join(dir, entry.name)]);
const sources = ['src', 'web', 'scripts', 'tests', 'extension'].flatMap(files).filter(file => /\.(?:mjs|js)$/.test(file));
for (const file of sources) execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
for (const file of ['package.json', 'extension/manifest.json']) JSON.parse(readFileSync(file, 'utf8'));
console.log(`${sources.length} JavaScript files and JSON manifests checked.`);
