import { readFile, writeFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
const { version } = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const hashes = {};
for (const target of ['chromium', 'firefox']) {
  const name = `tegin-${target}-${version}.zip`;
  const path = resolve('dist', name);
  await rm(path, { force: true });
  execFileSync('zip', ['-q', '-r', path, '.'], { cwd: resolve('dist', target) });
  hashes[name] = createHash('sha256').update(await readFile(path)).digest('hex');
}
await writeFile(resolve('dist/checksums.json'), JSON.stringify(hashes, null, 2) + '\n');
console.log(`Packaged Tegin ${version} for Chromium and Firefox; dist/checksums.json contains SHA-256.`);
