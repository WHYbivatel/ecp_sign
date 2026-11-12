import { readFile, writeFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { zipFolder } from './lib/zip.mjs';
const { version } = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const hashes = {};
for (const target of ['chromium', 'firefox']) {
  const name = `tegin-${target}-${version}.zip`;
  const bytes = await zipFolder(resolve('dist', target));
  await writeFile(resolve('dist', name), bytes);
  hashes[name] = createHash('sha256').update(bytes).digest('hex');
}
// Source code for AMO review: the committed tree only, so no keys, .env, dist/ or node_modules/ from the working copy.
const source = `tegin-source-${version}.zip`;
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
await rm(resolve('dist', source), { force: true });
execFileSync('git', ['archive', '--format=zip', `--prefix=tegin-source-${version}/`, '-o', resolve('dist', source), commit]);
hashes[source] = createHash('sha256').update(await readFile(resolve('dist', source))).digest('hex');
if (execFileSync('git', ['status', '--porcelain', '--', 'extension', 'scripts', 'package.json', 'package-lock.json'], { encoding: 'utf8' }).trim())
  console.warn(`Uncommitted changes: ${source} holds commit ${commit.slice(0, 12)}, not the working copy the extension archives were built from.`);
await writeFile(resolve('dist/checksums.json'), JSON.stringify(hashes, null, 2) + '\n');
console.log(`Packaged Tegin ${version} for Chromium and Firefox and the source of ${commit.slice(0, 12)}; dist/checksums.json contains SHA-256.`);
