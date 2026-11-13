// Builds that tegin.esl.kz actually serves, fetched over HTTPS and checked against pinned SHA-256.
// Chromium entries come from website/releases.json; Firefox 0.5.2 predates it, so its hash is pinned here.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { zipEntries } from '../../scripts/lib/zip.mjs';

const site = JSON.parse(readFileSync(resolve('website/releases.json'), 'utf8'));
const chromium = site.releases.find(release => release.platform === 'chromium');
export const PUBLISHED = {
  chromium: { version: chromium.version, file: chromium.file, url: chromium.url, sha256: chromium.sha256, commit: chromium.sourceCommit },
  chromiumRollback: { ...chromium.rollback, commit: chromium.rollback.sourceCommit },
  firefox: { version: '0.5.2', file: 'tegin-firefox-0.5.2.zip', url: 'https://tegin.esl.kz/downloads/tegin-firefox-0.5.2.zip',
    sha256: '4697dcab34fa3c90efcb66d8bb8b928236488840c20fb05d753150dce47e5f32' }
};

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

// TEGIN_PUBLISHED_DIR may hold local copies of the same files (the hash is checked all the same).
export async function publishedArchive(entry, cache = resolve('.browsers/published')) {
  const local = process.env.TEGIN_PUBLISHED_DIR && join(process.env.TEGIN_PUBLISHED_DIR, entry.file);
  const cached = join(cache, entry.file);
  let bytes = local && existsSync(local) ? readFileSync(local) : existsSync(cached) ? readFileSync(cached) : null;
  if (!bytes) {
    const response = await fetch(entry.url);
    if (!response.ok) throw new Error(`${entry.url}: HTTP ${response.status}`);
    bytes = Buffer.from(await response.arrayBuffer());
  }
  if (sha256(bytes) !== entry.sha256) throw new Error(`${entry.file}: SHA-256 differs from the published value`);
  mkdirSync(cache, { recursive: true }); writeFileSync(cached, bytes);
  return bytes;
}

// Replaces the contents of an unpacked extension folder, as a user does when updating in place.
export function unpack(bytes, folder) {
  rmSync(folder, { recursive: true, force: true });
  const zip = zipEntries(Buffer.from(bytes));
  for (const name of zip.names().filter(entry => !entry.endsWith('/'))) {
    mkdirSync(dirname(join(folder, name)), { recursive: true });
    writeFileSync(join(folder, name), zip.read(name));
  }
}

// The same commit built from source, optionally with synthetic issuance anchors (test builds only).
export function buildCommit(commit, target, { anchors, folder }) {
  const tree = join(folder, `src-${commit}`);
  if (!existsSync(tree)) {
    execFileSync('git', ['worktree', 'add', '--detach', tree, commit], { stdio: 'pipe' });
    execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: tree, stdio: 'pipe', shell: process.platform === 'win32' });
  }
  const env = { ...process.env }; delete env.TEGIN_TEST_ISSUANCE_ANCHORS; delete env.TEGIN_TEST_REVOCATION_ISSUERS; delete env.TEGIN_DIST;
  const out = anchors ? join(folder, `build-${commit}`) : join(tree, 'dist');
  if (anchors) Object.assign(env, { TEGIN_DIST: out, TEGIN_TEST_ISSUANCE_ANCHORS: JSON.stringify(anchors) });
  execFileSync('node', ['scripts/build.mjs'], { cwd: tree, stdio: 'pipe', env });
  return { path: join(out, target), remove: () => execFileSync('git', ['worktree', 'remove', '--force', tree], { stdio: 'pipe' }) };
}
