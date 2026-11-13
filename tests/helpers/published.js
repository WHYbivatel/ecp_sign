// Builds that tegin.esl.kz actually serves, fetched over HTTPS and checked against pinned SHA-256.
// website/releases.json may already describe the next release; each pinned build must be listed there, as the
// current or the rollback entry. Update the pins when a release goes live.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { zipEntries } from '../../scripts/lib/zip.mjs';

export const PUBLISHED = {
  chromium: { version: '0.5.3', file: 'tegin-chromium-0.5.3-dd40b5e.zip', url: 'https://tegin.esl.kz/downloads/tegin-chromium-0.5.3-dd40b5e.zip',
    sha256: 'd2872b7e06df7fe73bcbe060dd4bb85cdc0a318bbec0495300decb53a24c7651', commit: 'dd40b5e' },
  firefox: { version: '0.5.2', file: 'tegin-firefox-0.5.2.zip', url: 'https://tegin.esl.kz/downloads/tegin-firefox-0.5.2.zip',
    sha256: '4697dcab34fa3c90efcb66d8bb8b928236488840c20fb05d753150dce47e5f32' }
};
const site = JSON.parse(readFileSync(resolve('website/releases.json'), 'utf8'));
for (const [platform, pinned] of Object.entries(PUBLISHED)) {
  const entry = site.releases.find(release => release.platform === platform);
  if (![entry, entry?.rollback].some(build => build?.file === pinned.file && build.sha256 === pinned.sha256)) throw new Error(`${pinned.file} is not in website/releases.json`);
}

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
    // Windows runners check out with CRLF; the published archive was built from LF files.
    execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'core.eol=lf', 'worktree', 'add', '--detach', tree, commit], { stdio: 'pipe' });
    execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: tree, stdio: 'pipe', shell: process.platform === 'win32' });
  }
  const env = { ...process.env }; delete env.TEGIN_TEST_ISSUANCE_ANCHORS; delete env.TEGIN_TEST_REVOCATION_ISSUERS; delete env.TEGIN_DIST;
  const out = anchors ? join(folder, `build-${commit}`) : join(tree, 'dist');
  if (anchors) Object.assign(env, { TEGIN_DIST: out, TEGIN_TEST_ISSUANCE_ANCHORS: JSON.stringify(anchors) });
  execFileSync('node', ['scripts/build.mjs'], { cwd: tree, stdio: 'pipe', env });
  return { path: join(out, target), remove: () => execFileSync('git', ['worktree', 'remove', '--force', tree], { stdio: 'pipe' }) };
}
