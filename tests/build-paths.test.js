import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// Test builds go to TEGIN_DIST; CI checkouts and temp folders on Windows and macOS contain
// drive letters, spaces and non-ASCII names.
const build = dist => execFileSync(process.execPath, ['scripts/build.mjs'], {
  stdio: 'pipe', env: { ...process.env, TEGIN_TEST_ISSUANCE_ANCHORS: JSON.stringify(['AAAA']), TEGIN_DIST: dist } });

test('test builds land exactly in TEGIN_DIST with spaces, Cyrillic, # and % in the path', () => {
  const folder = mkdtempSync(join(tmpdir(), 'tegin build #1 % тест '));
  try {
    const dist = join(folder, 'сборка #2', 'out 100%');
    build(dist);
    for (const target of ['chromium', 'firefox']) {
      const manifest = JSON.parse(readFileSync(join(dist, target, 'manifest.json'), 'utf8'));
      assert.match(manifest.name, /test issuance build/);
      assert.ok(existsSync(join(dist, target, 'crypto', 'worker.js')));
    }
    assert.equal(existsSync(join(folder, 'сборка ')), false, 'the path must not be cut at #');
  } finally { rmSync(folder, { recursive: true, force: true }); }
});

test('a test build is refused inside dist/', () => {
  for (const dist of [resolve('dist'), resolve('dist', 'test build')]) assert.throws(() => build(dist), /TEGIN_DIST must be outside dist/);
});
