#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const websiteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const valueFor = (flag) => {
  const index = args.indexOf(flag);
  return index < 0 ? undefined : args[index + 1];
};

const metadata = JSON.parse(await readFile(path.join(websiteRoot, 'releases.json'), 'utf8'));
const html = await readFile(path.join(websiteRoot, 'index.html'), 'utf8');
assert.equal(metadata.schemaVersion, 1, 'unsupported release metadata schema');

const android = metadata.releases.find(({ platform }) => platform === 'android');
assert.ok(android, 'Android release is missing from releases.json');
assert.match(android.version, /^\d+\.\d+\.\d+$/);
assert.equal(android.file, `kazedo-signer-${android.version}.apk`);
assert.equal(android.url, `https://tegin.esl.kz/downloads/${android.file}`);
assert.match(android.publishedAt, /^\d{4}-\d{2}-\d{2}$/);
assert.match(android.sha256, /^[a-f0-9]{64}$/);
assert.match(android.signerCertificateSha256, /^[a-f0-9]{64}$/);
assert.match(android.sourceCommit, /^[a-f0-9]{7,40}$/);
assert.ok(Number.isSafeInteger(android.size) && android.size > 0);

const androidLink = new RegExp(
  `<a\\b(?=[^>]*data-release-platform="android")(?=[^>]*href="/downloads/${android.file}")(?=[^>]*download="${android.file}")[^>]*>[\\s\\S]*?Скачать для Android[\\s\\S]*?<\\/a>`,
);
assert.match(html, androidLink, 'Android download link differs from releases.json');
assert.ok(html.includes(`Android 8+ · Tegin Sign ${android.version}`), 'Android version label is stale');
assert.ok(html.includes('Локально подписывайте файлы и проверяйте CMS-подписи'), 'Android local purpose text is missing');
assert.ok(html.includes('live-интеграция ЭДО недоступна и не проверена'), 'EDO TLS limitation notice is missing');
for (const step of [
  'Скачайте APK на телефон.',
  'Откройте файл и разрешите установку из этого источника, если Android запросит.',
  'Откройте Tegin Sign и выберите «Подписать файл» или «Проверить подпись».',
]) assert.ok(html.includes(step), `installation instruction is missing: ${step}`);

// Extension archives carry the source commit in the name: /downloads/ is served immutable for a year.
// A rollback build published before that rule keeps its plain name and has no sourceCommit.
const extensions = {
  chromium: { browsers: ['chrome', 'edge'], button: 'Скачать для Chrome и Edge', label: 'Chrome и Edge' },
  firefox: { browsers: ['firefox'], button: 'Скачать для Firefox', label: 'Firefox' },
};
const builds = {};
for (const [platform, { browsers, button, label }] of Object.entries(extensions)) {
  const current = metadata.releases.find((release) => release.platform === platform);
  assert.ok(current, `${platform} release is missing from releases.json`);
  assert.deepEqual(current.browsers, browsers);
  assert.match(current.version, /^\d+\.\d+\.\d+$/);
  assert.match(current.sourceCommit, /^[a-f0-9]{7,40}$/);
  assert.match(current.publishedAt, /^\d{4}-\d{2}-\d{2}$/);
  assert.ok(current.rollback, `${platform} rollback build is missing from releases.json`);
  for (const build of [current, current.rollback]) {
    const name = build.sourceCommit ? `tegin-${platform}-${build.version}-${build.sourceCommit}.zip` : `tegin-${platform}-${build.version}.zip`;
    assert.equal(build.file, name, `${platform} archive name must carry the source commit`);
    assert.equal(build.url, `https://tegin.esl.kz/downloads/${build.file}`);
    assert.match(build.sha256, /^[a-f0-9]{64}$/);
    assert.ok(Number.isSafeInteger(build.size) && build.size > 0);
  }
  assert.ok(current.file.endsWith(`-${current.sourceCommit}.zip`), `${platform} current archive must carry the source commit`);
  assert.notEqual(current.file, current.rollback.file, 'rollback must be a different archive');
  const link = new RegExp(
    `<a\\b(?=[^>]*data-release-platform="${platform}")(?=[^>]*href="/downloads/${current.file}")(?=[^>]*download="${current.file}")[^>]*>[\\s\\S]*?${button}[\\s\\S]*?<\\/a>`,
  );
  assert.match(html, link, `${platform} download link differs from releases.json`);
  assert.ok(html.includes(`${label} ${current.version} (сборка ${current.sourceCommit})`), `${platform} version label is stale`);
  builds[platform] = current;
}
const { chromium, firefox } = builds;
assert.equal(firefox.addonId, 'ncabrowser@local.invalid', 'the site build keeps the add-on ID its users have: storage is tied to it');

const { execFileSync } = await import('node:child_process');
for (const platform of Object.keys(extensions)) {
  const archive = valueFor(`--${platform}-zip`);
  if (!archive) continue;
  const build = builds[platform];
  const bytes = await readFile(path.resolve(archive));
  assert.equal(bytes.length, build.size, `${platform} archive byte size differs from releases.json`);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), build.sha256, `${platform} archive SHA-256 differs from releases.json`);
  const manifest = JSON.parse(execFileSync('unzip', ['-p', path.resolve(archive), 'manifest.json'], { encoding: 'utf8' }));
  assert.equal(manifest.version, build.version, `${platform} manifest version differs from releases.json`);
  assert.equal(manifest.manifest_version, 3);
  if (platform === 'firefox') assert.equal(manifest.browser_specific_settings.gecko.id, build.addonId);
}

// dist/release.json from scripts/package.mjs: the site offers exactly the archives built from the stated commit.
const releasePath = valueFor('--release');
if (releasePath) {
  const release = JSON.parse(await readFile(path.resolve(releasePath), 'utf8'));
  assert.equal(release.clean, true, 'release archives were built from a tree with uncommitted changes');
  for (const build of Object.values(builds)) {
    assert.equal(release.version, build.version, `${build.platform} version differs from the packaged release`);
    assert.ok(release.commit.startsWith(build.sourceCommit), `${build.platform} sourceCommit ${build.sourceCommit} is not the packaged commit ${release.commit}`);
    const artifact = release.artifacts[`tegin-${build.platform}-${build.version}.zip`];
    assert.ok(artifact, `${build.platform} archive is missing from the packaged release`);
    assert.deepEqual({ size: build.size, sha256: build.sha256 }, artifact, `${build.platform} archive differs from the packaged release`);
  }
}

const apkPath = valueFor('--apk');
if (apkPath) {
  const absoluteApkPath = path.resolve(apkPath);
  const apkStat = await stat(absoluteApkPath);
  assert.equal(apkStat.size, android.size, 'APK byte size differs from releases.json');
  const digest = createHash('sha256').update(await readFile(absoluteApkPath)).digest('hex');
  assert.equal(digest, android.sha256, 'APK SHA-256 differs from releases.json');
}

const docRoot = valueFor('--doc-root');
if (docRoot) {
  const downloadSource = await readFile(
    path.join(path.resolve(docRoot), 'frontend/src/shared/lib/androidSignerDownload.ts'),
    'utf8',
  );
  assert.ok(downloadSource.includes(`ANDROID_SIGNER_VERSION = '${android.version}'`), 'private doc version constant is stale');
  assert.ok(
    downloadSource.includes('https://tegin.esl.kz/downloads/${ANDROID_SIGNER_APK_FILENAME}'),
    'private doc APK URL differs from releases.json',
  );
}

console.log(`Release metadata consistent: Android ${android.version} (${android.size} bytes, SHA-256 ${android.sha256})`);
for (const build of [chromium, firefox]) console.log(`Release metadata consistent: ${build.platform} ${build.version} from ${build.sourceCommit} (${build.size} bytes, SHA-256 ${build.sha256}); rollback ${build.rollback.file}`);
