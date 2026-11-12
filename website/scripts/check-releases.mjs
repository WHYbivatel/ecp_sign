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

const chromium = metadata.releases.find(({ platform }) => platform === 'chromium');
assert.ok(chromium, 'Chromium release is missing from releases.json');
assert.deepEqual(chromium.browsers, ['chrome', 'edge']);
assert.match(chromium.version, /^\d+\.\d+\.\d+$/);
assert.match(chromium.sourceCommit, /^[a-f0-9]{7,40}$/);
for (const build of [chromium, chromium.rollback]) {
  assert.ok(build, 'Chromium rollback build is missing from releases.json');
  assert.equal(build.file, `tegin-chromium-${build.version}-${build.sourceCommit}.zip`, 'Chromium archive name must carry the source commit');
  assert.equal(build.url, `https://tegin.esl.kz/downloads/${build.file}`);
  assert.match(build.sha256, /^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(build.size) && build.size > 0);
}
assert.notEqual(chromium.file, chromium.rollback.file, 'rollback must be a different archive');
assert.match(chromium.publishedAt, /^\d{4}-\d{2}-\d{2}$/);
const chromiumLink = new RegExp(
  `<a\\b(?=[^>]*data-release-platform="chromium")(?=[^>]*href="/downloads/${chromium.file}")(?=[^>]*download="${chromium.file}")[^>]*>[\\s\\S]*?Скачать для Chrome и Edge[\\s\\S]*?<\\/a>`,
);
assert.match(html, chromiumLink, 'Chromium download link differs from releases.json');
assert.ok(html.includes(`Chrome и Edge ${chromium.version} (сборка ${chromium.sourceCommit})`), 'Chromium version label is stale');
assert.ok(html.includes('/downloads/tegin-firefox-0.5.2.zip'), 'Firefox download link was removed');

const chromiumZip = valueFor('--chromium-zip');
if (chromiumZip) {
  const bytes = await readFile(path.resolve(chromiumZip));
  assert.equal(bytes.length, chromium.size, 'Chromium archive byte size differs from releases.json');
  assert.equal(createHash('sha256').update(bytes).digest('hex'), chromium.sha256, 'Chromium archive SHA-256 differs from releases.json');
  const { execFileSync } = await import('node:child_process');
  const manifest = JSON.parse(execFileSync('unzip', ['-p', path.resolve(chromiumZip), 'manifest.json'], { encoding: 'utf8' }));
  assert.equal(manifest.version, chromium.version, 'Chromium manifest version differs from releases.json');
  assert.equal(manifest.manifest_version, 3);
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
console.log(`Release metadata consistent: Chromium ${chromium.version} from ${chromium.sourceCommit} (${chromium.size} bytes, SHA-256 ${chromium.sha256})`);
