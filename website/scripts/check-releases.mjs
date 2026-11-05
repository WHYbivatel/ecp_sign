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

assert.ok(html.includes('/downloads/tegin-chromium-0.5.2.zip'), 'Chromium/Edge download link was removed');
assert.ok(html.includes('/downloads/tegin-firefox-0.5.2.zip'), 'Firefox download link was removed');

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
