import { arch, platform, tmpdir } from 'node:os';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { launchExtension, extensionWorker, browserName, browserVersion } from './helpers/browser.js';
import { gostHierarchy, issueFromCsr } from './helpers/gost-ca.js';
import { PUBLISHED, publishedArchive, unpack, buildCommit } from './helpers/published.js';
import { filesIn } from '../scripts/lib/zip.mjs';
import { unbase64, parse, der } from '../extension/crypto/encoding.js';
import { openContainer } from '../extension/crypto/signer.js';

// Update of the build tegin.esl.kz serves (Chromium 0.5.3, dd40b5e) to this release candidate in the same folder
// and profile, rollback to dd40b5e over data the candidate wrote, and the move to a build with another extension ID
// (store build) through backup files, including a backup made by dd40b5e. Synthetic CA and keys only.
const folder = mkdtempSync(join(tmpdir(), 'tegin-update-'));
const { root, ca } = gostHierarchy();
const { version } = JSON.parse(readFileSync(resolve('package.json'), 'utf8'));
const PASSWORD = 'Tegin-Test-2026';
const HOSTS = ['did.pki.gov.kz', 'nca.pki.gov.kz', 'goszakup.gov.kz', 'shop.example.kz', 'tsp.pki.gov.kz', 'ocsp.pki.gov.kz', 'crl.pki.gov.kz', 'crl1.pki.gov.kz', 'crl.root.gov.kz'];
const CREATE = 'https://did.pki.gov.kz/service/pkiorder/create.xhtml';
const STATUS = 'https://did.pki.gov.kz/service/pkiorder/status.xhtml';
const createPage = readFileSync(resolve('tests/fixtures/nca-issuance/create.html'), 'utf8').replace('{{STORAGES}}', 'PKCS12,AKKaztokenStore,AKKZIDCardStore');
const statusPage = readFileSync(resolve('tests/fixtures/nca-issuance/status.html'), 'utf8');
let issued = [];
const statusHtml = () => statusPage.replace('{{COUNT}}', String(issued.length))
  .replace('{{PEMS}}', issued.map((pem, index) => `<div id="hiddenCertrequests:${index}:pem" hidden>${pem}</div>`).join('\n'));
const errors = [];
mkdirSync(resolve('artifacts'), { recursive: true });

// Published and candidate builds. The candidate and the rollback build carry the synthetic NUC root so that a
// certificate can be installed; the published archive is used as served (its code is checked against dd40b5e below).
const published = await publishedArchive(PUBLISHED.chromium);
execFileSync('node', ['scripts/build.mjs'], { stdio: 'pipe', env: { ...process.env, TEGIN_TEST_ISSUANCE_ANCHORS: JSON.stringify([root.base64]), TEGIN_DIST: join(folder, 'candidate') } });
const candidate = join(folder, 'candidate', 'chromium');
const plainOld = buildCommit(PUBLISHED.chromium.commit, 'chromium', { folder });
const testOld = buildCommit(PUBLISHED.chromium.commit, 'chromium', { folder, anchors: [root.base64] });

let context, sw, extensionId;
async function launch(profile, extension) {
  context = await launchExtension(join(folder, profile), extension, { viewport: { width: 900, height: 900 },
    args: [`--host-resolver-rules=${HOSTS.map(host => `MAP ${host} ~NOTFOUND`).join(', ')}`] });
  context.on('page', page => page.on('pageerror', error => errors.push(`${page.url()}: ${error.message}`)));
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.protocol === 'chrome-extension:') return route.continue();
    if (url.host === 'did.pki.gov.kz') {
      if (route.request().method() === 'POST') return route.fulfill({ status: 204 });
      return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: url.pathname.includes('/status') ? statusHtml() : createPage });
    }
    if (['goszakup.gov.kz', 'shop.example.kz'].includes(url.host)) return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: '<!doctype html><title>portal</title>' });
    return route.abort();
  });
  sw = await extensionWorker(context);
  extensionId = new URL(sw.url()).host;
  return extensionId;
}
const storage = () => sw.evaluate(() => chrome.storage.local.get(null));
const records = async () => Object.entries(await storage()).filter(([key]) => key.startsWith('issuance:')).map(([key, value]) => ({ slot: key.slice(9), ...value }));
async function popupFor(page, call) {
  const opened = context.waitForEvent('page');
  await page.evaluate(name => { window.answer = window[name](); }, call);
  const popup = await opened;
  await popup.waitForURL(`chrome-extension://${extensionId}/signing/issue.html#*`);
  return popup;
}
// A pending request on the portal replica; returns the backup file and the CSR.
async function request(label) {
  const page = await context.newPage();
  await page.goto(CREATE);
  const popup = await popupFor(page, 'createCertRequest');
  await popup.locator('#password').fill(PASSWORD);
  await popup.locator('#password-confirm').fill(PASSWORD);
  await popup.locator('#approve').click();
  const generated = await page.evaluate(() => window.answer);
  assert.equal(generated.status, true);
  await popup.locator('#result-screen:not([hidden])').waitFor();
  const saved = popup.waitForEvent('download');
  await popup.locator('#downloads a').click();
  const backup = join(folder, `${label}.tegin-request.json`); await (await saved).saveAs(backup);
  await popup.close(); await page.close();
  return { backup, csr: unbase64(generated.body.pems[0].split('\n').filter(line => line && !line.startsWith('-----')).join('')) };
}
// Installs the issued certificate; restores a backup first when the key is not in this browser.
async function install(csr, { restore } = {}) {
  const leaf = issueFromCsr(ca, csr);
  issued = [leaf.pem.replaceAll('\n', '\r\n'), ca.pem];
  const page = await context.newPage();
  await page.goto(STATUS);
  const popup = await popupFor(page, 'setX509CertToKeystore');
  await popup.locator('.issue-certificate').waitFor();
  if (restore) {
    assert.match(await popup.locator('#certificates').innerText(), /не найден/);
    await popup.locator('#backup-file').setInputFiles(restore);
    await popup.locator('#status').filter({ hasText: 'Резервная копия добавлена.' }).waitFor();
  }
  await popup.locator('#certificates').filter({ hasText: 'Ключ заявки найден в этом браузере' }).waitFor({ timeout: 15000 });
  await popup.locator('#password').fill(PASSWORD);
  await popup.locator('#approve').click();
  await popup.locator('#result-screen:not([hidden])').waitFor();
  const saved = popup.waitForEvent('download');
  await popup.locator('#downloads a').click();
  const p12 = join(folder, `${(await saved).suggestedFilename()}`); await (await saved).saveAs(p12);
  assert.deepEqual(await page.evaluate(() => window.answer), { status: true, body: { result: true } });
  await popup.close(); await page.close();
  const opened = await openContainer(new Uint8Array(readFileSync(p12)), PASSWORD);
  try { assert.equal(opened.info.raw, der(parse(leaf.der))); } finally { opened.destroy(); }
}
// NURSign from a .kz page: the module settings decide before any window opens.
async function nursign(origin) {
  const page = await context.newPage();
  await page.goto(`${origin}/`);
  await page.waitForFunction(() => window.WebSocket.__ncaBrowserAdapter === true);
  const reply = await page.evaluate(() => new Promise(done => {
    const socket = new WebSocket('wss://127.0.0.1:13579');
    socket.onopen = () => { socket.onmessage = event => done(JSON.parse(event.data)); socket.send(JSON.stringify({ module: 'NURSign', type: 'text', data: 'test' })); };
  }));
  await page.close();
  return reply.errorMessage || '';
}
const connected = () => sw.evaluate(async () => (await chrome.scripting.getRegisteredContentScripts()).map(script => script.id).sort());

try {
  // The published archive is dd40b5e: the same commit built from source gives the same files.
  const servedFolder = join(folder, 'served'); unpack(published, servedFolder);
  const served = await filesIn(servedFolder), built = await filesIn(plainOld.path);
  assert.deepEqual(served, built);
  for (const file of served) assert.ok(readFileSync(join(servedFolder, file)).equals(readFileSync(join(plainOld.path, file))), `${file} differs from ${PUBLISHED.chromium.commit}`);
  console.log(`PASS: ${PUBLISHED.chromium.file} (SHA-256 as in releases.json) is byte-identical to ${PUBLISHED.chromium.commit} built from source: ${served.length} files`);

  // 1. The published build in the user's folder: settings, a connected site, a pending NUC request.
  const installed = join(folder, 'Tegin');
  unpack(published, installed);
  const firstId = await launch('profile', installed);
  console.log(`ENV: ${browserName} on ${platform()} ${arch()}: ${await browserVersion(context)}`);
  assert.equal(await sw.evaluate(() => chrome.runtime.getManifest().version), PUBLISHED.chromium.version);
  const manager = await context.newPage();
  await manager.goto(`chrome-extension://${extensionId}/modules/index.html`);
  const card = manager.locator('[data-module="goszakup"]');
  await card.waitFor();
  await card.locator(':scope > details > summary').click();
  await card.locator('textarea').fill('https://goszakup.gov.kz');
  await card.locator('select').selectOption('deny');
  await card.getByRole('button', { name: 'Сохранить настройки' }).click();
  await manager.waitForFunction(async () => (await chrome.storage.local.get('moduleSettings')).moduleSettings?.goszakup?.timestamp === 'deny');
  await manager.close();
  // «Подключить сайт» registers two scripts per site the browser granted. The permission prompt cannot be answered
  // in Chromium automation, so a registration for a host the manifest covers shows what happens to registrations.
  await sw.evaluate(() => chrome.scripting.registerContentScripts([
    { id: 'main-updatecheck', matches: ['http://localhost/*'], js: ['content/inject.js'], world: 'MAIN', runAt: 'document_start', allFrames: true },
    { id: 'bridge-updatecheck', matches: ['http://localhost/*'], js: ['content/bridge.js'], runAt: 'document_start', allFrames: true }]));
  assert.deepEqual(await connected(), ['bridge-updatecheck', 'main-updatecheck']);
  const oldRequest = await request('dd40b5e');
  const before = await storage();
  assert.equal((await records()).length, 1);
  assert.match(await nursign('https://shop.example.kz'), /не разрешён в настройках модуля/);
  assert.match(await nursign('https://goszakup.gov.kz'), /обязательную метку/);
  await context.close();
  console.log(`PASS: published ${PUBLISHED.chromium.version} (${PUBLISHED.chromium.commit}): module settings with an allowed site, a connected-site registration and an encrypted pending request saved; backup downloaded`);

  // 2. Update in place: the candidate replaces the files in the same folder; the same profile is opened.
  rmSync(installed, { recursive: true, force: true }); cpSync(candidate, installed, { recursive: true });
  assert.equal(await launch('profile', installed), firstId, 'same folder, same extension ID');
  assert.equal(await sw.evaluate(() => chrome.runtime.getManifest().version), version);
  const after = await storage();
  assert.deepEqual(after.moduleSettings, before.moduleSettings);
  const oldKey = Object.keys(before).find(key => key.startsWith('issuance:'));
  const { holder, ...withoutHolder } = before[oldKey];
  assert.equal(typeof holder, 'string', 'dd40b5e records still carry the CN');
  // Chromium drops registered scripts when it loads the folder again; Tegin rebuilds them from the granted origins
  // (tests/connected-sites.test.js, Firefox update E2E), which this ungranted registration does not have.
  assert.deepEqual(await connected(), []);
  assert.match(await nursign('https://shop.example.kz'), /не разрешён в настройках модуля/);
  assert.match(await nursign('https://goszakup.gov.kz'), /обязательную метку/);
  const keys = await context.newPage();
  await keys.goto(`chrome-extension://${extensionId}/keys/index.html`);
  await keys.locator('.key-record[data-status=requested]').waitFor();
  assert.equal(await keys.locator('.key-record').count(), 1);
  assert.equal(await keys.locator('.key-backup').count(), 1);
  // Opening the list drops the CN that dd40b5e stored; the key itself is untouched.
  assert.deepEqual((await storage())[oldKey], withoutHolder);
  await keys.screenshot({ path: resolve('artifacts/update-keys.png'), fullPage: true });
  await keys.close();
  await install(oldRequest.csr);
  const newRequest = await request('candidate');
  assert.deepEqual((await records()).map(record => record.status).sort(), ['installed', 'requested']);
  await context.close();
  console.log(`PASS: update ${PUBLISHED.chromium.version} → ${version} in the same folder and profile: same extension ID; module settings and the allowed site still apply; Chromium drops registered site scripts on reload; the dd40b5e request is listed with a backup button, loses only the stored CN and installs (.p12 reopens)`);

  // 3. Rollback: dd40b5e code back in the same folder over the data the candidate wrote.
  rmSync(installed, { recursive: true, force: true }); cpSync(testOld.path, installed, { recursive: true });
  assert.equal(await launch('profile', installed), firstId);
  assert.equal(await sw.evaluate(() => chrome.runtime.getManifest().version), PUBLISHED.chromium.version);
  assert.deepEqual((await storage()).moduleSettings, before.moduleSettings);
  assert.match(await nursign('https://shop.example.kz'), /не разрешён в настройках модуля/);
  await install(newRequest.csr);
  assert.deepEqual((await records()).map(record => record.status), ['installed', 'installed']);
  await context.close();
  console.log(`PASS: rollback to ${PUBLISHED.chromium.commit} over ${version} data: settings kept, the request made by ${version} installs in the old code`);

  // 4. Store build: another folder gives another extension ID and empty storage; keys move only as backup files.
  const store = join(folder, 'Tegin store');
  cpSync(candidate, store, { recursive: true });
  const storeId = await launch('store-profile', store);
  assert.notEqual(storeId, firstId);
  assert.deepEqual(await storage(), {});
  assert.deepEqual(await connected(), []);
  await install(oldRequest.csr, { restore: oldRequest.backup });
  await install(newRequest.csr, { restore: newRequest.backup });
  assert.equal((await records()).length, 2);
  await context.close();
  console.log(`PASS: move to a build with another ID: storage starts empty (settings and connected sites are set again); the backup made by ${PUBLISHED.chromium.commit} and the one made by ${version} restore and install`);

  assert.deepEqual(errors, []);
  console.log('Update E2E completed.');
} finally {
  await context?.close().catch(() => {});
  for (const build of [plainOld, testOld]) try { build.remove(); } catch {}
  rmSync(folder, { recursive: true, force: true });
}
