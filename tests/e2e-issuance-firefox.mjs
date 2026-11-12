import { arch, platform, tmpdir } from 'node:os';
import { mkdtempSync, rmSync, mkdirSync, readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { resolve, join, delimiter } from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import puppeteer from 'puppeteer-core';
import { Browser, detectBrowserPlatform, install, resolveBuildId } from '@puppeteer/browsers';
import { gostHierarchy, issueFromCsr } from './helpers/gost-ca.js';
import { unbase64, parse, der } from '../extension/crypto/encoding.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';
import { openContainer } from '../extension/crypto/signer.js';

// The built Firefox extension (dist/firefox layout) on the NUC issuance path, driven over WebDriver BiDi:
// application key, installation of the issued certificate, the saved .p12 reopened and used to sign.
// Portal pages are anonymized replicas answered by request interception; NUC hosts resolve to nothing.
// FIREFOX_EXECUTABLE selects an installed Firefox; otherwise the current stable release is cached in .browsers/.
async function firefox() {
  if (process.env.FIREFOX_EXECUTABLE) return process.env.FIREFOX_EXECUTABLE;
  const target = detectBrowserPlatform();
  const buildId = await resolveBuildId(Browser.FIREFOX, target, 'stable');
  return (await install({ browser: Browser.FIREFOX, buildId, platform: target, cacheDir: resolve('.browsers') })).executablePath;
}
const executablePath = await firefox();
if (!existsSync(executablePath)) throw new Error(`Firefox not found: ${executablePath}`);
const folder = mkdtempSync(join(tmpdir(), 'tegin-issuance-firefox-'));
const { root, ca } = gostHierarchy();
execFileSync('node', ['scripts/build.mjs'], { stdio: 'pipe', env: { ...process.env, TEGIN_TEST_ISSUANCE_ANCHORS: JSON.stringify([root.base64]), TEGIN_DIST: join(folder, 'build') } });
const extension = join(folder, 'build', 'firefox');
const ADDON_ID = JSON.parse(readFileSync(join(extension, 'manifest.json'), 'utf8')).browser_specific_settings.gecko.id;
const uuid = randomUUID();
const BASE = `moz-extension://${uuid}`;
const PASSWORD = 'Tegin-Test-2026';
const LOOKALIKE = 'nca.pki.gov.kz.example.kz';
const NUC_HOSTS = ['did.pki.gov.kz', 'nca.pki.gov.kz', 'tsp.pki.gov.kz', 'ocsp.pki.gov.kz', 'crl.pki.gov.kz', 'crl1.pki.gov.kz', 'crl.root.gov.kz'];
const CREATE = 'https://did.pki.gov.kz/service/pkiorder/create.xhtml';
const STATUS = 'https://did.pki.gov.kz/service/pkiorder/status.xhtml';
const createPage = readFileSync(resolve('tests/fixtures/nca-issuance/create.html'), 'utf8').replace('{{STORAGES}}', 'PKCS12,AKKaztokenStore,AKKZIDCardStore');
const statusPage = readFileSync(resolve('tests/fixtures/nca-issuance/status.html'), 'utf8');
let issued = [];
const posts = [], escaped = [], errors = [];
const statusHtml = () => statusPage.replace('{{COUNT}}', String(issued.length))
  .replace('{{PEMS}}', issued.map((pem, index) => `<div id="hiddenCertrequests:${index}:pem" hidden>${pem}</div>`).join('\n'));

// Extension windows are privileged browsing contexts: WebDriver BiDi reaches them only with system access (test profile only).
const browser = await puppeteer.launch({ browser: 'firefox', executablePath, headless: true, userDataDir: join(folder, 'profile'),
  env: { ...process.env, MOZ_REMOTE_ALLOW_SYSTEM_ACCESS: '1' },
  extraPrefsFirefox: {
    'extensions.webextensions.uuids': JSON.stringify({ [ADDON_ID]: uuid }),
    'network.dns.localDomains': [...NUC_HOSTS, LOOKALIKE].join(','),
    'browser.download.folderList': 2, 'browser.download.dir': join(folder, 'downloads'), 'browser.download.useDownloadDir': true
  } });

async function portal(url, { adapter = true } = {}) {
  const page = await browser.newPage();
  page.on('pageerror', error => errors.push(error.message));
  await page.setRequestInterception(true);
  page.on('request', async request => {
    const target = new URL(request.url());
    if (![new URL(url).host, 'did.pki.gov.kz'].includes(target.host)) { escaped.push(target.href); return request.abort(); }
    if (request.method() === 'POST') { posts.push({ path: target.pathname, body: await request.fetchPostData() }); return request.respond({ status: 204 }); }
    request.respond({ status: 200, contentType: 'text/html; charset=utf-8', body: target.pathname.includes('/status') ? statusHtml() : createPage });
  });
  await page.goto(url);
  if (adapter) await page.waitForFunction(() => window.WebSocket.__ncaBrowserAdapter === true);
  return page;
}
// Puppeteer keeps the about:blank URL of a window the extension opened, so windows are matched by their own location.
async function extensionWindow(path, known) {
  for (let i = 0; i < 300; i++) {
    for (const candidate of await browser.pages()) {
      if (known.has(candidate)) continue;
      const href = await candidate.evaluate(() => location.href).catch(() => '');
      if (href === `${BASE}/${path}` || href.startsWith(`${BASE}/${path}#`)) { candidate.on('pageerror', error => errors.push(error.message)); return candidate; }
    }
    await new Promise(done => setTimeout(done, 50));
  }
  throw new Error(`no extension window ${path}`);
}
async function startPopup(page, call, path) {
  const known = new Set(await browser.pages());
  await page.evaluate(name => { window.answer = window[name](); }, call);
  return extensionWindow(path, known);
}
const answer = page => page.evaluate(() => window.answer);
const visible = (page, selector) => page.waitForSelector(selector, { visible: true, timeout: 15000 });
const textOf = (page, selector) => page.$eval(selector, node => node.innerText);
async function fill(page, selector, value) { await page.$eval(selector, node => { node.value = ''; }); await page.type(selector, value); }
// The file is taken from where Firefox saved it after the user's click (the page CSP rightly blocks reading the blob).
async function download(page, selector = '#downloads a') {
  const link = await visible(page, selector);
  const name = await page.evaluate(node => node.download, link);
  const path = join(folder, 'downloads', name);
  await link.click();
  // Firefox first creates an empty placeholder next to a .part file.
  const saved = () => existsSync(path) && !existsSync(`${path}.part`) && statSync(path).size > 0;
  for (let i = 0; i < 200 && !saved(); i++) await new Promise(done => setTimeout(done, 50));
  assert.ok(saved(), `${name} was not saved`);
  return { name, bytes: new Uint8Array(readFileSync(path)), path };
}
// WebDriver BiDi cannot navigate to moz-extension:// itself, so storage is read from a window the extension opened.
async function records(extensionPage) {
  const all = await extensionPage.evaluate(() => browser.storage.local.get(null));
  return Object.entries(all).filter(([key]) => key.startsWith('issuance:')).map(([, value]) => value);
}

try {
  assert.equal(await browser.installExtension(extension), ADDON_ID);
  const version = await browser.version();
  console.log(`ENV: firefox on ${platform()} ${arch()}: ${version} (${await browser.userAgent()})`);
  // A look-alike host gets the refusal at once, without a window.
  const lookalike = await portal(`https://${LOOKALIKE}/service/pkiorder/create.xhtml`, { adapter: false });
  const windows = (await browser.pages()).length;
  assert.deepEqual(await lookalike.evaluate(() => createCertRequest()), { status: false, code: 'ORIGIN_NOT_ALLOWED', message: 'Выпуск ключей доступен только на сайте НУЦ РК.' });
  assert.deepEqual(await lookalike.evaluate(() => window.alerts), ['ORIGIN_NOT_ALLOWED']);
  await new Promise(done => setTimeout(done, 500));
  assert.equal((await browser.pages()).length, windows);
  await lookalike.close();

  const page = await portal(CREATE);
  let popup = await startPopup(page, 'createCertRequest', 'signing/issue.html');
  assert.match(await popup.evaluate(() => browser.runtime.getManifest().name), /test issuance build/);
  console.log('PASS: the Firefox build loads as a WebExtension; a look-alike host is refused without a window; on the portal the NCALayer adapter opens its window');
  await visible(popup, '#request-panel:not([hidden])');
  const shown = await textOf(popup, '#subject');
  for (const value of ['ТЕСТОВ ТЕСТ', 'IIN000000000000', 'ТОО «ҚАЗАҚ СИНТЕТИКА»']) assert.ok(shown.includes(value), value);
  assert.equal(await textOf(popup, '#origin'), 'https://did.pki.gov.kz');
  await fill(popup, '#password', PASSWORD);
  await fill(popup, '#password-confirm', PASSWORD);
  await popup.click('#approve');
  const generated = await answer(page);
  assert.equal(generated.status, true);
  assert.match(generated.body.pems[0], /^-----BEGIN CERTIFICATE REQUEST-----\n/);
  for (let i = 0; i < 100 && !posts.length; i++) await new Promise(done => setTimeout(done, 50));
  assert.equal(posts.length, 1);
  assert.equal(new URLSearchParams(posts[0].body).get('certrequestStr').replaceAll('\r\n', '\n'), generated.body.pems[0]);
  await visible(popup, '#result-screen:not([hidden])');
  const backup = await download(popup);
  assert.match(backup.name, /\.tegin-request\.json$/);
  const stored = await records(popup);
  assert.equal(stored.length, 1);
  assert.equal(stored[0].sealed.cipher, 'AES-256-GCM');
  assert.deepEqual(JSON.parse(Buffer.from(backup.bytes).toString()), stored[0]);
  assert.ok(!JSON.stringify(stored).includes(PASSWORD) && !JSON.stringify(stored).includes('synthetic-default'));
  console.log('PASS: the application key is generated in the extension; the page gets only the PKCS#10 PEM; only the encrypted key and its backup are kept');

  // «Ключи заявок» exports the same backup for the pending request; after deletion only that file is left.
  rmSync(backup.path);
  let known = new Set(await browser.pages());
  await popup.evaluate(() => browser.tabs.create({ url: '/keys/index.html' }));
  const keys = await extensionWindow('keys/index.html', known);
  await popup.close(); await page.close();
  await visible(keys, '.key-record[data-status=requested]');
  const exported = await download(keys, '.key-backup');
  assert.equal(exported.name, backup.name);
  assert.deepEqual(JSON.parse(Buffer.from(exported.bytes).toString()), stored[0]);
  await keys.click('.key-remove');
  assert.match(await textOf(keys, '.key-confirm'), /только из резервной копии ключа заявки/);
  await keys.click('.key-yes');
  await keys.waitForSelector('#empty:not([hidden])', { timeout: 15000 });
  assert.deepEqual(await records(keys), []);
  await keys.close();
  console.log('PASS: the application keys page downloads the backup of the pending request (same file as after the request) and deletes the record after confirmation');

  const csr = unbase64(generated.body.pems[0].split('\n').filter(line => line && !line.startsWith('-----')).join(''));
  const leaf = issueFromCsr(ca, csr);
  issued = [leaf.pem.replaceAll('\n', '\r\n'), ca.pem];
  const status = await portal(STATUS);
  popup = await startPopup(status, 'setX509CertToKeystore', 'signing/issue.html');
  await visible(popup, '.issue-certificate');
  assert.match(await textOf(popup, '#certificates'), /Ключ для этого сертификата в этом браузере не найден/);
  // input.setFiles is refused in privileged contexts; the same File reaches the input through DataTransfer.
  await popup.evaluate((bytes, name) => {
    const transfer = new DataTransfer(); transfer.items.add(new File([Uint8Array.from(bytes)], name, { type: 'application/json' }));
    const input = document.querySelector('#backup-file'); input.files = transfer.files; input.dispatchEvent(new Event('change', { bubbles: true }));
  }, Array.from(exported.bytes), exported.name);
  await popup.waitForFunction(() => document.querySelector('#status')?.textContent.includes('Резервная копия добавлена.'), { timeout: 15000 });
  await popup.waitForFunction(() => document.querySelector('#certificates').innerText.includes('Ключ заявки найден в этом браузере'), { timeout: 15000 });
  const card = await textOf(popup, '#certificates');
  assert.match(card, /Цепочка до корня НУЦ РК подтверждена/);
  assert.match(card, /Ключ заявки найден в этом браузере/);
  await fill(popup, '#password', 'Wrong-Pass-2026');
  await popup.click('#approve');
  await popup.waitForFunction(() => document.querySelector('#status[data-error]')?.textContent.includes('Пароль не подошёл'), { timeout: 15000 });
  await fill(popup, '#password', PASSWORD);
  await popup.click('#approve');
  await visible(popup, '#result-screen:not([hidden])');
  assert.equal(await status.evaluate(() => window.statusChanged || false), false, 'the portal is told only after the file is saved');
  const p12 = await download(popup);
  assert.match(p12.name, /^tegin-gost-000000000000-[0-9a-f]{1,8}\.p12$/);
  const p12Path = p12.path;
  assert.deepEqual(await answer(status), { status: true, body: { result: true } });
  assert.equal(await status.evaluate(() => window.statusChanged), true);
  await popup.waitForSelector('#forget:not([hidden])', { timeout: 15000 });
  assert.equal((await records(popup))[0].status, 'installed');
  await popup.close();
  const reopened = await openContainer(new Uint8Array(p12.bytes), PASSWORD);
  try { assert.equal(reopened.info.raw, der(parse(leaf.der))); } finally { reopened.destroy(); }
  console.log('PASS: the key restored from the exported backup installs; wrong password refused, retry installs; chain and key checked; the .p12 is saved before the portal is told and reopens with the issued certificate');

  await status.evaluate(() => new Promise(done => { window.socket = new WebSocket('wss://127.0.0.1:13579'); window.socket.onopen = done; }));
  const content = 'Тестовый документ после выпуска ЭЦП';
  known = new Set(await browser.pages());
  await status.evaluate(message => { window.signed = new Promise(done => { window.socket.onmessage = event => done(JSON.parse(event.data)); }); window.socket.send(JSON.stringify(message)); },
    { module: 'kz.gov.pki.knca.basics', method: 'sign', args: { allowedStorages: ['PKCS12'], format: 'cms', data: Buffer.from(content).toString('base64'), signingParams: { decode: true, encapsulate: true }, signerParams: { extKeyUsageOids: [], chain: [root.pem] }, locale: 'ru' } });
  const signing = await extensionWindow('signing/approve.html', known);
  await signing.waitForSelector('#key-file');
  await signing.evaluate((bytes, name) => {
    const transfer = new DataTransfer(); transfer.items.add(new File([Uint8Array.from(bytes)], name, { type: 'application/x-pkcs12' }));
    const input = document.querySelector('#key-file'); input.files = transfer.files; input.dispatchEvent(new Event('change', { bubbles: true }));
  }, Array.from(p12.bytes), p12.name);
  await fill(signing, '#password', PASSWORD);
  await signing.click('#unlock');
  await visible(signing, '#certificate:not([hidden])');
  assert.match(await textOf(signing, '#trust-state'), /Цепочка сайта подтверждена/);
  await signing.click('#approve');
  const signed = await status.evaluate(() => window.signed);
  assert.equal(signed.status, true);
  const verified = await verifyCms(unbase64(signed.body.result[0]), { anchors: [root.der, ca.der] });
  assert.equal(verified.signers[0].trust.trusted, true);
  assert.equal(Buffer.from(verified.content).toString(), content);
  assert.equal(verified.signers[0].certificate.raw, der(parse(leaf.der)));
  console.log('PASS: the saved .p12 opens in the Firefox signing window and signs a CMS that verifies to the synthetic NUC root');

  if (process.env.NCA_KALKAN_JARS) {
    const classes = join(folder, 'kalkan'); mkdirSync(classes);
    const classpath = `${process.env.NCA_KALKAN_JARS}${delimiter}${classes}`;
    execFileSync(process.env.NCA_JAVAC || 'javac', ['-cp', process.env.NCA_KALKAN_JARS, '-d', classes, resolve('tests/interop/Pkcs12Interop.java'), resolve('tests/interop/Verify.java')], { stdio: 'pipe' });
    const kalkan = (...args) => execFileSync(process.env.NCA_JAVA || 'java', ['-cp', classpath, ...args], { encoding: 'utf8', stdio: 'pipe', env: { ...process.env, TEGIN_TEST_P12_PASSWORD: PASSWORD } });
    assert.match(kalkan('Pkcs12Interop', 'open', p12Path), /KALKAN OPEN OK/);
    const cmsPath = join(folder, 'signed.cms'); writeFileSync(cmsPath, unbase64(signed.body.result[0]));
    assert.match(kalkan('Verify', 'cms', cmsPath), /KALKAN CMS VALID/);
    const changed = unbase64(signed.body.result[0]); changed[Buffer.from(changed).indexOf(Buffer.from(content))] ^= 1;
    writeFileSync(cmsPath, changed);
    assert.throws(() => kalkan('Verify', 'cms', cmsPath));
    console.log('PASS: Kalkan opens the Firefox-saved .p12 and verifies the CMS it signed; a changed document is rejected');
  } else console.log('SKIP: Kalkan check of the Firefox-saved .p12 (set NCA_KALKAN_JARS)');

  assert.deepEqual(escaped, []);
  assert.deepEqual(errors, []);
  console.log('Firefox issuance E2E completed.');
} finally {
  await browser.close();
  rmSync(folder, { recursive: true, force: true });
}
