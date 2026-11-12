import { arch, platform, tmpdir } from 'node:os';
import { mkdtempSync, rmSync, mkdirSync, readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { resolve, join, delimiter } from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import puppeteer from 'puppeteer-core';
import { Browser, detectBrowserPlatform, install, resolveBuildId } from '@puppeteer/browsers';
import { rsaFixture, gostFixture, PASSWORD } from './helpers/fixtures.js';
import { openContainer } from '../extension/crypto/signer.js';
import { der } from '../extension/crypto/encoding.js';

// "Сменить пароль ключа" in the built Firefox extension, driven over WebDriver BiDi. A local site sends the
// NCA password form calls (changePassword, then browseKeyStore); the popup log offers the local tool; the tool
// changes the password of synthetic RSA and GOST-512 keys: cancelled file choice, cancel by button and Esc,
// wrong old password, then a copy that Firefox saves and that opens with the new password in the signing tool.
// FIREFOX_EXECUTABLE selects an installed Firefox; otherwise the current stable release is cached in .browsers/.
async function firefox() {
  if (process.env.FIREFOX_EXECUTABLE) return process.env.FIREFOX_EXECUTABLE;
  const target = detectBrowserPlatform();
  const buildId = await resolveBuildId(Browser.FIREFOX, target, 'stable');
  return (await install({ browser: Browser.FIREFOX, buildId, platform: target, cacheDir: resolve('.browsers') })).executablePath;
}
const executablePath = await firefox();
if (!existsSync(executablePath)) throw new Error(`Firefox not found: ${executablePath}`);
const folder = mkdtempSync(join(tmpdir(), 'tegin-password-firefox-'));
// The regular build without test trust settings: the same Firefox package that is shipped.
execFileSync('node', ['scripts/build.mjs'], { stdio: 'pipe' });
const extension = resolve('dist/firefox');
const ADDON_ID = JSON.parse(readFileSync(join(extension, 'manifest.json'), 'utf8')).browser_specific_settings.gecko.id;
const uuid = randomUUID();
const BASE = `moz-extension://${uuid}`;
const NEW_PASSWORD = 'NewPass2026';
// With NCA_KALKAN_JARS the GOST key is created by Kalkan (it does not read the synthetic GOST fixture's key encoding),
// and Kalkan compares each Firefox-saved copy with its original.
const kalkanJars = process.env.NCA_KALKAN_JARS;
const kalkanClasses = join(folder, 'kalkan');
const kalkan = (args, env = {}) => execFileSync(process.env.NCA_JAVA || 'java', ['-cp', `${kalkanJars}${delimiter}${kalkanClasses}`, 'Pkcs12Interop', ...args],
  { encoding: 'utf8', stdio: 'pipe', env: { ...process.env, TEGIN_TEST_P12_PASSWORD: PASSWORD, ...env } });
function gostKey() {
  if (!kalkanJars) return gostFixture('512').container;
  mkdirSync(kalkanClasses);
  execFileSync(process.env.NCA_JAVAC || 'javac', ['-cp', kalkanJars, '-d', kalkanClasses, resolve('tests/interop/Pkcs12Interop.java')], { stdio: 'pipe' });
  const path = join(folder, 'kalkan-gost512.p12');
  kalkan(['create', 'GOST512', 'PKCS12', path]);
  return new Uint8Array(readFileSync(path));
}
const keys = [['RSA', 'rsa-key.p12', rsaFixture().container], ['GOST 512', 'gost-key.p12', gostKey()]];

const site = createServer((req, res) => { res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end('<!doctype html><title>Tegin password fixture</title><h1>Synthetic NCA password form</h1>'); });
await new Promise(done => site.listen(0, '127.0.0.1', done));
// Extension windows are privileged browsing contexts: WebDriver BiDi reaches them only with system access (test profile only).
const browser = await puppeteer.launch({ browser: 'firefox', executablePath, headless: true, userDataDir: join(folder, 'profile'),
  env: { ...process.env, MOZ_REMOTE_ALLOW_SYSTEM_ACCESS: '1' },
  extraPrefsFirefox: {
    'extensions.webextensions.uuids': JSON.stringify({ [ADDON_ID]: uuid }),
    'browser.download.folderList': 2, 'browser.download.dir': join(folder, 'downloads'), 'browser.download.useDownloadDir': true
  } });
const errors = [];
const pause = ms => new Promise(done => setTimeout(done, ms));
const hrefOf = page => page.evaluate(() => location.href).catch(() => '');
async function extensionPage(prefix, known) {
  for (let i = 0; i < 300; i++) {
    for (const candidate of await browser.pages()) {
      if (known.has(candidate)) continue;
      if ((await hrefOf(candidate)).startsWith(`${BASE}/${prefix}`)) { candidate.on('pageerror', error => errors.push(error.message)); return candidate; }
    }
    await pause(50);
  }
  throw new Error(`no extension page ${prefix}`);
}
// WebDriver BiDi cannot open moz-extension:// itself; extension pages navigate themselves.
async function go(page, path) {
  await page.evaluate(target => location.assign(browser.runtime.getURL(target)), path);
  await arrived(page, path);
}
async function arrived(page, path) {
  for (let i = 0; i < 200; i++) {
    if ((await hrefOf(page)) === `${BASE}/${path}` && await page.evaluate(() => document.readyState === 'complete').catch(() => false)) return;
    await pause(50);
  }
  throw new Error(`did not reach ${path}`);
}
const visible = (page, selector) => page.waitForSelector(selector, { visible: true, timeout: 30000 });
const textOf = (page, selector) => page.$eval(selector, node => node.textContent);
const valueOf = (page, selector) => page.$eval(selector, node => node.value);
async function fill(page, selector, value) { await page.$eval(selector, node => { node.value = ''; }); await page.type(selector, value); }
// input.setFiles is refused in privileged contexts; the same File reaches the input through DataTransfer.
// No bytes means a cancelled file chooser: the input fires "change" with an empty list.
async function choose(page, selector, bytes, name, type) {
  await page.evaluate((selector, bytes, name, type) => {
    const transfer = new DataTransfer();
    if (bytes) transfer.items.add(new File([Uint8Array.from(bytes)], name, { type }));
    const input = document.querySelector(selector); input.files = transfer.files; input.dispatchEvent(new Event('change', { bubbles: true }));
  }, selector, bytes ? Array.from(bytes) : null, name, type);
}
async function download(page) {
  const name = await page.$eval('#download', node => node.download);
  const path = join(folder, 'downloads', name);
  await page.click('#download');
  // Firefox first creates an empty placeholder next to a .part file.
  const saved = () => existsSync(path) && !existsSync(`${path}.part`) && statSync(path).size > 0;
  for (let i = 0; i < 200 && !saved(); i++) await pause(50);
  assert.ok(saved(), `${name} was not saved`);
  return { name, path, bytes: new Uint8Array(readFileSync(path)) };
}

try {
  assert.equal(await browser.installExtension(extension), ADDON_ID);
  console.log(`ENV: firefox on ${platform()} ${arch()}: ${await browser.version()}`);
  const page = await browser.newPage();
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(`http://127.0.0.1:${site.address().port}/`);
  await page.waitForFunction(() => window.WebSocket.__ncaBrowserAdapter === true);
  await page.evaluate(() => new Promise((done, fail) => { window.socket = new WebSocket('wss://127.0.0.1:13579'); window.socket.onopen = done; window.socket.onerror = fail; }));
  const call = message => page.evaluate(message => new Promise(done => { window.socket.onmessage = event => done(JSON.parse(event.data)); window.socket.send(JSON.stringify(message)); }), message);

  // An extension window opened by a site call gives the test an extension context; it then opens a helper tab and is cancelled.
  let known = new Set(await browser.pages());
  const pending = call({ module: 'kz.gov.pki.knca.basics', method: 'sign', args: { allowedStorages: ['PKCS12'], format: 'xml', data: '<login><nonce>password</nonce></login>', signingParams: {}, signerParams: { extKeyUsageOids: [] } } });
  const approval = await extensionPage('signing/approve.html#', known);
  const siteTab = await approval.evaluate(url => browser.tabs.query({}).then(tabs => tabs.find(tab => tab.url === url)?.id), page.url());
  assert.ok(Number.isInteger(siteTab));
  known = new Set(await browser.pages());
  await approval.evaluate(() => browser.tabs.create({ url: browser.runtime.getURL('password/index.html'), active: true }));
  const tool = await extensionPage('password/index.html', known);
  await approval.click('#cancel');
  assert.deepEqual(await pending, { status: true, body: {} }, 'basics: a cancelled window answers with an empty body');

  // The NCA form: changePassword, then browseKeyStore (what the form calls first) — both refused, no window.
  known = new Set(await browser.pages());
  for (const request of [{ method: 'changePassword', args: ['PKCS12', '/synthetic/key.p12', 'Old12345', 'New12345'] }, { method: 'browseKeyStore', args: ['PKCS12', 'P12', ''] }]) {
    const answer = await call(request);
    assert.equal(answer.code, '400', request.method);
    assert.match(answer.message, /Сменить пароль ключа/);
  }
  await pause(500);
  for (const candidate of await browser.pages()) if (!known.has(candidate)) assert.doesNotMatch(await hrefOf(candidate), /signing\/approve\.html#/, 'no signing window for the form');
  await go(tool, `index.html?workspace=1&site=${siteTab}`);
  await visible(tool, '#site-log');
  assert.equal(await textOf(tool, '#log-method'), 'browseKeyStore');
  assert.match(await textOf(tool, '#log-reason'), /Сменить пароль ключа/);
  await visible(tool, '#password-hint');
  await tool.click('#password-hint');
  await arrived(tool, 'password/index.html');
  console.log('PASS: Firefox: the NCA form calls (changePassword, browseKeyStore) are refused with a pointer to the tool, no window opens; the popup log names browseKeyStore and its button opens the tool');

  const downloads = [];
  for (const [label, name, key] of keys) {
    const original = Buffer.from(key);
    await visible(tool, '#change-form');
    await choose(tool, '#key-file', original, name, 'application/x-pkcs12');
    assert.equal(await textOf(tool, '#key-name'), name);
    await choose(tool, '#key-file', null);
    assert.equal(await textOf(tool, '#key-name'), name, `${label}: a cancelled file chooser keeps the selection`);
    for (const how of ['button', 'Escape']) {
      await fill(tool, '#old-password', PASSWORD);
      for (const field of ['#new-password', '#repeat-password']) await fill(tool, field, NEW_PASSWORD);
      await tool.click('#submit');
      if (how === 'button') { await visible(tool, '#cancel'); await tool.click('#cancel'); } else await tool.keyboard.press('Escape');
      await tool.waitForFunction(() => document.querySelector('#status').textContent.includes('Смена пароля отменена'), { timeout: 15000 });
      assert.equal(await tool.$eval('#result', node => node.hidden), true, `${label}: no result after cancel (${how})`);
      assert.equal(await tool.$eval('#cancel', node => node.hidden), true);
      for (const field of ['#old-password', '#new-password', '#repeat-password']) assert.equal(await valueOf(tool, field), '', `${label}: ${field} wiped (${how})`);
    }
    assert.equal(downloads.length, label === 'RSA' ? 0 : 1, 'cancel saves nothing');
    await fill(tool, '#old-password', PASSWORD + 'x');
    for (const field of ['#new-password', '#repeat-password']) await fill(tool, field, NEW_PASSWORD);
    await tool.click('#submit');
    await tool.waitForFunction(() => document.querySelector('#status[data-error]')?.textContent.includes('Текущий пароль не подошёл'), { timeout: 60000 });
    assert.equal(await valueOf(tool, '#old-password'), '', 'the wrong old password is wiped');
    await fill(tool, '#old-password', PASSWORD);
    await tool.click('#submit');
    const started = Date.now();
    await tool.waitForFunction(() => !document.querySelector('#result').hidden || document.querySelector('#status[data-error]'), { timeout: 180000 });
    assert.equal(await tool.$eval('#result', node => node.hidden), false, `${label}: ${await textOf(tool, '#status')}`);
    console.log(`INFO: ${label} change took ${((Date.now() - started) / 1000).toFixed(1)} s in Firefox`);
    for (const field of ['#old-password', '#new-password', '#repeat-password']) assert.equal(await valueOf(tool, field), '');
    assert.match(await textOf(tool, '#protection-after'), /HMAC-SHA-256.*PBES2 AES-256-CBC/);
    const saved = await download(tool);
    downloads.push(saved);
    assert.equal(saved.name, `${name.replace(/\.p12$/, '')} (новый пароль).p12`);
    const before = await openContainer(new Uint8Array(original), PASSWORD, { exportKey: true }), after = await openContainer(saved.bytes, NEW_PASSWORD, { exportKey: true });
    try {
      assert.equal(der(after.privateKeyInfo()), der(before.privateKeyInfo()));
      assert.deepEqual(after.certificates.map(der), before.certificates.map(der));
    } finally { before.destroy(); after.destroy(); }
    await assert.rejects(openContainer(saved.bytes, PASSWORD), { code: 'PASSWORD_OR_DAMAGED' });
    assert.deepEqual(original, Buffer.from(key), 'the selected file is untouched');
    // The user's next step in the same Firefox: the saved copy opens with the new password in "Подписать файл".
    await go(tool, 'signing/approve.html');
    await tool.waitForSelector('#document');
    await choose(tool, '#document', Buffer.from('Синтетический документ Tegin'), 'test.txt', 'text/plain');
    await choose(tool, '#key-file', saved.bytes, saved.name, 'application/x-pkcs12');
    await fill(tool, '#password', PASSWORD);
    await tool.click('#unlock');
    await tool.waitForSelector('#status[data-error]', { timeout: 60000 });
    assert.equal(await tool.$eval('#certificate', node => node.hidden), true, 'the old password does not open the copy');
    await fill(tool, '#password', NEW_PASSWORD);
    await tool.click('#unlock');
    await tool.waitForSelector('#certificate:not([hidden])', { timeout: 60000 });
    await go(tool, 'password/index.html');
    console.log(`PASS: Firefox password change ${label}: cancelled file choice, cancel by button and Esc (no file, passwords wiped), wrong old password refused; the saved copy opens with the new password only, in Node and in the Firefox signing tool; key and certificates unchanged, original untouched`);
  }

  if (kalkanJars) {
    for (const [index, [label, name, key]] of keys.entries()) {
      const originalPath = join(folder, `original-${name}`); writeFileSync(originalPath, key);
      const output = kalkan(['compare', originalPath, downloads[index].path], { TEGIN_TEST_NEW_PASSWORD: NEW_PASSWORD });
      assert.match(output, /KALKAN SAME KEY AND CERTIFICATES/); assert.match(output, /KALKAN OLD PASSWORD REJECTED/);
      console.log(`PASS: Kalkan opens the Firefox-saved ${label} copy${label.startsWith('GOST') ? ' of a Kalkan-created key' : ''} with the new password: same key and certificates, old password rejected`);
    }
  } else console.log('SKIP: Kalkan check of the Firefox-saved copies (set NCA_KALKAN_JARS)');

  assert.deepEqual(errors, []);
  console.log('Firefox password E2E completed.');
} finally {
  await browser.close();
  site.close();
  rmSync(folder, { recursive: true, force: true });
}
