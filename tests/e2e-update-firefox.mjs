import { arch, platform, tmpdir } from 'node:os';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createServer } from 'node:http';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import puppeteer from 'puppeteer-core';
import { Browser, detectBrowserPlatform, install, resolveBuildId } from '@puppeteer/browsers';
import { PUBLISHED, publishedArchive, unpack } from './helpers/published.js';

// Firefox: the build tegin.esl.kz serves (0.5.2, temporary add-on) updated to this release candidate in the same
// profile. Firefox removes a temporary add-on when it closes, so the update is a reinstall with the same ID.
// A site outside .kz is connected through the popup; optional permissions are granted without a prompt here.
async function firefox() {
  if (process.env.FIREFOX_EXECUTABLE) return process.env.FIREFOX_EXECUTABLE;
  const target = detectBrowserPlatform();
  const buildId = await resolveBuildId(Browser.FIREFOX, target, 'stable');
  return (await install({ browser: Browser.FIREFOX, buildId, platform: target, cacheDir: resolve('.browsers') })).executablePath;
}
const executablePath = await firefox();
if (!existsSync(executablePath)) throw new Error(`Firefox not found: ${executablePath}`);
const folder = mkdtempSync(join(tmpdir(), 'tegin-update-firefox-'));
const { version } = JSON.parse(readFileSync(resolve('package.json'), 'utf8'));
const buildEnv = { ...process.env }; for (const name of ['TEGIN_DIST', 'TEGIN_TEST_ISSUANCE_ANCHORS', 'TEGIN_TEST_REVOCATION_ISSUERS']) delete buildEnv[name];
execFileSync('node', ['scripts/build.mjs'], { stdio: 'pipe', env: buildEnv });
const candidate = resolve('dist/firefox');
const old = join(folder, 'tegin-0.5.2');
unpack(await publishedArchive(PUBLISHED.firefox), old);
const ADDON_ID = JSON.parse(readFileSync(join(old, 'manifest.json'), 'utf8')).browser_specific_settings.gecko.id;
assert.equal(JSON.parse(readFileSync(join(candidate, 'manifest.json'), 'utf8')).browser_specific_settings.gecko.id, ADDON_ID);
const uuid = randomUUID();
const BASE = `moz-extension://${uuid}`;
const SITE = 'https://edo.example.org';
const HOSTS = ['edo.example.org', 'goszakup.gov.kz', 'shop.example.kz'];
const local = createServer((req, res) => { res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end('<!doctype html><title>local</title>'); });
await new Promise(done => local.listen(0, '127.0.0.1', done));
const errors = [];
const pause = ms => new Promise(done => setTimeout(done, ms));

let browser;
const launch = () => puppeteer.launch({ browser: 'firefox', executablePath, headless: true, userDataDir: join(folder, 'profile'),
  env: { ...process.env, MOZ_REMOTE_ALLOW_SYSTEM_ACCESS: '1' },
  extraPrefsFirefox: {
    'extensions.webextensions.uuids': JSON.stringify({ [ADDON_ID]: uuid }),
    'extensions.webextOptionalPermissionPrompts': false,
    'network.dns.localDomains': HOSTS.join(',')
  } });
async function site(url) {
  const page = await browser.newPage();
  page.on('pageerror', error => errors.push(error.message));
  await page.setRequestInterception(true);
  page.on('request', request => {
    const target = new URL(request.url());
    if (!HOSTS.includes(target.hostname)) return request.abort();
    request.respond({ status: 200, contentType: 'text/html; charset=utf-8', body: '<!doctype html><title>portal</title>' });
  });
  await page.goto(url);
  return page;
}
const adapter = page => page.evaluate(() => window.WebSocket.__ncaBrowserAdapter === true);
async function extensionPage(prefix, known) {
  for (let i = 0; i < 300; i++) {
    for (const candidate of await browser.pages()) {
      if (known.has(candidate)) continue;
      if ((await candidate.evaluate(() => location.href).catch(() => '')).startsWith(`${BASE}/${prefix}`)) return candidate;
    }
    await pause(50);
  }
  throw new Error(`no extension page ${prefix}`);
}
// A signing request from a local page opens the approval window: an extension context for the test.
async function extensionContext() {
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${local.address().port}/`);
  await page.waitForFunction(() => window.WebSocket.__ncaBrowserAdapter === true);
  const known = new Set(await browser.pages());
  page.evaluate(() => { const socket = new WebSocket('wss://127.0.0.1:13579'); socket.onopen = () => socket.send(JSON.stringify({ module: 'kz.gov.pki.knca.basics', method: 'sign', args: { allowedStorages: ['PKCS12'], format: 'xml', data: '<a/>', signingParams: {}, signerParams: { extKeyUsageOids: [] } } })); });
  const approval = await extensionPage('signing/approve.html#', known);
  return { page, approval };
}
async function open(context, path) {
  const known = new Set(await browser.pages());
  await context.evaluate(url => browser.tabs.create({ url }), `${BASE}/${path}`);
  return extensionPage(path, known);
}
async function nursign(origin) {
  const page = await site(`${origin}/`);
  await page.waitForFunction(() => window.WebSocket.__ncaBrowserAdapter === true);
  const reply = await page.evaluate(() => new Promise(done => {
    const socket = new WebSocket('wss://127.0.0.1:13579');
    socket.onopen = () => { socket.onmessage = event => done(JSON.parse(event.data)); socket.send(JSON.stringify({ module: 'NURSign', type: 'text', data: 'test' })); };
  }));
  await page.close();
  return reply.errorMessage || '';
}

try {
  browser = await launch();
  assert.equal(await browser.installExtension(old), ADDON_ID);
  console.log(`ENV: firefox on ${platform()} ${arch()}: ${await browser.version()}`);
  let { page: helper, approval } = await extensionContext();
  assert.equal(await approval.evaluate(() => browser.runtime.getManifest().version), PUBLISHED.firefox.version);

  // Connect a site outside .kz through the popup, as a user does.
  // Without access to the site the extension does not see its URL: the new tab is found by id.
  const tabIds = () => approval.evaluate(() => browser.tabs.query({}).then(tabs => tabs.map(tab => tab.id)));
  const earlier = await tabIds();
  const edo = await site(`${SITE}/`);
  assert.equal(await adapter(edo), false);
  const [edoTab] = (await tabIds()).filter(id => !earlier.includes(id));
  assert.ok(Number.isInteger(edoTab));
  // The toolbar click that gives the popup the tab (activeTab) cannot be made here, so the site is granted first with
  // the same permissions.request the popup makes, from a click in an extension page; the popup then registers it.
  await approval.evaluate(origin => {
    const button = document.createElement('button'); button.id = 'grant-site'; button.textContent = 'grant';
    button.onclick = () => { window.grant = browser.permissions.request({ origins: [origin] }); };
    document.body.prepend(button);
  }, `${SITE}/*`);
  await approval.click('#grant-site');
  assert.equal(await approval.evaluate(() => window.grant), true);
  const popup = await open(approval, `index.html?site=${edoTab}`);
  await popup.waitForSelector('#enable:not([disabled])').catch(async error => { throw new Error(`${error.message}: ${await popup.$eval('#status', node => node.textContent)} / ${await popup.$eval('#site-name', node => node.textContent)}`); });
  assert.match(await popup.$eval('#site-state', node => node.textContent), /Нужно обновить/);
  await popup.click('#enable');
  await edo.waitForFunction(() => window.WebSocket.__ncaBrowserAdapter === true, { timeout: 15000 });
  const granted = await approval.evaluate(() => browser.permissions.getAll().then(all => all.origins));
  assert.ok(granted.includes(`${SITE}/*`), JSON.stringify(granted));

  // Module settings with an allowed site.
  const manager = await open(approval, 'modules/index.html');
  await manager.waitForSelector('[data-module="goszakup"] > details > summary');
  await manager.click('[data-module="goszakup"] > details > summary');
  await manager.$eval('[data-module="goszakup"] textarea', node => { node.value = 'https://goszakup.gov.kz'; });
  await manager.select('[data-module="goszakup"] select', 'deny');
  await manager.click('[data-module="goszakup"] button[type="submit"]');
  await manager.waitForFunction(async () => (await browser.storage.local.get('moduleSettings')).moduleSettings?.goszakup?.timestamp === 'deny');
  const before = await manager.evaluate(() => browser.storage.local.get(null));
  const scriptsBefore = await manager.evaluate(() => browser.scripting.getRegisteredContentScripts().then(list => list.map(script => script.id).sort()));
  assert.equal(scriptsBefore.length, 2);
  await approval.click('#cancel');
  assert.match(await nursign('https://shop.example.kz'), /не разрешён в настройках модуля/);
  await browser.close();
  console.log(`PASS: published Firefox ${PUBLISHED.firefox.version}: a site outside .kz connected through the popup (permission granted, adapter on the page), module settings with an allowed site`);

  // Same profile, the candidate installed in place of the removed temporary add-on.
  browser = await launch();
  assert.equal(await browser.installExtension(candidate), ADDON_ID);
  ({ page: helper, approval } = await extensionContext());
  assert.equal(await approval.evaluate(() => browser.runtime.getManifest().version), version);
  const after = await approval.evaluate(() => browser.storage.local.get(null));
  assert.deepEqual(after, before);
  assert.ok((await approval.evaluate(() => browser.permissions.getAll().then(all => all.origins))).includes(`${SITE}/*`));
  const scriptsAfter = await approval.evaluate(() => browser.scripting.getRegisteredContentScripts().then(list => list.map(script => script.id).sort()));
  assert.deepEqual(scriptsAfter, scriptsBefore);
  const edoAgain = await site(`${SITE}/`);
  await edoAgain.waitForFunction(() => window.WebSocket.__ncaBrowserAdapter === true, { timeout: 15000 });
  await approval.click('#cancel');
  assert.match(await nursign('https://shop.example.kz'), /не разрешён в настройках модуля/);
  assert.match(await nursign('https://goszakup.gov.kz'), /обязательную метку/);
  console.log(`PASS: update Firefox ${PUBLISHED.firefox.version} → ${version} in the same profile: storage.local unchanged, the granted site and its adapter scripts are there and the page gets the adapter; module settings and the allowed site apply`);

  // Scripts gone while the site stays granted (what Chromium does on reload): the next install rebuilds them.
  ({ page: helper, approval } = await extensionContext());
  await approval.evaluate(() => browser.scripting.getRegisteredContentScripts().then(list => browser.scripting.unregisterContentScripts({ ids: list.map(script => script.id) })));
  await browser.close();
  browser = await launch();
  assert.equal(await browser.installExtension(candidate), ADDON_ID);
  const restored = await site(`${SITE}/`);
  await restored.waitForFunction(() => window.WebSocket.__ncaBrowserAdapter === true, { timeout: 15000 });
  ({ page: helper, approval } = await extensionContext());
  assert.deepEqual(await approval.evaluate(() => browser.scripting.getRegisteredContentScripts().then(list => list.map(script => script.id).sort())), scriptsBefore);
  await approval.click('#cancel');
  console.log('PASS: adapter scripts removed while the site stays granted are registered again by the next install; the page gets the adapter without reconnecting');

  assert.deepEqual(errors, []);
  console.log('Firefox update E2E completed.');
} finally {
  await browser?.close().catch(() => {});
  local.close();
  rmSync(folder, { recursive: true, force: true });
}
