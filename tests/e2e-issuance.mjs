import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { gostHierarchy, issueFromCsr } from './helpers/gost-ca.js';
import { unbase64, parse, der, oidValue } from '../extension/crypto/encoding.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';
import { generateRequest } from '../extension/crypto/issuance.js';
import { normalizeIssuance } from '../extension/signing/issuance-protocol.js';

// NUC key issuance in the built extension against anonymized replicas of the portal pages.
// https://did.pki.gov.kz and https://nca.pki.gov.kz are answered by local routes; the real hosts never resolve.
const folder = mkdtempSync(join(tmpdir(), 'tegin-issuance-e2e-'));
const { root, ca } = gostHierarchy();
execFileSync('node', ['scripts/build.mjs'], { stdio: 'pipe', env: { ...process.env, TEGIN_TEST_ISSUANCE_ANCHORS: JSON.stringify([root.base64]), TEGIN_DIST: join(folder, 'build') } });
const extension = join(folder, 'build', 'chromium');
const PASSWORD = 'Tegin-Test-2026';
const NUC_HOSTS = ['did.pki.gov.kz', 'nca.pki.gov.kz', 'nca.pki.gov.kz.example.kz', 'tsp.pki.gov.kz', 'ocsp.pki.gov.kz', 'crl.pki.gov.kz', 'crl1.pki.gov.kz', 'crl.root.gov.kz'];
const createPage = readFileSync(resolve('tests/fixtures/nca-issuance/create.html'), 'utf8');
const statusPage = readFileSync(resolve('tests/fixtures/nca-issuance/status.html'), 'utf8');
let storages = 'PKCS12,AKKaztokenStore,AKKZIDCardStore', issued = [];
const posts = [];
const statusHtml = () => statusPage.replace('{{COUNT}}', String(issued.length))
  .replace('{{PEMS}}', issued.map((pem, index) => `<div id="hiddenCertrequests:${index}:pem" hidden>${pem}</div>`).join('\n'));

const server = createServer((req, res) => { res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(createPage.replace('{{STORAGES}}', storages)); });
await new Promise(done => server.listen(0, '127.0.0.1', done));
const port = server.address().port;
mkdirSync(resolve('artifacts'), { recursive: true });

let context, sw, extensionId;
const errors = [], escaped = [];
async function launch() {
  context = await chromium.launchPersistentContext(join(folder, 'profile'), {
    executablePath: process.env.CHROMIUM_EXECUTABLE || chromium.executablePath(), headless: true, viewport: { width: 870, height: 900 }, acceptDownloads: true,
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`, '--no-first-run', `--host-resolver-rules=${NUC_HOSTS.map(host => `MAP ${host} ~NOTFOUND`).join(', ')}`]
  });
  context.on('page', page => page.on('pageerror', error => errors.push(error.message)));
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.href.startsWith(`http://127.0.0.1:${port}/`) || url.protocol === 'chrome-extension:') return route.continue();
    if (['did.pki.gov.kz', 'nca.pki.gov.kz', 'nca.pki.gov.kz.example.kz'].includes(url.host)) {
      // The application form is recorded as encoded; 204 keeps the page so its state stays readable.
      if (route.request().method() === 'POST') {
        posts.push({ path: url.pathname, type: route.request().headers()['content-type'], body: route.request().postData() });
        return route.fulfill({ status: 204 });
      }
      const body = url.pathname.includes('/status') ? statusHtml() : url.pathname.includes('/frame') ? '<!doctype html><title>frame</title>' : createPage.replace('{{STORAGES}}', storages);
      return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body });
    }
    escaped.push(url.href); return route.abort();
  });
  sw = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  extensionId = new URL(sw.url()).host;
}
const CREATE = 'https://did.pki.gov.kz/service/pkiorder/create.xhtml';
const STATUS = 'https://did.pki.gov.kz/service/pkiorder/status.xhtml';
const records = async () => Object.entries(await sw.evaluate(() => chrome.storage.local.get(null))).filter(([key]) => key.startsWith('issuance:')).map(([, value]) => value);
async function startPopup(page, call) {
  const opened = context.waitForEvent('page');
  await page.evaluate(name => { window.answer = window[name](); }, call);
  const popup = await opened;
  await popup.waitForURL(`chrome-extension://${extensionId}/signing/issue.html#*`);
  return popup;
}
const answer = page => page.evaluate(() => window.answer);

try {
  await launch();
  assert.match(await sw.evaluate(() => chrome.runtime.getManifest().name), /test issuance build/);

  // Foreign origins and frames get a refusal immediately, without any window.
  for (const url of [`http://127.0.0.1:${port}/service/pkiorder/create.xhtml`, 'https://nca.pki.gov.kz.example.kz/service/pkiorder/create.xhtml']) {
    const page = await context.newPage();
    await page.goto(url);
    const pages = context.pages().length;
    assert.deepEqual(await page.evaluate(() => createCertRequest()), { status: false, code: 'ORIGIN_NOT_ALLOWED', message: 'Выпуск ключей доступен только на сайте НУЦ РК.' });
    assert.deepEqual(await page.evaluate(() => window.alerts), ['ORIGIN_NOT_ALLOWED']);
    assert.equal(context.pages().length, pages);
    await page.close();
  }
  const framed = await context.newPage();
  await framed.goto(CREATE);
  await framed.evaluate(() => { document.getElementById('frame').src = 'https://did.pki.gov.kz/frame'; });
  const frame = await (async () => { for (let i = 0; i < 100; i++) { const found = framed.frames().find(item => item.url().endsWith('/frame')); if (found) return found; await framed.waitForTimeout(50); } })();
  await frame.waitForFunction(() => window.WebSocket.__ncaBrowserAdapter === true);
  const fromFrame = await frame.evaluate(() => new Promise(done => { const socket = new WebSocket('wss://127.0.0.1:13579'); socket.onopen = () => { socket.onmessage = event => done(JSON.parse(event.data));
    socket.send(JSON.stringify({ module: 'kz.gov.pki.knca.basics', method: 'generateCsr', class: 'PKIEssentials', args: { dn: { '2.5.4.3': 'X' }, params: [{ algorithm: 'ECGOST3410-2015', length: 512 }] } })); }; }));
  assert.equal(fromFrame.code, 'ORIGIN_NOT_ALLOWED');
  await framed.close();
  // A template restricted to hardware carriers is refused with an explanation.
  storages = 'AKKaztokenStore,AKKZIDCardStore';
  const hardware = await context.newPage();
  await hardware.goto(CREATE);
  assert.equal((await hardware.evaluate(() => createCertRequest())).code, 'STORAGE_NOT_SUPPORTED');
  // The refusal is logged for the popup with names and structure only.
  const hardwareTab = await sw.evaluate(async url => (await chrome.tabs.query({ url })).at(-1).id, CREATE);
  const [logged] = (await sw.evaluate(key => chrome.storage.session.get(key), `diagnostic:${hardwareTab}`))[`diagnostic:${hardwareTab}`];
  assert.deepEqual({ ...logged, at: 0, reason: '' }, { at: 0, module: 'kz.gov.pki.knca.basics', method: 'generateCsr', class: 'PKIEssentials', stage: 'refused', code: 'STORAGE_NOT_SUPPORTED', reason: '',
    args: { allowedStorages: { array: 2, items: ['string'] }, defaultPassword: 'string', dn: { '2.5.4.3': 'string', '2.5.4.4': 'string', '2.5.4.5': 'string', '2.5.4.6': 'string', '2.5.4.42': 'string', '2.5.4.10': 'string', '2.5.4.11': 'string' },
      email: 'empty', subjectAltNames: 'empty', params: { array: 1, items: [{ algorithm: 'string', length: 'number' }] }, locale: 'string', omittedKeyIds: { array: 1, items: ['empty'] } } });
  assert.ok(!/IIN0|BIN0|synthetic-default|ТЕСТ|pki\.gov\.kz/.test(JSON.stringify(logged)));
  const sitePopup = await context.newPage();
  await sitePopup.goto(`chrome-extension://${extensionId}/index.html?site=${hardwareTab}`);
  await sitePopup.locator('#site-log:not([hidden])').waitFor();
  assert.equal(await sitePopup.locator('#log-method').textContent(), 'PKIEssentials.generateCsr');
  assert.equal(await sitePopup.locator('#log-result').textContent(), 'Отклонён · STORAGE_NOT_SUPPORTED');
  assert.equal(await sitePopup.locator('#version').textContent(), JSON.parse(readFileSync(resolve('package.json'), 'utf8')).version);
  await sitePopup.screenshot({ path: 'artifacts/issuance-popup-log.png' });
  // A page already served by Tegin 0.5.2 (shared ncabrowser:* channel) is reported as a version conflict.
  await hardware.evaluate(source => {
    const legacy = function () {};
    Object.defineProperty(legacy, '__ncaBrowserAdapter', { value: true });
    window.WebSocket = legacy;
    (0, eval)(source);
  }, readFileSync(join(extension, 'content', 'inject.js'), 'utf8'));
  assert.equal(await hardware.evaluate(() => document.documentElement.getAttribute('data-tegin-conflict')), 'legacy');
  await sitePopup.reload();
  assert.equal(await sitePopup.locator('#site-state').textContent(), 'Конфликт версий');
  await sitePopup.close();
  await hardware.close();
  storages = 'PKCS12,AKKaztokenStore,AKKZIDCardStore';
  console.log('PASS: generateCsr from 127.0.0.1, a look-alike host, an iframe of the portal, or a hardware-only template is refused without a window');

  // Step 3: cancel, then retry on the same page and socket.
  const page = await context.newPage();
  await page.goto(CREATE);
  let popup = await startPopup(page, 'createCertRequest');
  await popup.locator('#request-panel:not([hidden])').waitFor();
  const shown = await popup.locator('#subject').innerText();
  for (const value of ['ТЕСТОВ ТЕСТ', 'IIN000000000000', 'BIN000000000000', 'ТОО «ҚАЗАҚ СИНТЕТИКА»']) assert.ok(shown.includes(value), value);
  assert.equal(await popup.locator('#algorithms').innerText(), 'ГОСТ 34.10-2015 · 512 бит');
  assert.equal(await popup.locator('#origin').innerText(), 'https://did.pki.gov.kz');
  // The same record cannot be driven from the signing window.
  const hijack = await context.newPage();
  await hijack.goto(`chrome-extension://${extensionId}/signing/approve.html${new URL(popup.url()).hash}`);
  await hijack.locator('#status[data-error]').filter({ hasText: 'не в своём окне' }).waitFor();
  await hijack.close();
  await popup.locator('#cancel').click();
  assert.deepEqual(await answer(page), { status: true, body: {} });
  assert.deepEqual(posts, []);
  assert.deepEqual(await records(), []);
  console.log('PASS: cancel returns the NCALayer cancellation; the portal unblocks and nothing is stored; the request cannot be opened in the signing window');

  popup = await startPopup(page, 'createCertRequest');
  await popup.locator('#password').fill('weakpass');
  await popup.locator('#password-confirm').fill('weakpass');
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  await popup.locator('#password').fill(PASSWORD);
  await popup.locator('#password-confirm').fill(PASSWORD + 'x');
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  await popup.locator('#password-confirm').fill(PASSWORD);
  await popup.screenshot({ path: resolve('artifacts/issuance-generate.png'), fullPage: true });
  await popup.locator('#approve').click();
  const generated = await answer(page);
  assert.equal(generated.status, true);
  assert.deepEqual(Object.keys(generated.body), ['pems']);
  assert.equal(generated.body.pems.length, 1);
  assert.match(generated.body.pems[0], /^-----BEGIN CERTIFICATE REQUEST-----\n/);
  // The form reaches the server exactly as a browser encodes it.
  for (let i = 0; i < 100 && !posts.length; i++) await page.waitForTimeout(50);
  assert.equal(posts.length, 1);
  assert.equal(posts[0].path, '/service/pkiorder/create.xhtml');
  assert.equal(posts[0].type, 'application/x-www-form-urlencoded');
  const form = new URLSearchParams(posts[0].body);
  assert.deepEqual([...form.keys()], ['createForm', 'certrequestStr', 'storagePath', 'javax.faces.ViewState', 'submitOrderBTest']);
  // A textarea submits CRLF line breaks; the PEM itself is unchanged.
  assert.equal(form.get('certrequestStr'), generated.body.pems[0].replaceAll('\n', '\r\n'));
  assert.equal(form.get('certrequestStr').replaceAll('\r\n', '\n'), generated.body.pems[0]);
  assert.equal(form.get('storagePath'), '');
  // $('storagePath') in pkiorder-basics.js selects <storagePath> elements: a body.container could never reach the form.
  assert.equal(await page.evaluate(() => document.querySelectorAll('storagePath').length), 0);
  assert.equal(form.get('javax.faces.ViewState'), 'synthetic-view-state:1');
  assert.equal(form.get('submitOrderBTest'), 'Отправить');
  assert.equal(await page.evaluate(() => document.getElementById('certrequestStr').value), generated.body.pems[0]);
  posts.length = 0;
  await popup.locator('#result-screen:not([hidden])').waitFor();
  const backupDownload = popup.waitForEvent('download');
  await popup.locator('#downloads a').click();
  const backupPath = join(folder, 'backup.json'); await (await backupDownload).saveAs(backupPath);
  await popup.screenshot({ path: resolve('artifacts/issuance-generated.png'), fullPage: true });
  await popup.close();
  const stored = await records();
  assert.equal(stored.length, 1);
  assert.deepEqual(Object.keys(stored[0]).sort(), ['algorithms', 'created', 'holder', 'id', 'identities', 'origin', 'sealed', 'status', 'v']);
  assert.equal(stored[0].sealed.cipher, 'AES-256-GCM');
  const storedText = JSON.stringify(await sw.evaluate(() => chrome.storage.local.get(null)));
  assert.ok(!storedText.includes(PASSWORD) && !storedText.includes('synthetic-default'));
  assert.deepEqual(JSON.parse(readFileSync(backupPath, 'utf8')), stored[0]);
  const csr = unbase64(generated.body.pems[0].split('\n').filter(line => line && !line.startsWith('-----')).join(''));
  assert.equal(oidValue(parse(csr).value[1].value[0]), '1.2.398.3.10.1.1.2.3.2');
  await page.close();
  console.log('PASS: retry after cancel generates the key in the extension; the page gets only the PKCS#10 PEM and submits it; only the encrypted key is stored');

  // The NUC issues the certificate; the user returns later in a restarted browser.
  const leaf = issueFromCsr(ca, csr);
  issued = [leaf.pem, ca.pem];
  await context.close();
  await launch();
  assert.equal((await records()).length, 1);
  console.log('PASS: the encrypted application key survives a browser restart');

  // Certificate for a key generated elsewhere: found nothing to install.
  const foreignRequest = await generateRequest(normalizeIssuance({ module: 'kz.gov.pki.knca.basics', method: 'generateCsr', class: 'PKIEssentials',
    args: { dn: { '2.5.4.3': 'ТЕСТОВ ТЕСТ' }, params: [{ algorithm: 'ECGOST3410-2015', length: 512 }] } }), PASSWORD, 'foreign');
  const foreignCsr = unbase64(foreignRequest.pems[0].split('\n').filter(line => line && !line.startsWith('-----')).join(''));
  issued = [issueFromCsr(ca, foreignCsr).pem, ca.pem];
  let status = await context.newPage();
  await status.goto(STATUS);
  popup = await startPopup(status, 'setX509CertToKeystore');
  await popup.locator('.issue-certificate').waitFor();
  assert.match(await popup.locator('#certificates').innerText(), /Ключ для этого сертификата в этом браузере не найден/);
  assert.equal(await popup.locator('#backup-import').isVisible(), true);
  await popup.locator('#password').fill(PASSWORD);
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  await popup.screenshot({ path: resolve('artifacts/issuance-foreign-key.png'), fullPage: true });
  await popup.locator('#cancel').click();
  assert.deepEqual(await answer(status), { status: true, body: {} });
  assert.equal(await status.evaluate(() => window.statusChanged || false), false);
  await status.close();
  console.log('PASS: a certificate for another key is not installed; the portal status stays unchanged');

  // Installation; the service worker is stopped while the window is open.
  issued = [leaf.pem.replaceAll('\n', '\r\n'), ca.pem];
  status = await context.newPage();
  await status.goto(STATUS);
  popup = await startPopup(status, 'setX509CertToKeystore');
  await popup.locator('.issue-certificate').waitFor();
  const card = await popup.locator('#certificates').innerText();
  assert.match(card, /Цепочка до корня НУЦ РК подтверждена/);
  assert.match(card, /Ключ заявки найден в этом браузере/);
  // The extension window shares the worker's origin, so its DevTools session can stop it.
  const cdp = await context.newCDPSession(popup);
  const stopped = new Promise(done => cdp.on('ServiceWorker.workerVersionUpdated', ({ versions }) => {
    if (versions.some(version => version.scriptURL.endsWith('/background.js') && version.runningStatus === 'stopped')) done();
  }));
  await cdp.send('ServiceWorker.enable');
  await cdp.send('ServiceWorker.stopAllWorkers');
  await Promise.race([stopped, new Promise((_, fail) => setTimeout(() => fail(new Error('service worker did not stop')), 10000))]);
  await cdp.detach();
  await popup.locator('#password').fill('Wrong-Pass-2026');
  await popup.locator('#approve').click();
  await popup.locator('#status[data-error]').filter({ hasText: 'Пароль не подошёл' }).waitFor();
  await popup.locator('#password').fill(PASSWORD);
  await popup.screenshot({ path: resolve('artifacts/issuance-install.png'), fullPage: true });
  await popup.locator('#approve').click();
  await popup.locator('#result-screen:not([hidden])').waitFor();
  assert.equal(await status.evaluate(() => window.statusChanged || false), false, 'the portal is told only after the file is saved');
  const p12Download = popup.waitForEvent('download');
  await popup.locator('#downloads a').click();
  const p12File = await p12Download;
  assert.match(p12File.suggestedFilename(), /^tegin-gost-000000000000-[0-9a-f]{1,8}\.p12$/);
  const p12Path = join(folder, 'issued.p12'); await p12File.saveAs(p12Path);
  assert.deepEqual(await answer(status), { status: true, body: { result: true } });
  assert.equal(await status.evaluate(() => window.statusChanged), true);
  await popup.locator('#forget:not([hidden])').waitFor();
  await popup.screenshot({ path: resolve('artifacts/issuance-installed.png'), fullPage: true });
  assert.equal((await records())[0].status, 'installed');
  await popup.close();
  console.log('PASS: service worker stopped mid-installation; wrong password refused, retry installs; chain and key checked; .p12 saved before the portal is told');

  // The saved .p12 signs a document through the regular NCALayer basics call.
  await status.evaluate(() => new Promise(done => { window.socket = new WebSocket('wss://127.0.0.1:13579'); window.socket.onopen = done; }));
  const document = Buffer.from('Тестовый документ после выпуска ЭЦП').toString('base64');
  const opened = context.waitForEvent('page');
  await status.evaluate(message => { window.signed = new Promise(done => { window.socket.onmessage = event => done(JSON.parse(event.data)); }); window.socket.send(JSON.stringify(message)); },
    { module: 'kz.gov.pki.knca.basics', method: 'sign', args: { allowedStorages: ['PKCS12'], format: 'cms', data: document, signingParams: { decode: true, encapsulate: true }, signerParams: { extKeyUsageOids: [], chain: [root.pem] }, locale: 'ru' } });
  const signing = await opened;
  await signing.waitForURL(`chrome-extension://${extensionId}/signing/approve.html#*`);
  await signing.locator('#key-file').setInputFiles(p12Path);
  await signing.locator('#password').fill(PASSWORD);
  await signing.locator('#unlock').click();
  await signing.locator('#certificate:not([hidden])').waitFor();
  assert.match(await signing.locator('#trust-state').innerText(), /Цепочка сайта подтверждена/);
  await signing.locator('#approve').click();
  const signed = await status.evaluate(() => window.signed);
  assert.equal(signed.status, true);
  const verified = await verifyCms(unbase64(signed.body.result[0]), { anchors: [root.der, ca.der] });
  assert.equal(verified.signers[0].trust.trusted, true);
  assert.equal(Buffer.from(verified.content).toString(), 'Тестовый документ после выпуска ЭЦП');
  assert.equal(verified.signers[0].certificate.raw, der(parse(leaf.der)));
  console.log('PASS: the issued .p12 opens in Tegin and signs a CMS document that verifies to the synthetic NUC root');

  assert.deepEqual(escaped, []);
  assert.deepEqual(errors, []);
  console.log('Issuance browser E2E completed.');
} finally {
  await context?.close();
  await new Promise(done => server.close(done));
  rmSync(folder, { recursive: true, force: true });
}
