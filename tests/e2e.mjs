import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { rsaFixture, gostFixture, PASSWORD } from './helpers/fixtures.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';
import { forge, oid, der } from '../extension/crypto/encoding.js';

const folder = mkdtempSync(join(tmpdir(), 'ncabrowser-e2e-'));
const extension = resolve('dist/chromium');
const fixture = rsaFixture();
const gost = gostFixture();
const server = createServer((req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end('<!doctype html><html lang="ru"><title>Тестовый сайт ЭЦП</title><h1>Тестовый сайт ЭЦП</h1><p>Используется только одноразовый тестовый ключ.</p></html>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
const cache = join(homedir(), 'Library', 'Caches', 'ms-playwright');
const fallback = existsSync(cache) ? readdirSync(cache).filter(name => /^chromium-\d+$/.test(name)).reverse()
  .map(name => join(cache, name, 'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing')).find(existsSync) : undefined;
const executablePath = process.env.CHROMIUM_EXECUTABLE || (existsSync(chromium.executablePath()) ? chromium.executablePath() : fallback);
let context;
try {
  context = await chromium.launchPersistentContext(join(folder, 'profile'), {
    executablePath, headless: true, viewport: { width: 620, height: 790 },
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`, '--no-first-run']
  });
  const errors = [];
  const liveTsp = process.env.NCA_LIVE_TSP === '1';
  const network = [];
  context.on('page', page => page.on('pageerror', error => errors.push(error.message)));
  context.on('request', request => { if (/^https?:/.test(request.url())) network.push(request.url()); });
  await context.route('**/*', route => {
    const url = route.request().url();
    if (url === 'https://egov.kz/tegin-ui-test') return route.fulfill({ contentType: 'text/html; charset=utf-8', body: '<!doctype html><title>Tegin local UI fixture</title><h1>Artificial authentication request</h1>' });
    if (url.startsWith(`http://127.0.0.1:${port}/`) || url.startsWith('chrome-extension:') || (liveTsp && url === 'http://tsp.pki.gov.kz/')) route.continue();
    else route.abort();
  });
  const sw = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  const extensionId = new URL(sw.url()).host;
  const page = await context.newPage();
  await page.addInitScript(() => {
    window.bridgeMessages = [];
    window.addEventListener('message', event => {
      if (event.source === window) window.bridgeMessages.push(JSON.stringify(event.data));
    });
  });
  await page.goto(`http://127.0.0.1:${port}/`);
  await page.evaluate(() => new Promise((resolve, reject) => {
    window.socket = new WebSocket('wss://127.0.0.1:13579');
    window.socket.onmessage = event => { window.greeting = JSON.parse(event.data); resolve(); };
    window.socket.onerror = reject;
  }));
  assert.equal(await page.evaluate(() => window.greeting.result.implementation), 'Tegin');
  async function send(request) {
    await page.evaluate(request => {
      window.result = new Promise(resolve => { window.socket.onmessage = event => resolve(JSON.parse(event.data)); });
      window.socket.send(JSON.stringify(request));
    }, request);
  }
  const result = () => page.evaluate(() => window.result);
  await send({ module: 'kz.gov.pki.knca.commonUtils', method: 'getActiveTokens' });
  assert.deepEqual((await result()).responseObject, []);
  console.log('PASS: page detects virtual NCALayer, getActiveTokens works without a local service');

  async function confirmation(request, key = fixture, wrongFirst = false) {
    const opened = context.waitForEvent('page');
    await send(request);
    const popup = await opened;
    await popup.waitForURL(`chrome-extension://${extensionId}/signing/approve.html#*`);
    await popup.locator('#origin').filter({ hasText: `http://127.0.0.1:${port}` }).waitFor();
    await popup.locator('#key-file').setInputFiles({ name: 'disposable-test.p12', mimeType: 'application/x-pkcs12', buffer: Buffer.from(key.container) });
    if (wrongFirst) {
      await popup.locator('#password').fill('wrong');
      await popup.locator('#unlock').click();
      await popup.locator('#status[data-error]').waitFor();
      assert.equal(await popup.locator('#approve').isDisabled(), true);
    }
    await popup.locator('#password').fill(PASSWORD);
    await popup.locator('#unlock').click();
    await popup.locator('#certificate:not([hidden])').waitFor({ timeout: 15000 });
    assert.equal(await popup.locator('#password').inputValue(), '');
    return popup;
  }
  const data = Buffer.from('Browser end-to-end signing: Привет');
  const common = { module: 'kz.gov.pki.knca.commonUtils', method: 'createCAdESFromBase64', args: ['PKCS12', 'SIGNATURE', data.toString('base64'), true] };
  let popup = await confirmation(common, fixture, true);
  mkdirSync(resolve('artifacts'), { recursive: true });
  await popup.setViewportSize({ width: 870, height: 850 });
  await popup.screenshot({ path: resolve('artifacts/confirmation.png'), fullPage: true });
  await popup.locator('#approve').click();
  let answer = await result();
  assert.equal(answer.code, '200');
  writeFileSync(join(folder, 'browser.p7s'), Buffer.from(answer.responseObject, 'base64'));
  execFileSync('openssl', ['cms', '-verify', '-binary', '-inform', 'DER', '-in', join(folder, 'browser.p7s'), '-noverify', '-out', join(folder, 'document')], { stdio: 'pipe' });
  assert.deepEqual(readFileSync(join(folder, 'document')), data);
  console.log('PASS: browser PKCS12 unlock, wrong password rejection, explicit approval, CMS verified by OpenSSL');

  // Regression: OpenSSL 3 default PKCS#12 (PBES2/AES-256) with a non-ASCII password.
  const unicodePassword = 'Ұлттық куәлік 2026 пароль';
  const unicodeKey = rsaFixture({ password: unicodePassword });
  const unicodeFile = { name: 'unicode-test-key.p12', mimeType: 'application/x-pkcs12', buffer: Buffer.from(unicodeKey.container) };
  const unicodeOpened = context.waitForEvent('page');
  await send(common);
  popup = await unicodeOpened;
  await popup.locator('#origin').filter({ hasText: `http://127.0.0.1:${port}` }).waitFor();
  await popup.locator('#key-file').setInputFiles(unicodeFile);
  await popup.locator('#password').fill('Ұлттық куәлік 2025 пароль');
  await popup.locator('#unlock').click();
  await popup.locator('#status[data-error]').filter({ hasText: 'Пароль не подошёл или контейнер повреждён.' }).waitFor();
  assert.equal(await popup.locator('#password').inputValue(), '');
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  assert.equal(await popup.locator('#certificate').isHidden(), true);
  await popup.locator('#key-diagnostic summary').click();
  await popup.setViewportSize({ width: 870, height: 850 });
  await popup.screenshot({ path: resolve('artifacts/pkcs12-error-diagnostic.png'), fullPage: true });
  const diagnostic = JSON.parse(await popup.locator('#key-diagnostic-data').textContent());
  assert.equal(diagnostic.code, 'PASSWORD_OR_DAMAGED'); assert.equal(diagnostic.stage, 'integrity');
  assert.equal(diagnostic.product, 'Tegin'); assert.match(diagnostic.browser, /\d/);
  assert.equal(diagnostic.container.integrity.algorithm, '2.16.840.1.101.3.4.2.1');
  assert.ok(diagnostic.container.encryption.some(entry => entry.scheme === '1.2.840.113549.1.5.13'));
  const diagnosticText = JSON.stringify(diagnostic);
  for (const secret of ['unicode-test-key', 'Tegin disposable test', 'Ұлттық', 'пароль']) assert.ok(!diagnosticText.includes(secret), `diagnostic leaks ${secret}`);
  // A different file clears the error; a late worker reply after another file change must not unlock signing.
  await popup.locator('#key-file').setInputFiles({ name: 'other.p12', mimeType: 'application/x-pkcs12', buffer: Buffer.from(fixture.container) });
  assert.equal(await popup.locator('#key-diagnostic').isHidden(), true);
  await popup.locator('#password').fill(PASSWORD);
  await popup.locator('#unlock').click();
  await popup.locator('#key-file').setInputFiles(unicodeFile);
  await popup.waitForTimeout(1500);
  assert.equal(await popup.locator('#certificate').isHidden(), true, 'stale worker must not open the previous key');
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  await popup.locator('#password').fill(unicodePassword);
  await popup.locator('#unlock').click();
  await popup.locator('#certificate:not([hidden])').waitFor({ timeout: 15000 });
  assert.equal(await popup.locator('#password').inputValue(), '');
  assert.equal(await popup.locator('#key-diagnostic').isHidden(), true);
  await popup.locator('#approve').click();
  answer = await result();
  assert.equal(answer.code, '200');
  const unicodeCms = Buffer.from(answer.responseObject, 'base64');
  writeFileSync(join(folder, 'unicode.p7s'), unicodeCms);
  writeFileSync(join(folder, 'unicode-cert.pem'), unicodeKey.certificate);
  execFileSync('openssl', ['cms', '-verify', '-binary', '-inform', 'DER', '-in', join(folder, 'unicode.p7s'), '-CAfile', join(folder, 'unicode-cert.pem'), '-purpose', 'any', '-out', join(folder, 'unicode-document')], { stdio: 'pipe' });
  assert.deepEqual(readFileSync(join(folder, 'unicode-document')), data);
  const tampered = Buffer.from(unicodeCms); tampered[tampered.indexOf(data) + 1] ^= 1;
  writeFileSync(join(folder, 'unicode-tampered.p7s'), tampered);
  assert.throws(() => execFileSync('openssl', ['cms', '-verify', '-binary', '-inform', 'DER', '-in', join(folder, 'unicode-tampered.p7s'), '-CAfile', join(folder, 'unicode-cert.pem'), '-purpose', 'any', '-out', join(folder, 'unicode-tampered-out')], { stdio: 'pipe' }));
  console.log('PASS: PBES2 PKCS12 with a Kazakh/Cyrillic password: precise error, anonymous diagnostic, stale-worker guard, retry, OpenSSL-verified CMS, tampered document rejected');

  // A certificate-stage error replaces the key form with the certificate card; the diagnostic must stay reachable.
  const day = 24 * 60 * 60 * 1000;
  const expiredKey = rsaFixture({ subject: '/CN=Tegin expired disposable test', validity: { notBefore: new Date(Date.now() - 30 * day), notAfter: new Date(Date.now() - day) } });
  // Chromium cannot grant clipboard access to the extension origin, so the copied text is read back from the fixture page.
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: `http://127.0.0.1:${port}` });
  const expiredOpened = context.waitForEvent('page');
  await send(common);
  popup = await expiredOpened;
  await popup.locator('#origin').filter({ hasText: `http://127.0.0.1:${port}` }).waitFor();
  await popup.locator('#key-file').setInputFiles({ name: 'expired-test-key.p12', mimeType: 'application/x-pkcs12', buffer: Buffer.from(expiredKey.container) });
  await popup.locator('#password').fill(PASSWORD);
  await popup.locator('#unlock').click();
  await popup.locator('#status[data-error]').filter({ hasText: 'Срок действия сертификата ещё не наступил или уже истёк.' }).waitFor({ timeout: 15000 });
  assert.equal(await popup.locator('#certificate[data-diagnostic]').isVisible(), true);
  assert.equal(await popup.locator('#key-form').isHidden(), true);
  assert.equal(await popup.locator('#key-diagnostic').isVisible(), true, 'diagnostic must be visible next to the certificate card');
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  assert.equal(await popup.locator('#password').inputValue(), '');
  await popup.locator('#key-diagnostic summary').click();
  assert.equal(await popup.locator('#key-diagnostic-data').isVisible(), true);
  await popup.setViewportSize({ width: 870, height: 850 });
  await popup.screenshot({ path: resolve('artifacts/certificate-error-diagnostic.png'), fullPage: true });
  const expiredText = await popup.locator('#key-diagnostic-data').textContent();
  const expiredDiagnostic = JSON.parse(expiredText);
  assert.equal(expiredDiagnostic.code, 'CERTIFICATE_NOT_VALID_NOW'); assert.equal(expiredDiagnostic.stage, 'certificate');
  assert.equal(expiredDiagnostic.product, 'Tegin');
  for (const secret of ['expired-test-key', 'Tegin expired disposable test', PASSWORD, expiredKey.certificate.split('\n')[1].slice(0, 32)]) assert.ok(!expiredText.includes(secret), `diagnostic leaks ${secret}`);
  await popup.bringToFront();
  await popup.locator('#copy-diagnostic').click();
  await popup.locator('#copy-diagnostic').filter({ hasText: 'Скопировано' }).waitFor();
  await page.bringToFront();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), expiredText);
  await page.evaluate(() => navigator.clipboard.writeText(''));
  await popup.bringToFront();
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  await popup.locator('#change-key').click();
  assert.equal(await popup.locator('#key-diagnostic').isHidden(), true);
  assert.equal(await popup.locator('#key-diagnostic-data').textContent(), '');
  assert.equal(await popup.locator('#key-form').isVisible(), true);
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  await popup.locator('#cancel').click();
  answer = await result();
  assert.equal(answer.code, '500'); assert.equal(answer.responseObject, null);
  expiredKey.container.fill(0);
  console.log('PASS: expired disposable certificate: error shown, diagnostic visible beside the certificate card, CERTIFICATE_NOT_VALID_NOW/certificate, copy works, approval disabled, cleared on key change');

  const basics = { module: 'kz.gov.pki.knca.basics', method: 'sign', args: { allowedStorages: ['PKCS12'], format: 'xml', data: '<request><text>Тест браузера</text></request>', signingParams: {}, signerParams: { extKeyUsageOids: [], chain: [] } } };
  popup = await confirmation(basics);
  await popup.locator('#approve').click();
  answer = await result();
  assert.equal(answer.status, true);
  assert.match(answer.body.result[0], /ds:SignatureValue/);
  console.log('PASS: basics.sign XML returned through the page bridge');

  // Reproduce the public NUC login request: send immediately on open,
  // null TSA profile, twelve acceptable certificates including a legacy OID.
  const authentication = rsaFixture({ purpose: 'clientAuth' });
  const signingOnly = rsaFixture({ purpose: 'emailProtection' });
  const oldRoot = forge.pki.certificateToAsn1(forge.pki.certificateFromPem(authentication.certificate));
  oldRoot.value[0].value[6].value[0].value[0] = oid('1.3.6.1.4.1.6801.1.5.8');
  const legacyPem = forge.pem.encode({ type: 'CERTIFICATE', body: der(oldRoot) });
  const nucRequest = { module: basics.module, method: 'sign', args: { allowedStorages: ['PKCS12', 'JKS'], format: 'xml', data: '<login><client-type>PORTAL</client-type></login>', signingParams: { decode: false, encapsulate: false, digested: false, tsaProfile: null }, signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'], chain: [...Array(11).fill(authentication.certificate), legacyPem] } } };
  async function portalOnOpen(request) {
    const opened = context.waitForEvent('page');
    await page.evaluate(request => {
      window.portalMessages = [];
      window.portalSocket = new WebSocket('wss://127.0.0.1:13579/');
      window.portalResult = new Promise(resolve => {
        window.portalSocket.onopen = () => window.portalSocket.send(JSON.stringify(request));
        window.portalSocket.onmessage = event => { const response = JSON.parse(event.data); window.portalMessages.push(response); resolve(response); };
      });
    }, request);
    const approval = await opened; await approval.waitForLoadState();
    assert.equal(await page.evaluate(() => window.portalMessages.length), 0, 'No unsolicited greeting may resolve an immediate-request client');
    return approval;
  }
  popup = await portalOnOpen(nucRequest);
  await popup.locator('#key-file').setInputFiles({ name: 'переименованный-ключ.p12', mimeType: 'application/x-pkcs12', buffer: Buffer.from(authentication.container) });
  await popup.locator('#password').fill(PASSWORD); await popup.locator('#unlock').click();
  await popup.locator('#certificate:not([hidden])').waitFor();
  await popup.locator('#approve').click();
  const portalAnswer = await page.evaluate(() => window.portalResult);
  assert.equal(portalAnswer.status, true); assert.match(portalAnswer.body.result[0], /ds:SignatureValue/);
  await page.evaluate(() => window.portalSocket.close());
  console.log('PASS: NUC-style null TSA + twelve roots + legacy root + authentication EKU, direct onopen client receives signed XML');

  // Exact Tegin NCALayerService wire profiles: UTF-8/base64 challenge attached,
  // then downloaded document bytes detached. No Tegin API payload includes key/password.
  const challenge = 'tegin-auth-challenge-v1-123456';
  const authCmsRequest = { module: basics.module, method: 'sign', args: { allowedStorages: null, format: 'cms',
    data: Buffer.from(challenge, 'utf8').toString('base64'),
    signingParams: { decode: true, encapsulate: true, digested: false },
    signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'], chain: [] }, locale: 'ru' } };
  popup = await confirmation(authCmsRequest, authentication);
  await popup.locator('#approve').click();
  const authWireAnswer = await result();
  assert.equal(authWireAnswer.status, true);
  const authCms = new Uint8Array(Buffer.from(authWireAnswer.body.result[0], 'base64'));
  const verifiedAuth = await verifyCms(authCms);
  assert.deepEqual(Buffer.from(verifiedAuth.content), Buffer.from(challenge, 'utf8'));
  console.log('PASS: Tegin authChallenge bytes encoded by frontend profile are returned as attached CMS and verified independently');

  const documentBytes = Buffer.from('%PDF-1.4\nTegin synthetic document-sign fixture\n');
  const documentWireRequest = { module: basics.module, method: 'sign', args: { allowedStorages: null, format: 'cms',
    data: documentBytes.toString('base64'),
    signingParams: { decode: true, encapsulate: false, digested: false },
    signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.4'], chain: [] }, locale: 'ru' } };
  popup = await confirmation(documentWireRequest, signingOnly);
  await popup.locator('#approve').click();
  const documentWireAnswer = await result();
  assert.equal(documentWireAnswer.status, true);
  const documentCms = new Uint8Array(Buffer.from(documentWireAnswer.body.result[0], 'base64'));
  assert.equal((await verifyCms(documentCms, { detached: new Uint8Array(documentBytes) })).valid, true);
  const changedTeginPdf = new Uint8Array(documentBytes); changedTeginPdf[0] ^= 1;
  await assert.rejects(verifyCms(documentCms, { detached: changedTeginPdf }));
  console.log('PASS: Tegin downloaded-document profile returns detached CMS; exact bytes pass, changed bytes fail');

  popup = await portalOnOpen(nucRequest);
  await popup.locator('#key-file').setInputFiles({ name: 'signing-only-test.p12', mimeType: 'application/x-pkcs12', buffer: Buffer.from(signingOnly.container) });
  await popup.locator('#password').fill(PASSWORD); await popup.locator('#unlock').click();
  await popup.locator('#status[data-error]').filter({ hasText: 'единый ГОСТ' }).waitFor();
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  assert.equal(await popup.locator('#certificate[data-diagnostic]').isVisible(), true);
  assert.equal(await popup.locator('#certificate-technical').getAttribute('open'), null);
  await popup.locator('#certificate-technical > summary').click();
  assert.match(await popup.locator('#cert-usage').innerText(), /1\.3\.6\.1\.5\.5\.7\.3\.4/);
  assert.doesNotMatch(await popup.locator('#cert-usage').innerText(), /1\.3\.6\.1\.5\.5\.7\.3\.2/);
  await popup.locator('#change-key').click();
  assert.equal(await popup.locator('#key-form').isVisible(), true);
  assert.equal(await popup.locator('#certificate').isHidden(), true);
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  assert.equal(await page.evaluate(() => window.portalMessages.length), 0);
  await popup.locator('#cancel').click();
  const cancelledPortal = await page.evaluate(() => window.portalResult);
  assert.deepEqual(cancelledPortal, { status: true, body: {} });
  await page.evaluate(() => window.portalSocket.close());
  // A self-signed GOST key with copied NUC purpose OIDs and a site-provided
  // anchor must not acquire the pinned NUC issuer policy.
  const imitation = gostFixture('512', { eku: ['1.3.6.1.5.5.7.3.4', '1.2.398.3.3.4.1.1'], keyUsage: true });
  const imitationPem = forge.pem.encode({ type: 'CERTIFICATE', body: forge.util.decode64(imitation.certificate) });
  const imitationRequest = structuredClone(nucRequest);
  imitationRequest.args.signerParams.chain = [imitationPem];
  popup = await portalOnOpen(imitationRequest);
  await popup.locator('#key-file').setInputFiles({ name: 'renamed-unified-imitation.p12', mimeType: 'application/x-pkcs12', buffer: Buffer.from(imitation.container) });
  await popup.locator('#password').fill(PASSWORD); await popup.locator('#unlock').click();
  await popup.locator('#status[data-error]').filter({ hasText: 'единый ГОСТ' }).waitFor();
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  assert.equal(await popup.locator('#cert-policy-note').isHidden(), true);
  assert.equal(await popup.locator('#trust-state[data-trusted]').isVisible(), true, 'Site-provided anchor is trusted but cannot grant NUC policy');
  assert.equal(await page.evaluate(() => window.portalMessages.length), 0);
  await popup.locator('#cancel').click(); await page.evaluate(() => window.portalResult);
  await page.evaluate(() => window.portalSocket.close()); imitation.container.fill(0);
  console.log('PASS: site-trusted imitation GOST subscriber cannot claim pinned NUC unified authentication policy');
  authentication.container.fill(0); signingOnly.container.fill(0);
  console.log('PASS: a document-signing-only certificate cannot authenticate; clear explanation and no signed response');


  popup = await confirmation(common, gost);
  await popup.locator('#approve').click();
  answer = await result();
  assert.equal(answer.code, '200');
  assert.ok(Buffer.from(answer.responseObject, 'base64').length > 300);
  console.log('PASS: GOST-512 signing in a real extension worker');
  for (const family of ['256', '2004']) {
    const key = gostFixture(family); popup = await confirmation(common, key);
    await popup.locator('#approve').click(); answer = await result(); assert.equal(answer.code, '200', answer.message);
    key.container.fill(0); console.log(`PASS: GOST-${family} signing in a real extension worker`);
  }

  popup = await confirmation({ ...common, method: 'createCAdESFromBase64' });
  await popup.locator('#approve').click();
  answer = await result();
  assert.equal(answer.code, '200');
  writeFileSync(join(folder, 'browser-cades.der'), Buffer.from(answer.responseObject, 'base64'));
  writeFileSync(join(folder, 'cert.pem'), fixture.certificate);
  execFileSync('openssl', ['cms', '-verify', '-cades', '-binary', '-inform', 'DER', '-in', join(folder, 'browser-cades.der'), '-CAfile', join(folder, 'cert.pem'), '-purpose', 'any', '-out', join(folder, 'document')], { stdio: 'pipe' });
  assert.deepEqual(readFileSync(join(folder, 'document')), data);
  console.log('PASS: browser CAdES-BES including SigningCertificateV2 verified by OpenSSL');

  // The local tools use the same worker but never require a site or private key for verification.
  const tool = await context.newPage();
  await tool.setViewportSize({ width: 870, height: 850 });
  await tool.goto(`chrome-extension://${extensionId}/signing/approve.html`);
  assert.equal(await tool.locator('#format').isVisible(), false);
  await tool.locator('#document').setInputFiles({ name: 'test.txt', mimeType: 'text/plain', buffer: data });
  await tool.locator('#key-file').setInputFiles({ name: 'test.p12', mimeType: 'application/x-pkcs12', buffer: Buffer.from(fixture.container) });
  await tool.locator('#password').fill(PASSWORD); await tool.locator('#unlock').click();
  await tool.locator('#certificate:not([hidden])').waitFor();
  await tool.locator('#approve').click();
  await tool.locator('#result-title').filter({ hasText: 'Документ подписан' }).waitFor();
  const downloadWait = tool.waitForEvent('download'); await tool.locator('#download').click();
  const downloaded = await downloadWait; const localPath = join(folder, 'local.p7s'); await downloaded.saveAs(localPath);
  await tool.locator('#verify-created').click();
  await tool.locator('#result-title').filter({ hasText: 'Подпись верна' }).waitFor();
  assert.match(tool.url(), /mode=verify/);
  await tool.goBack();
  await tool.locator('#title').filter({ hasText: 'Подписать документ' }).waitFor();
  assert.equal(await tool.locator('#password').inputValue(), '');
  await tool.locator('#nav-verify').click();
  await tool.locator('#title').filter({ hasText: 'Проверить подпись' }).waitFor();
  await tool.locator('#nav-sign').click();
  assert.equal(await tool.locator('#password').inputValue(), '');
  console.log('PASS: direct verification of newly signed file, same-tab mode switching, browser Back and key clearing');
  assert.equal(await tool.locator('#approve').isDisabled(), true);
  await tool.goto(`chrome-extension://${extensionId}/signing/approve.html?mode=verify`);
  await tool.locator('#document').setInputFiles(localPath);
  assert.equal(await tool.locator('#original-controls').isVisible(), false);
  await tool.locator('#verify-submit').click();
  await tool.locator('#result-title').filter({ hasText: 'Подпись верна' }).waitFor();
  await tool.screenshot({ path: resolve('artifacts/verification.png'), fullPage: true });
  console.log('PASS: local file signing, download, reset and CMS verification without a key');
  popup = await confirmation({ ...common, args: [...common.args.slice(0, 3), false] });
  await popup.locator('#approve').click(); answer = await result(); assert.equal(answer.code, '200');
  await tool.locator('#again').click();
  await tool.locator('#document').setInputFiles({ name: 'detached.p7s', mimeType: 'application/pkcs7-signature', buffer: Buffer.from(answer.responseObject, 'base64') });
  await tool.locator('#verify-submit').click();
  await tool.locator('#status[data-error]').filter({ hasText: 'исходный документ' }).waitFor();
  await tool.locator('#original').setInputFiles({ name: 'original.txt', mimeType: 'text/plain', buffer: data });
  await tool.locator('#verify-submit').click();
  await tool.locator('#result-title').filter({ hasText: 'Подпись верна' }).waitFor();
  console.log('PASS: detached verification requires original document and recovers after missing-document error');
  await tool.locator('#again').click();
  await tool.locator('#document').setInputFiles({ name: 'detached.p7s', mimeType: 'application/pkcs7-signature', buffer: Buffer.from(answer.responseObject, 'base64') });
  await tool.locator('#original').waitFor({ state: 'visible' });
  await tool.locator('#original').setInputFiles({ name: 'wrong.txt', mimeType: 'text/plain', buffer: Buffer.from('wrong document') });
  await tool.locator('#verify-submit').click(); await tool.locator('#status[data-error]').waitFor();
  await tool.locator('#document').setInputFiles(localPath);
  await tool.locator('#verify-submit:not([disabled])').waitFor();
  assert.equal(await tool.locator('#original').inputValue(), '');
  assert.equal(await tool.locator('#original-controls').isVisible(), false);
  await tool.locator('#verify-submit').click();
  await tool.locator('#result-title').filter({ hasText: 'Подпись верна' }).waitFor();
  console.log('PASS: changed detached original rejected; switching to attached CMS clears stale original and verifies');
  await tool.locator('#again').click();
  const damaged = Buffer.from(readFileSync(localPath)); damaged[damaged.length - 1] ^= 1;
  await tool.locator('#document').setInputFiles({ name: 'damaged.p7s', mimeType: 'application/pkcs7-signature', buffer: damaged });
  await tool.locator('#verify-submit').click(); await tool.locator('#status[data-error]').waitFor();
  assert.equal(await tool.locator('#result-screen').isVisible(), false);
  console.log('PASS: detecting attached content never marks a damaged signature as valid');

  for (const width of [1280, 870, 400]) {
    await tool.locator('#nav-verify').click(); await tool.setViewportSize({ width, height: 900 });
    await tool.locator('#document').setInputFiles(localPath);
    await tool.locator('#verify-submit:not([disabled])').waitFor();
    await tool.screenshot({ path: resolve(`artifacts/verify-${width}.png`), fullPage: true });
    assert.equal(await tool.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `horizontal overflow at ${width}`);
  }
  await tool.setViewportSize({ width: 870, height: 850 });


  if (liveTsp) {
    popup = await confirmation({ ...common, method: 'createCMSSignatureFromBase64' });
    await popup.locator('#approve').click(); answer = await result();
    assert.equal(answer.code, '200', answer.message);
    writeFileSync(join(folder, 'timestamped.p7s'), Buffer.from(answer.responseObject, 'base64'));
    await tool.locator('#nav-verify').click();
    await tool.locator('#document').setInputFiles(join(folder, 'timestamped.p7s'));
    await tool.locator('#verify-submit').click();
    await tool.locator('#result-title').filter({ hasText: 'Подпись верна' }).waitFor();
    assert.match(await tool.locator('#result-details').textContent(), /Метка времени:/);
    console.log('PASS: browser CAdES-T with live NUC TSA, then offline embedded timestamp verification');
  }
  const popupPage = await context.newPage();
  await popupPage.setViewportSize({ width: 400, height: 600 });
  await popupPage.goto(`chrome-extension://${extensionId}/index.html`);
  await popupPage.screenshot({ path: resolve('artifacts/popup.png'), fullPage: true });
  // Switching modes keeps the same shell and card positions, with navigation at the top.
  for (const width of [1280, 870, 400]) {
    await tool.setViewportSize({ width, height: 900 });
    await tool.locator('#nav-sign').click();
    const signBoxes = await Promise.all(['#workspace', '#local-controls', '#data-panel', '#signing-column'].map(selector => tool.locator(selector).boundingBox()));
    await tool.locator('#nav-verify').click();
    const verifyBoxes = await Promise.all(['#workspace', '#local-controls', '#data-panel', '#signing-column'].map(selector => tool.locator(selector).boundingBox()));
    for (let index = 0; index < signBoxes.length; index++) {
      for (const key of ['x', 'y', 'width']) assert.ok(Math.abs(signBoxes[index][key] - verifyBoxes[index][key]) <= 1, `mode layout shift ${width} ${index} ${key}: ${signBoxes[index][key]} vs ${verifyBoxes[index][key]}`);
    }
    assert.equal(await tool.locator('#cancel').isVisible(), false);
    const back = await tool.locator('#nav-back').boundingBox();
    assert.ok(back.y < 150 && back.x < width / 2, 'Back stays in upper left');
    await tool.evaluate(() => Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {}))));
    await tool.screenshot({ path: resolve(`artifacts/design-verify-${width}.png`), fullPage: true });
    await tool.locator('#nav-back').click();
    await tool.locator('#title').filter({ hasText: 'Подписать документ' }).waitFor();
    await tool.evaluate(() => Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {}))));
    await tool.screenshot({ path: resolve(`artifacts/design-sign-${width}.png`), fullPage: true });
  }
  await tool.emulateMedia({ reducedMotion: 'reduce' });
  await tool.locator('#nav-verify').click();
  assert.equal(await tool.evaluate(() => document.getAnimations().filter(animation => animation.playState === 'running').length), 0);
  await tool.emulateMedia({ reducedMotion: 'no-preference' });
  console.log('PASS: stable signing/verification layout at 1280/870/400, upper-left Back and reduced-motion preference');
  const toolId = await tool.evaluate(() => new Promise(resolve => chrome.tabs.getCurrent(tab => resolve(tab.id))));
  await popupPage.locator('#verify').click();
  await tool.waitForURL(`chrome-extension://${extensionId}/signing/approve.html?mode=verify`);
  assert.equal(await tool.evaluate(() => new Promise(resolve => chrome.tabs.getCurrent(tab => resolve(tab.id)))), toolId);
  console.log('PASS: launcher reuses existing local tool tab');
  await tool.goto(`chrome-extension://${extensionId}/index.html?workspace=1`);
  await tool.locator('#local').click();
  await tool.locator('#title').filter({ hasText: 'Подписать документ' }).waitFor();
  assert.equal(await tool.evaluate(() => new Promise(resolve => chrome.tabs.getCurrent(tab => resolve(tab.id)))), toolId);
  await tool.locator('#nav-home').click();
  await tool.locator('#verify').waitFor();
  console.log('PASS: home, sign and verify stay in one tab without separate windows');
  await tool.close();
  if (!popupPage.isClosed()) await popupPage.close();

  const opened = context.waitForEvent('page');
  await send(common);
  popup = await opened;
  await popup.waitForLoadState();
  await popup.close();
  answer = await result();
  assert.equal(answer.code, '500');
  console.log('PASS: closing confirmation cancels the operation');

  await send({ ...basics, args: { ...basics.args, signingParams: { tsaProfile: {} } } });
  answer = await result();
  assert.equal(answer.status, false);
  assert.match(answer.message, /Метка времени/);
  console.log('PASS: XML timestamp request fails explicitly (CMS timestamp supported)');

  const moduleKey = rsaFixture({ purpose: 'emailProtection' });
  for (const request of [
    { module: 'NURSign', type: 'xml', data: '<request>Госзакупки</request>' },
    { module: 'NURSign', type: 'multixml', data: ['<a/>','<b/>'] },
    { module: 'kz.sapa.eproc.osgi.EprocModule', method: 'signXml', uid: 'correlated-request', storageName: 'PKCS12', keyType: 'SIGN', xml: '<samruk/>' },
    { module: 'kz.qiwi.osgi.SecurityUtils', method: 'signXml', args: ['qiwi-call','<qiwi/>'] },
    { module: 'kz.rating1c.edo.signUtils', method: 'signXml', args: ['PKCS12','SIGNATURE','<rating/>','',''], uuid: 'rating-correlation' },
    { module: 'kz.uchet.signUtil.commonUtils', method: 'signXml', args: ['PKCS12','SIGNATURE','<uchet/>','',''] }
  ]) {
    popup = await confirmation(request, moduleKey);
    await popup.locator('#approve').click(); answer = await result();
    if (request.module === 'NURSign') { assert.equal(answer.errorCode, 'NONE'); assert.ok((Array.isArray(answer.result) ? answer.result : [answer.result]).every(xml => xml.includes('ds:SignatureValue'))); }
    else { assert.equal(answer.code, '200'); if (request.uid) assert.equal(answer.uid, request.uid); if (request.uuid) assert.equal(answer.uuid, request.uuid);
      if (request.module === 'kz.qiwi.osgi.SecurityUtils') { assert.equal(answer.responseObject.verificationResult, true); assert.equal(answer.responseObject.callID, 'qiwi-call'); } }
  }
  const binaryRequest = { module: 'NURSign', type: 'binary', data: data.toString('base64') };
  popup = await confirmation(binaryRequest, moduleKey); await popup.locator('#approve').click(); answer = await result();
  assert.equal(answer.errorCode, 'NONE');
  const verifiedModuleCms = await verifyCms(new Uint8Array(Buffer.from(answer.result, 'base64')), { detached: new Uint8Array(data) });
  assert.equal(verifiedModuleCms.valid, true); assert.equal(verifiedModuleCms.signers[0].cades, true); assert.equal(verifiedModuleCms.attached, false);
  if (liveTsp) {
    popup = await confirmation({ module: 'NURSign', type: 'text', data: data.toString('utf8') }, moduleKey);
    await popup.locator('#approve').click(); answer = await result(); assert.equal(answer.errorCode, 'NONE');
    const stamped = await verifyCms(new Uint8Array(Buffer.from(answer.result, 'base64')), { detached: new Uint8Array(data) });
    assert.equal(stamped.valid, true);
    assert.ok(stamped.signers[0].info.value.some(node => node.tagClass === 128 && node.type === 1));
    console.log('PASS: NURSign text keeps its mandatory NUC timestamp; CAdES signature verifies');
  }
  console.log('PASS: inspected Goszakup/Samruk/QIWI/Rating/Uchet protocols sign through isolated workers; NURSign detached CAdES verifies');

  const manager = await context.newPage();
  await manager.goto(`chrome-extension://${extensionId}/index.html?workspace=1`); await manager.locator('#modules').click();
  await manager.locator('[data-module="goszakup"]').waitFor();
  assert.equal(await manager.locator('[data-module]').count(), 8);
  await manager.locator('#filter').selectOption('all'); assert.equal(await manager.locator('.module').count(), 47);
  await manager.locator('#search').fill('ЭСФ'); assert.ok(await manager.locator('[data-unavailable]').count() >= 1);
  await manager.locator('#search').fill(''); await manager.locator('#filter').selectOption('available');
  const moduleCard = manager.locator('[data-module="goszakup"]');
  await moduleCard.getByLabel('Включить Госзакупки · NURSign').uncheck();
  await manager.locator('#status').filter({ hasText: 'сохранены' }).waitFor();
  await send(binaryRequest); answer = await result(); assert.equal(answer.errorCode, '400'); assert.match(answer.errorMessage, /выключен/);
  await moduleCard.getByLabel('Включить Госзакупки · NURSign').check();
  await manager.locator('#status').filter({ hasText: 'сохранены' }).waitFor();
  // Wait for the actual saved flag; the status text may repeat across updates.
  await manager.waitForFunction(async () => (await chrome.storage.local.get('moduleSettings')).moduleSettings.goszakup.enabled);
  popup = await confirmation(binaryRequest, moduleKey);
  await moduleCard.getByLabel('Включить Госзакупки · NURSign').uncheck();
  await manager.waitForFunction(async () => !(await chrome.storage.local.get('moduleSettings')).moduleSettings.goszakup.enabled);
  await popup.locator('#approve').click(); await popup.locator('#status[data-error]').filter({ hasText: 'выключен' }).waitFor();
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  await popup.locator('#cancel').click(); answer = await result(); assert.equal(answer.errorCode, '500');
  await moduleCard.getByLabel('Включить Госзакупки · NURSign').check();
  await manager.waitForFunction(async () => (await chrome.storage.local.get('moduleSettings')).moduleSettings.goszakup.enabled);
  await moduleCard.locator(':scope > details > summary').click();
  await moduleCard.locator('textarea').fill(`http://127.0.0.1:${port}`);
  await moduleCard.locator('select').selectOption('deny'); await moduleCard.locator('input[type="number"]').fill('1');
  await moduleCard.getByRole('button', { name: 'Сохранить настройки' }).click();
  await manager.waitForFunction(async () => (await chrome.storage.local.get('moduleSettings')).moduleSettings.goszakup.timestamp === 'deny');
  await send({ module: 'NURSign', type: 'text', data: 'test' }); answer = await result(); assert.match(answer.errorMessage, /обязательную метку/);
  await send({ module: 'NURSign', type: 'multixml', data: ['<a/>','<b/>'] }); answer = await result(); assert.match(answer.errorMessage, /Число/);
  await manager.reload(); await manager.locator('[data-module="goszakup"]').waitFor();
  await manager.locator('[data-module="goszakup"] > details > summary').click();
  assert.equal(await manager.locator('[data-module="goszakup"] select').inputValue(), 'deny');
  await manager.setViewportSize({ width: 400, height: 850 });
  assert.ok(await manager.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Module manager must fit mobile width');
  await manager.setViewportSize({ width: 1100, height: 900 });
  mkdirSync(resolve('artifacts'), { recursive: true }); await manager.screenshot({ path: resolve('artifacts/modules.png'), fullPage: true });
  await manager.getByRole('link', { name: '← На главную' }).click(); await manager.locator('#modules').waitFor();
  await manager.close();
  const preferences = await sw.evaluate(async () => (await chrome.storage.local.get('moduleSettings')).moduleSettings);
  assert.deepEqual(Object.keys(preferences), ['goszakup']); assert.ok(!JSON.stringify(preferences).includes(PASSWORD));
  await sw.evaluate(() => chrome.storage.local.clear()); moduleKey.container.fill(0);
  console.log('PASS: module manager catalog/search/mobile layout, persistent preferences, disabling and revoking pending signing, required timestamp and batch limits');

  // The eGov origin is intercepted by the local test route: no real portal
  // session, account or document is involved.
  const loginPage = await context.newPage(); await loginPage.goto('https://egov.kz/tegin-ui-test');
  const authUiKey = rsaFixture({ purpose: 'clientAuth' });
  const loginRequest = { module: 'kz.gov.pki.knca.basics', method: 'sign', args: { format: 'xml', data: '<login><client-type>PORTAL</client-type></login>', signingParams: {}, signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'], chain: [] } } };
  async function loginConfirmation(request) {
    const opened = context.waitForEvent('page');
    await loginPage.evaluate(request => {
      window.uiSocket = new WebSocket('wss://127.0.0.1:13579/');
      window.uiAnswer = new Promise(resolve => { window.uiSocket.onopen = () => window.uiSocket.send(JSON.stringify(request)); window.uiSocket.onmessage = event => resolve(JSON.parse(event.data)); });
    }, request);
    const approval = await opened; await approval.waitForLoadState(); return approval;
  }
  popup = await loginConfirmation(loginRequest);
  await popup.locator('#title').filter({ hasText: 'Вход на сайт' }).waitFor();
  assert.equal(await popup.locator('#preview').isVisible(), false);
  assert.equal(await popup.locator('#operation-details').getAttribute('open'), null);
  await popup.locator('#operation-details > summary').click();
  assert.match(await popup.locator('#preview').innerText(), /<login>/);
  await popup.locator('#operation-details > summary').click();
  await popup.locator('#key-file').setInputFiles({ name: 'public-ui-fixture.p12', mimeType: 'application/x-pkcs12', buffer: Buffer.from(authUiKey.container) });
  await popup.locator('#password').fill(PASSWORD); await popup.locator('#unlock').click();
  await popup.locator('#certificate:not([hidden])').waitFor();
  assert.match(await popup.locator('#cert-details').innerText(), /Действителен до/);
  assert.equal(await popup.locator('#cert-suitability').innerText(), 'Подходит для входа');
  assert.equal(await popup.locator('#cert-usage').isVisible(), false);
  await popup.locator('#certificate-technical > summary').click();
  assert.match(await popup.locator('#cert-usage').innerText(), /1\.3\.6\.1\.5\.5\.7\.3\.2/);
  await popup.locator('#certificate-technical > summary').click();
  await popup.screenshot({ path: resolve('artifacts/approval-simple.png'), fullPage: true });
  await popup.locator('#approve').click();
  const loginAnswer = await loginPage.evaluate(() => window.uiAnswer); assert.equal(loginAnswer.status, true);
  await loginPage.evaluate(() => window.uiSocket.close());
  popup = await loginConfirmation({ ...loginRequest, args: { ...loginRequest.args, data: '<login><client-type>PORTAL</client-type><amount>500</amount></login>' } });
  assert.equal(await popup.locator('#title').innerText(), 'Подписать документ');
  assert.equal(await popup.locator('#preview').isVisible(), true);
  assert.match(await popup.locator('#preview').innerText(), /<amount>500/);
  await popup.locator('#cancel').click(); await loginPage.evaluate(() => window.uiAnswer);
  await loginPage.close(); authUiKey.container.fill(0);
  console.log('PASS: concise known login summary and certificate details; extra XML fields retain full document preview');

  const previousMessages = await page.evaluate(() => window.bridgeMessages.join(''));
  popup = await confirmation(common);
  const closed = popup.waitForEvent('close');
  await page.reload();
  await closed;
  console.log('PASS: navigation invalidates a pending approval');

  const sensitive = previousMessages + await page.evaluate(() => window.bridgeMessages.join(''));
  assert.ok(!sensitive.includes(PASSWORD));
  assert.ok(network.every(url => url === 'https://egov.kz/tegin-ui-test' || url.startsWith(`http://127.0.0.1:${port}/`) || (liveTsp && url === 'http://tsp.pki.gov.kz/')), network.join('\n'));
  assert.deepEqual(errors, []);
  const stored = await sw.evaluate(async () => ({ local: await chrome.storage.local.get(null), session: await chrome.storage.session.get(null) }));
  assert.deepEqual(stored.local, {});
  assert.deepEqual(stored.session, {});
  console.log('PASS: network limited to local fixture and optional NUC TSA; no persistent keys or pending session data');
  console.log('Browser E2E completed.');
} finally {
  await context?.close();
  await new Promise(resolve => server.close(resolve));
  rmSync(folder, { recursive: true, force: true });
}
