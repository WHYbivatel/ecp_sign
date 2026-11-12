import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { rsaFixture, gostFixture, PASSWORD } from './helpers/fixtures.js';
import { syntheticTsa } from './helpers/tsa.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';
import { forge, oid, der } from '../extension/crypto/encoding.js';
import { SignedXml } from 'xml-crypto';
import { DOMParser } from '@xmldom/xmldom';
import { PDFDocument } from 'pdf-lib';

const folder = mkdtempSync(join(tmpdir(), 'ncabrowser-e2e-'));
const extension = resolve('dist/chromium');
const fixture = rsaFixture();
const gost = gostFixture();
const server = createServer((req, res) => {
  if (req.url === '/ncalayer-client.js') {
    res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
    return res.end(readFileSync(resolve('node_modules/ncalayer-js-client/ncalayer-client.js')));
  }
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
const liveTsp = process.env.NCA_LIVE_TSP === '1';
const TSA = 'http://tsp.pki.gov.kz/';
// The CAdES-T result is accepted only after the TSA certificate chain passes the revocation check.
const NCA_HOSTS = ['tsp.pki.gov.kz', 'ocsp.pki.gov.kz', 'crl.pki.gov.kz', 'crl1.pki.gov.kz', 'crl.root.gov.kz'];
const revocationUrl = url => /^https?:/.test(url) && NCA_HOSTS.slice(1).includes(new URL(url).host);
// crl.root.gov.kz answers a "page blocked" HTML for the HeadlessChrome user agent (2026-11-09).
const BROWSER_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';
try {
  context = await chromium.launchPersistentContext(join(folder, 'profile'), {
    executablePath, headless: true, viewport: { width: 620, height: 790 },
    // Without NCA_LIVE_TSP the real NUC names never resolve, even if a request escaped the route.
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`, '--no-first-run',
      ...(liveTsp ? [`--user-agent=${BROWSER_UA}`] : [`--host-resolver-rules=${NCA_HOSTS.map(host => `MAP ${host} ~NOTFOUND`).join(', ')}`])]
  });
  const errors = [];
  const network = [];
  let tsaStub = null, tsaRequests = 0, tsaStubbed = 0;
  context.on('page', page => page.on('pageerror', error => errors.push(error.message)));
  context.on('request', request => { if (/^https?:/.test(request.url())) network.push(request.url()); });
  await context.route('**/*', route => {
    const url = route.request().url();
    if (url === TSA) { tsaRequests++; if (tsaStub) { tsaStubbed++; return tsaStub(route); } }
    if (url === 'https://egov.kz/tegin-ui-test' || url === 'https://nca.pki.gov.kz/tegin-ui-test') return route.fulfill({ contentType: 'text/html; charset=utf-8', body: '<!doctype html><title>Tegin local UI fixture</title><h1>Artificial authentication request</h1>' });
    if (url.startsWith(`http://127.0.0.1:${port}/`) || url.startsWith('chrome-extension:') || (liveTsp && (url === 'http://tsp.pki.gov.kz/' || revocationUrl(url)))) route.continue();
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
  assert.deepEqual(answer, { code: '500', message: 'action.canceled' });
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

  // Tegin NCALayerService profiles in the test-chain configuration with TSA disabled
  // (chain: [], no tsaProfile): UTF-8/base64 challenge attached, then downloaded
  // document bytes detached. Production defaults are exercised further below.
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
  console.log('PASS: Tegin authChallenge (test-chain configuration, no TSA) bytes are returned as attached CMS and verified independently');

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
  console.log('PASS: Tegin document profile (test-chain configuration, TSA disabled) returns detached CMS; exact bytes pass, changed bytes fail');

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

  const pdfTool = await context.newPage();
  await pdfTool.goto(`chrome-extension://${extensionId}/signing/approve.html`);
  const pdfSource = await PDFDocument.create(); pdfSource.addPage().drawText('Tegin synthetic PDF for PAdES');
  const pdf = Buffer.from(await pdfSource.save());
  const choosePades = async (name, buffer) => {
    if (!await pdfTool.locator('#advanced-settings').evaluate(node => node.open)) await pdfTool.locator('#advanced-settings summary').click();
    if (await pdfTool.locator('#format').inputValue() !== 'pades') await pdfTool.locator('#format').selectOption('pades');
    await pdfTool.locator('#document').setInputFiles({ name, mimeType: 'application/pdf', buffer });
  };
  await pdfTool.locator('#document').setInputFiles({ name: 'contract.pdf', mimeType: 'application/pdf', buffer: pdf });
  await pdfTool.locator('#format-help').filter({ hasText: 'PAdES-B-B' }).waitFor();
  await choosePades('contract.pdf', pdf);
  await pdfTool.locator('#status').filter({ hasText: 'PDF готов к подписи' }).waitFor();
  assert.match(await pdfTool.locator('#operation').textContent(), /PAdES-B-B/);
  assert.match(await pdfTool.locator('#data-description').textContent(), /встроена в PDF \(1 стр\.\)/);
  await pdfTool.locator('#key-file').setInputFiles({ name: 'test.p12', mimeType: 'application/x-pkcs12', buffer: Buffer.from(fixture.container) });
  await pdfTool.locator('#password').fill(PASSWORD); await pdfTool.locator('#unlock').click();
  await pdfTool.locator('#certificate:not([hidden])').waitFor();
  await pdfTool.locator('#approve').click();
  await pdfTool.locator('#result-title').filter({ hasText: 'PDF подписан' }).waitFor();
  assert.equal(await pdfTool.locator('#download-label').textContent(), 'Скачать подписанный PDF');
  assert.equal(await pdfTool.locator('#verify-created').isVisible(), false);
  const pdfDownload = pdfTool.waitForEvent('download'); await pdfTool.locator('#download').click();
  const signedPdfFile = await pdfDownload;
  assert.equal(signedPdfFile.suggestedFilename(), 'contract.signed.pdf');
  const signedPdfPath = join(folder, 'contract.signed.pdf'); await signedPdfFile.saveAs(signedPdfPath);
  const signedPdf = readFileSync(signedPdfPath);
  const pdfText = signedPdf.toString('latin1');
  assert.match(pdfText, /\/SubFilter \/ETSI\.CAdES\.detached/);
  const [, , first, second, rest] = /\/ByteRange \[(\d+) (\d+) (\d+) (\d+) *\]/.exec(pdfText).map(Number);
  assert.equal(second + rest, signedPdf.length);
  const contents = Buffer.from(pdfText.slice(first + 1, second - 1), 'hex');
  const lengthOctets = contents[1] & 0x7f; let cmsLength = 0;
  for (let index = 0; index < lengthOctets; index++) cmsLength = cmsLength * 256 + contents[2 + index];
  writeFileSync(join(folder, 'pades.der'), contents.subarray(0, 2 + lengthOctets + cmsLength));
  writeFileSync(join(folder, 'pades-covered'), Buffer.concat([signedPdf.subarray(0, first), signedPdf.subarray(second)]));
  execFileSync('openssl', ['cms', '-verify', '-binary', '-inform', 'DER', '-in', join(folder, 'pades.der'), '-content', join(folder, 'pades-covered'),
    '-CAfile', join(folder, 'cert.pem'), '-purpose', 'any', '-out', '/dev/null'], { stdio: 'pipe' });
  console.log('PASS: local PAdES-B-B: format choice, PDF pre-check, approval, .signed.pdf download; embedded CMS over ByteRange verified by OpenSSL');
  if (process.env.DSS_VALIDATOR) {
    const [dssResult] = JSON.parse(execFileSync('java', ['-cp', `${process.env.DSS_VALIDATOR}/classes:${process.env.DSS_VALIDATOR}/lib/*`, 'Validate', signedPdfPath, join(folder, 'cert.pem')], { encoding: 'utf8' })).signatures;
    const [hankoResult] = JSON.parse(execFileSync('python3', [resolve('tests/independent_pades.py'), 'validate', signedPdfPath, join(folder, 'cert.pem')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })).signatures;
    assert.equal(dssResult.indication, 'TOTAL_PASSED', JSON.stringify(dssResult)); assert.equal(dssResult.format, 'PAdES-BASELINE-B');
    assert.ok(hankoResult.bottomLine && hankoResult.coverage === 'ENTIRE_FILE' && hankoResult.modificationLevel === 'NONE' && hankoResult.adesBasic === 'PASSED', JSON.stringify(hankoResult));
    console.log('PASS: PDF signed in the browser worker: EU DSS TOTAL_PASSED PAdES-BASELINE-B, pyHanko ENTIRE_FILE without modifications');
  }

  await pdfTool.locator('#again').click();
  await choosePades('contract.signed.pdf', signedPdf);
  await pdfTool.locator('#status[data-error]').filter({ hasText: 'уже содержит электронную подпись' }).waitFor();
  assert.equal(await pdfTool.locator('#unlock').isDisabled(), true);
  await choosePades('notes.txt', Buffer.from('not a pdf'));
  await pdfTool.locator('#status[data-error]').filter({ hasText: 'только для PDF' }).waitFor();
  // The key is chosen while the PDF pre-check may still run: the check must not be cancelled.
  await choosePades('contract.pdf', pdf);
  await pdfTool.locator('#key-file').setInputFiles({ name: 'gost.p12', mimeType: 'application/x-pkcs12', buffer: Buffer.from(gost.container) });
  await pdfTool.locator('#password').fill(PASSWORD); await pdfTool.locator('#unlock').click();
  await pdfTool.locator('#status[data-error]').filter({ hasText: 'только для ключей RSA' }).waitFor();
  assert.equal(await pdfTool.locator('#approve').isDisabled(), true);
  await pdfTool.close();
  console.log('PASS: PAdES refuses an already signed PDF, a non-PDF file and a GOST key with explicit messages');

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
    assert.match(await tool.locator('#result-details').textContent(), /Сертификат службы меток: не проверялся/);
    console.log('PASS: browser CAdES-T with live NUC TSA (TSA chain revocation checked before release), then offline embedded timestamp verification');
    await tool.locator('#again').click();
    await tool.locator('#document').setInputFiles(join(folder, 'timestamped.p7s'));
    await tool.locator('#check-revocation').check();
    await tool.locator('#verify-submit').click();
    await tool.locator('#result-title').filter({ hasText: 'Подпись верна' }).waitFor({ timeout: 60000 });
    assert.match(await tool.locator('#result-details').textContent(), /Сертификат службы меток: не отозван по актуальным данным/);
    console.log('PASS: live NUC OCSP and root CRL from the extension worker: the public TSA certificate chain is not revoked');
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

  // Portal compatibility. Requests come from tests/fixtures/portals; the portal
  // origins are served by the local route, so no real portal, account or NUC key is used.
  const portal = name => JSON.parse(readFileSync(resolve(`tests/fixtures/portals/${name}.json`), 'utf8'));
  const egovLogin = portal('egov-login'), nucCabinet = portal('nuc-cabinet-login');
  const unlock = async (approval, key) => {
    await approval.locator('#key-file').setInputFiles({ name: 'disposable-test.p12', mimeType: 'application/x-pkcs12', buffer: Buffer.from(key.container) });
    await approval.locator('#password').fill(PASSWORD); await approval.locator('#unlock').click();
  };
  const verifyXml = (xml, certificate) => {
    const verifier = new SignedXml({ publicCert: certificate, getCertFromKeyInfo: () => null });
    verifier.loadSignature(new DOMParser().parseFromString(xml, 'application/xml').getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0]);
    return verifier.checkSignature(xml);
  };

  // Tegin EDO profiles of commit 2961da5 as reported by the repository owner (the
  // code is not available here). Production defaults send no chain, so only the
  // bundled NUC roots apply; the document profile also requires a NUC timestamp.
  const teginLogin = portal('tegin-edo-login'), teginDocument = portal('tegin-edo-document-sign'), teginTestChain = portal('tegin-edo-test-chain');
  const edoAuthKey = rsaFixture({ purpose: 'clientAuth' }), edoSignKey = rsaFixture({ purpose: 'emailProtection' });
  const siteWaiting = () => page.evaluate(() => Promise.race([window.result.then(() => 'answered'), new Promise(resolve => setTimeout(() => resolve('pending'), 300))]));
  const tsaBefore = tsaRequests;
  let edoWindow;
  for (const [profile, key] of [[teginLogin, edoAuthKey], [teginDocument, edoSignKey]]) {
    edoWindow = context.waitForEvent('page');
    await send(profile.request);
    popup = await edoWindow;
    await popup.locator('#origin').filter({ hasText: `http://127.0.0.1:${port}` }).waitFor();
    assert.equal(await popup.locator('#timestamp-note').isVisible(), profile === teginDocument, `${profile.portal}: timestamp note`);
    await unlock(popup, key);
    await popup.locator('#status[data-error]').filter({ hasText: 'доверенную цепочку' }).waitFor({ timeout: 15000 });
    assert.equal(await popup.locator('#approve').isDisabled(), true);
    assert.equal(await siteWaiting(), 'pending', `${profile.portal}: the site receives nothing while the certificate is refused`);
    await popup.locator('#cancel').click();
    assert.deepEqual(await result(), { status: true, body: {} });
  }
  assert.equal(tsaRequests, tsaBefore, 'a refused certificate never reaches the TSA');
  console.log('PASS: Tegin EDO production login and document profiles (2961da5, owner-reported; no chain) refuse a certificate outside the NUC chain before any TSA request');

  // Test-chain configuration with the default TSA (chain: [], tsaProfile: {}): the
  // signature is computed, but every TSA failure must keep it from the site.
  const localTsa = syntheticTsa();
  const reply = body => ({ status: 200, contentType: 'application/timestamp-reply', body });
  const tsaFailures = [
    ['unreachable TSA', route => route.abort('connectionrefused'), /недоступна/],
    ['HTML instead of a timestamp reply', route => route.fulfill({ status: 200, contentType: 'text/html', body: '<html></html>' }), /неожиданный ответ/],
    ['malformed timestamp reply', route => route.fulfill(reply(Buffer.from([0x30, 0x82, 0xff, 0xff, 0x01]))), /./],
    ['rejection status', route => route.fulfill(reply(Buffer.from([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02]))), /не выдал/],
    ['well-formed reply from a TSA outside the NUC chain', route => route.fulfill(reply(Buffer.from(localTsa.reply(route.request().postDataBuffer())))), /службы меток времени не прошёл проверку/]
  ];
  edoWindow = context.waitForEvent('page');
  await send(teginTestChain.requests.documentSignTsa);
  popup = await edoWindow;
  await popup.locator('#origin').filter({ hasText: `http://127.0.0.1:${port}` }).waitFor();
  assert.equal(await popup.locator('#timestamp-note').isVisible(), true);
  for (const [name, handler, message] of tsaFailures) {
    tsaStub = handler;
    await unlock(popup, edoSignKey);
    await popup.locator('#certificate:not([hidden])').waitFor({ timeout: 15000 });
    const before = tsaStubbed;
    await popup.locator('#approve').click();
    await popup.locator('#status[data-error]').waitFor({ timeout: 30000 });
    assert.match(await popup.locator('#status').innerText(), message, name);
    assert.equal(tsaStubbed, before + 1, `${name}: exactly one TSA request`);
    assert.equal(await siteWaiting(), 'pending', `${name}: no unstamped signature reaches the site`);
  }
  tsaStub = null;
  await popup.locator('#cancel').click();
  assert.deepEqual(await result(), { status: true, body: {} });
  localTsa.destroy();
  if (liveTsp) {
    // Explicit only (NCA_LIVE_TSP=1): disposable key and synthetic document.
    popup = await confirmation(teginTestChain.requests.documentSignTsa, edoSignKey);
    await popup.locator('#approve').click(); answer = await result();
    assert.equal(answer.status, true, answer.message);
    const stampedEdo = await verifyCms(new Uint8Array(Buffer.from(answer.body.result[0], 'base64')), { detached: new Uint8Array(Buffer.from(teginTestChain.requests.documentSignTsa.args.data, 'base64')) });
    assert.equal(stampedEdo.valid, true);
    assert.ok(stampedEdo.signers[0].info.value.some(node => node.tagClass === 128 && node.type === 1));
    console.log('PASS: live NUC TSA: Tegin EDO test-chain document profile returns a detached CAdES-T');
  }
  edoAuthKey.container.fill(0); edoSignKey.container.fill(0);
  console.log('PASS: Tegin EDO document profile with tsaProfile {}: unreachable, HTML, malformed, rejected and non-NUC TSA replies keep the unstamped signature from the site');

  // SIGEX ncalayer-js-client 1.6.1: waits for the greeting, probes KAZTOKEN, then uses basics and commonUtils.
  const clientPage = await context.newPage();
  await clientPage.goto(`http://127.0.0.1:${port}/sigex-client`);
  await clientPage.addScriptTag({ url: `http://127.0.0.1:${port}/ncalayer-client.js` });
  const connected = await clientPage.evaluate(async () => {
    window.client = new NCALayerClient('wss://127.0.0.1:13579', false);
    window.settle = promise => { window.pending = promise.then(value => ({ value }), error => ({ error: error.message, cancelled: error.canceledByUser === true })); };
    const version = await client.connect();
    return { version, kmd: client.isKmd, tokens: await client.getActiveTokens() };
  });
  assert.deepEqual(connected, { version: '1.4', kmd: false, tokens: [] });
  const clientResult = () => clientPage.evaluate(() => window.pending);
  let nextPage = context.waitForEvent('page');
  await clientPage.evaluate(xml => settle(client.basicsSignXML(['PKCS12', 'AKKaztokenStore', 'AKKZIDCardStore'], xml, NCALayerClient.basicsXMLParams, NCALayerClient.basicsSignerTestAny)), egovLogin.request.args.data);
  popup = await nextPage;
  await popup.locator('#origin').filter({ hasText: `http://127.0.0.1:${port}` }).waitFor();
  await unlock(popup, fixture); await popup.locator('#certificate:not([hidden])').waitFor({ timeout: 15000 });
  await popup.locator('#approve').click();
  const clientXml = await clientResult();
  assert.ok(Array.isArray(clientXml.value) && clientXml.value.length === 1, JSON.stringify(clientXml).slice(0, 200));
  assert.ok(clientXml.value[0].startsWith('<?xml version="1.0" encoding="UTF-8"?>'));
  assert.equal(verifyXml(clientXml.value[0], fixture.certificate), true);
  assert.throws(() => { if (!verifyXml(clientXml.value[0].replace('PORTAL', 'CHANGED'), fixture.certificate)) throw new Error('invalid'); });

  const parts = [Buffer.from('Первый синтетический документ ЭДО'), Buffer.from('%PDF-1.4\nsecond synthetic document\n')];
  nextPage = context.waitForEvent('page');
  await clientPage.evaluate(parts => settle(client.basicsSignCMS(NCALayerClient.basicsStoragePKCS12,
    parts.map(part => Uint8Array.from(atob(part), char => char.charCodeAt(0)).buffer), NCALayerClient.basicsCMSParamsDetachedNoTSP, NCALayerClient.basicsSignerTestAny)), parts.map(part => part.toString('base64')));
  popup = await nextPage;
  await unlock(popup, fixture); await popup.locator('#certificate:not([hidden])').waitFor({ timeout: 15000 });
  await popup.locator('#approve').click();
  const clientCms = await clientResult();
  assert.equal(clientCms.value?.length, 2, JSON.stringify(clientCms).slice(0, 200));
  writeFileSync(join(folder, 'client-cert.pem'), fixture.certificate);
  for (const [index, part] of parts.entries()) {
    writeFileSync(join(folder, `client-${index}.p7s`), Buffer.from(clientCms.value[index], 'base64'));
    writeFileSync(join(folder, `client-${index}.bin`), part);
    const changed = Buffer.from(part); changed[0] ^= 1; writeFileSync(join(folder, `client-${index}-changed.bin`), changed);
    const verifyDetached = content => execFileSync('openssl', ['cms', '-verify', '-binary', '-inform', 'DER', '-in', join(folder, `client-${index}.p7s`), '-content', join(folder, content), '-CAfile', join(folder, 'client-cert.pem'), '-purpose', 'any', '-out', join(folder, 'client-out')], { stdio: 'pipe' });
    verifyDetached(`client-${index}.bin`);
    assert.throws(() => verifyDetached(`client-${index}-changed.bin`));
  }
  assert.throws(() => execFileSync('openssl', ['cms', '-verify', '-binary', '-inform', 'DER', '-in', join(folder, 'client-0.p7s'), '-content', join(folder, 'client-1.bin'), '-CAfile', join(folder, 'client-cert.pem'), '-purpose', 'any', '-out', join(folder, 'client-out')], { stdio: 'pipe' }), 'each signature covers its own document');

  nextPage = context.waitForEvent('page');
  await clientPage.evaluate(data => settle(client.createCAdESFromBase64('PKCS12', data, 'SIGNATURE', true)), data.toString('base64'));
  popup = await nextPage;
  await unlock(popup, fixture); await popup.locator('#certificate:not([hidden])').waitFor({ timeout: 15000 });
  await popup.locator('#approve').click();
  const clientCades = await clientResult();
  writeFileSync(join(folder, 'client-cades.p7s'), Buffer.from(clientCades.value, 'base64'));
  execFileSync('openssl', ['cms', '-verify', '-cades', '-binary', '-inform', 'DER', '-in', join(folder, 'client-cades.p7s'), '-CAfile', join(folder, 'client-cert.pem'), '-purpose', 'any', '-out', join(folder, 'client-cades.bin')], { stdio: 'pipe' });
  assert.deepEqual(readFileSync(join(folder, 'client-cades.bin')), data);

  nextPage = context.waitForEvent('page');
  await clientPage.evaluate(xml => settle(client.basicsSignXML(NCALayerClient.basicsStoragePKCS12, xml, NCALayerClient.basicsXMLParams, NCALayerClient.basicsSignerTestAny)), egovLogin.request.args.data);
  popup = await nextPage; await popup.waitForLoadState();
  await popup.locator('#cancel').click();
  const clientCancel = await clientResult();
  assert.equal(clientCancel.cancelled, true, JSON.stringify(clientCancel));

  const unexpectedWindows = [];
  const recordWindow = item => unexpectedWindows.push(item.url());
  context.on('page', recordWindow);
  await clientPage.evaluate(() => settle(client.getKeyInfo('AKKaztokenStore')));
  assert.match((await clientResult()).error, /^500: /);
  await clientPage.evaluate(xml => settle(client.basicsSignXML(NCALayerClient.basicsStoragePKCS12, xml, { tsaProfile: {} }, NCALayerClient.basicsSignerTestAny)), egovLogin.request.args.data);
  assert.match((await clientResult()).error, /^UNSUPPORTED_OR_FAILED: Метка времени/);
  await clientPage.evaluate(() => settle(client.basicsSignXML(['AKKaztokenStore'], '<a/>', {}, NCALayerClient.basicsSignerTestAny)));
  assert.match((await clientResult()).error, /PKCS#12/);
  await clientPage.evaluate(() => settle(client.getActiveTokens()));
  assert.deepEqual((await clientResult()).value, [], 'the client connection keeps working after errors');
  context.off('page', recordWindow);
  assert.deepEqual(unexpectedWindows, [], 'unsupported requests must not open an approval window');
  await clientPage.close();
  console.log('PASS: SIGEX ncalayer-js-client 1.6.1: greeting and KAZTOKEN probe, eGov XML, two detached CMS, attached CAdES verified by OpenSSL, cancel, unsupported methods without a window');

  // eGov client code (public bundle 4250-251581e72057e301.js): a new socket per
  // operation, send in onopen, continue only when body.result is non-empty.
  const authKey = rsaFixture({ purpose: 'clientAuth' });
  const egovPage = await context.newPage(); await egovPage.goto('https://egov.kz/tegin-ui-test');
  nextPage = context.waitForEvent('page');
  await egovPage.evaluate(signInfo => {
    window.egovEvents = []; window.egovSigned = [];
    const edsEventFn = ({ signInfo, onMessageEvent }) => {
      const socket = new WebSocket('wss://127.0.0.1:13579/');
      socket.onopen = () => { socket.send(signInfo); };
      socket.onmessage = event => {
        if (event.data === 'reload') return;
        const response = JSON.parse(event.data); window.egovEvents.push(response);
        if (response.body?.result?.length) onMessageEvent(response);
      };
      socket.onclose = event => { if (!event.wasClean) window.egovEvents.push('interrupted'); };
    };
    edsEventFn({ signInfo, onMessageEvent: response => window.egovSigned.push(response.body.result[0]) });
  }, JSON.stringify(egovLogin.request));
  popup = await nextPage;
  await popup.locator('#origin').filter({ hasText: 'https://egov.kz' }).waitFor();
  await popup.locator('#title').filter({ hasText: 'Вход на сайт' }).waitFor();
  await unlock(popup, authKey);
  await popup.locator('#status[data-error]').filter({ hasText: 'доверенную цепочку' }).waitFor({ timeout: 15000 });
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  assert.deepEqual(await egovPage.evaluate(() => window.egovEvents), []);
  await popup.locator('#cancel').click();
  await egovPage.waitForFunction(() => window.egovEvents.length === 1);
  assert.deepEqual(await egovPage.evaluate(() => [window.egovEvents, window.egovSigned]), [[{ status: true, body: {} }], []]);
  await egovPage.close();
  console.log('PASS: exact eGov login request: a certificate outside the NUC chain is refused, cancel leaves the eGov callback untouched');

  // NUC cabinet signature-basics.js: one socket reused between attempts, twelve
  // published CA certificates as chain, alert(code) on status=false.
  const nucPage = await context.newPage(); await nucPage.goto('https://nca.pki.gov.kz/tegin-ui-test');
  await nucPage.evaluate(signInfo => {
    window.nucEvents = []; window.nucAlerts = []; window.nucSockets = 0; window.nucSignature = null;
    function connect() {
      if (connect.webSocket && connect.webSocket.readyState < 2) return Promise.resolve(connect.webSocket);
      return new Promise((resolve, reject) => {
        connect.webSocket = new WebSocket('wss://127.0.0.1:13579/'); window.nucSockets++;
        connect.webSocket.onopen = () => resolve(connect.webSocket);
        connect.webSocket.onerror = reject;
      });
    }
    window.nucSign = () => connect().then(webSocket => {
      webSocket.send(JSON.stringify(signInfo));
      return new Promise(resolve => {
        webSocket.onmessage = ({ data }) => {
          const response = JSON.parse(data); window.nucEvents.push(response);
          if (response.status === true && response.body && Object.hasOwn(response.body, 'result')) window.nucSignature = response.body.result;
          else if (response.status === false) window.nucAlerts.push(response.code);
          resolve(response);
        };
      });
    });
  }, nucCabinet.request);
  nextPage = context.waitForEvent('page');
  await nucPage.evaluate(() => { window.nucRun = nucSign(); });
  popup = await nextPage;
  await popup.locator('#origin').filter({ hasText: 'https://nca.pki.gov.kz' }).waitFor();
  await popup.locator('#title').filter({ hasText: 'Подтверждение на сайте НУЦ' }).waitFor();
  await unlock(popup, authKey);
  await popup.locator('#status[data-error]').filter({ hasText: 'доверенную цепочку' }).waitFor({ timeout: 15000 });
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  await popup.locator('#cancel').click();
  assert.deepEqual(await nucPage.evaluate(() => window.nucRun), { status: true, body: {} });
  nextPage = context.waitForEvent('page');
  await nucPage.evaluate(() => { window.nucRun = nucSign(); });
  popup = await nextPage; await popup.waitForLoadState();
  await popup.close();
  assert.deepEqual(await nucPage.evaluate(() => window.nucRun), { status: true, body: {} });
  assert.deepEqual(await nucPage.evaluate(() => [window.nucSockets, window.nucSignature, window.nucAlerts]), [1, null, []]);
  await nucPage.close(); authKey.container.fill(0);
  console.log('PASS: exact NUC cabinet request: twelve published CAs do not trust a foreign certificate, the reused socket serves a second attempt, cancel and window close reach the page');

  // Responses stay bound to the frame and operation that asked; limits and timeout are explicit.
  const framePage = await context.newPage(); await framePage.goto(`http://127.0.0.1:${port}/frames`);
  await framePage.evaluate(() => new Promise(resolve => { const frame = document.createElement('iframe'); frame.src = '/frame'; frame.onload = resolve; document.body.append(frame); }));
  const child = framePage.frames().find(frame => frame.url().endsWith('/frame'));
  const openSocket = (target, request) => target.evaluate(request => {
    window.answers ||= [];
    const socket = new WebSocket('wss://127.0.0.1:13579/');
    socket.onopen = () => socket.send(JSON.stringify(request));
    socket.onmessage = event => window.answers.push(JSON.parse(event.data));
    socket.onclose = event => window.answers.push({ closed: event.code });
  }, request);
  const answers = target => target.evaluate(() => window.answers || []);
  const frameRequest = text => ({ module: basics.module, method: 'sign', args: { allowedStorages: ['PKCS12'], format: 'xml', data: `<frame-test>${text}</frame-test>`, signingParams: {}, signerParams: { extKeyUsageOids: [], chain: [] } } });
  nextPage = context.waitForEvent('page');
  await openSocket(framePage, frameRequest('top'));
  const topPopup = await nextPage; await topPopup.waitForLoadState();
  await openSocket(framePage, frameRequest('second top'));
  await framePage.waitForFunction(() => window.answers?.length === 1);
  const busy = (await answers(framePage))[0];
  assert.equal(busy.status, false); assert.match(busy.message, /Уже есть ожидающий запрос/);
  nextPage = context.waitForEvent('page');
  await openSocket(child, frameRequest('child'));
  const childPopup = await nextPage;
  await childPopup.locator('#preview').filter({ hasText: '<frame-test>child</frame-test>' }).waitFor({ state: 'attached' });
  await unlock(childPopup, fixture); await childPopup.locator('#certificate:not([hidden])').waitFor({ timeout: 15000 });
  await childPopup.locator('#approve').click();
  await child.waitForFunction(() => window.answers?.length === 1);
  const childAnswer = (await answers(child))[0];
  assert.equal(childAnswer.status, true); assert.match(childAnswer.body.result[0], /^<frame-test>child<ds:Signature/);
  assert.equal(verifyXml(childAnswer.body.result[0], fixture.certificate), true);
  assert.equal((await answers(framePage)).length, 1, 'the top frame must not receive the child frame response');
  const topClosed = topPopup.waitForEvent('close', { timeout: 90000 });
  await sw.evaluate(async () => {
    const [key, record] = Object.entries(await chrome.storage.session.get(null)).find(([name]) => name.startsWith('pending:'));
    await chrome.storage.session.set({ [key]: { ...record, expires: Date.now() - 1 } });
    await chrome.alarms.create(key, { when: Date.now() + 50 });
  });
  try { await topClosed; } catch (error) {
    console.error('timeout diagnostic', JSON.stringify(await sw.evaluate(async () => ({ alarms: await chrome.alarms.getAll(), session: Object.keys(await chrome.storage.session.get(null)), now: Date.now() }))), JSON.stringify(await answers(framePage)), topPopup.isClosed());
    throw error;
  }
  await framePage.waitForFunction(() => window.answers.length === 2);
  assert.deepEqual((await answers(framePage))[1], { status: true, body: {} });
  assert.equal((await answers(child)).length, 1);
  await framePage.evaluate(request => {
    window.doubled = [];
    const socket = new WebSocket('wss://127.0.0.1:13579/');
    socket.onopen = () => { socket.send(JSON.stringify(request)); socket.send(JSON.stringify(request)); };
    socket.onmessage = event => window.doubled.push(JSON.parse(event.data));
    socket.onclose = event => window.doubled.push({ closed: event.code });
  }, frameRequest('doubled'));
  await framePage.waitForFunction(() => window.doubled.length === 1);
  assert.deepEqual(await framePage.evaluate(() => window.doubled), [{ closed: 1008 }]);
  const noPending = () => sw.evaluate(() => new Promise(resolve => { const check = async () => Object.keys(await chrome.storage.session.get(null)).some(key => key.startsWith('pending:')) ? setTimeout(check, 100) : resolve(); check(); }));
  await noPending();
  // A request that expired without its alarm firing is ended by the next request, and its window closes.
  nextPage = context.waitForEvent('page');
  await framePage.evaluate(request => {
    window.stale = [];
    const socket = new WebSocket('wss://127.0.0.1:13579/');
    socket.onopen = () => socket.send(JSON.stringify(request));
    socket.onmessage = event => window.stale.push(JSON.parse(event.data));
  }, frameRequest('stale'));
  const stalePopup = await nextPage;
  const staleClosed = stalePopup.waitForEvent('close');
  await sw.evaluate(() => new Promise(resolve => {
    const expire = async () => {
      const found = Object.entries(await chrome.storage.session.get(null)).find(([key, record]) => key.startsWith('pending:') && record.windowId);
      if (!found) return setTimeout(expire, 100);
      await chrome.alarms.clear(found[0]);
      await chrome.storage.session.set({ [found[0]]: { ...found[1], expires: Date.now() - 1 } });
      resolve();
    };
    expire();
  }));
  nextPage = context.waitForEvent('page');
  await openSocket(child, frameRequest('after stale'));
  const freshPopup = await nextPage;
  await staleClosed;
  await framePage.waitForFunction(() => window.stale.length === 1);
  assert.deepEqual(await framePage.evaluate(() => window.stale[0]), { status: true, body: {} });
  await freshPopup.close();
  await noPending();
  await openSocket(child, frameRequest('closing tab'));
  const orphanId = await sw.evaluate(() => new Promise(resolve => {
    const check = async () => { const found = Object.entries(await chrome.storage.session.get(null)).find(([key, record]) => key.startsWith('pending:') && record.windowId && JSON.stringify(record.request).includes('closing tab')); found ? resolve(found[1].id) : setTimeout(check, 100); };
    check();
  }));
  let orphan;
  for (let attempt = 0; attempt < 150 && !orphan; attempt++) { orphan = context.pages().find(item => item.url().endsWith(`#${orphanId}`)); if (!orphan) await new Promise(resolve => setTimeout(resolve, 100)); }
  assert.ok(orphan, 'approval window for the closing tab request');
  const orphanClosed = orphan.waitForEvent('close');
  await framePage.close();
  try { await orphanClosed; } catch (error) {
    console.error('tab-close diagnostic', JSON.stringify(await sw.evaluate(async id => {
      const pendingKeys = Object.keys(await chrome.storage.session.get(null)).filter(key => key.startsWith('pending:'));
      const windows = (await chrome.windows.getAll({ populate: true })).map(item => ({ id: item.id, type: item.type, tabs: item.tabs.map(tab => tab.url?.split('#')[1] === id ? 'orphan' : 'other') }));
      return { pendingKeys, windows };
    }, orphanId)));
    throw error;
  }
  console.log('PASS: frame binding: the child response reaches only the child, one pending request per frame, timeout returns a basics cancel and closes the window, a second send on one socket closes it, an expired request ended by the next one closes its window, closing the tab closes the approval');

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
  // ncalayer-js-client probes the KAZTOKEN HTTP API itself; the route aborts that request.
  const allowed = ['https://egov.kz/tegin-ui-test', 'https://nca.pki.gov.kz/tegin-ui-test', 'https://127.0.0.1:24680/'];
  assert.ok(network.every(url => allowed.includes(url) || url.startsWith(`http://127.0.0.1:${port}/`) || (url === TSA && (liveTsp || tsaStubbed > 0)) || (liveTsp && revocationUrl(url))), network.join('\n'));
  if (!liveTsp) assert.ok(!network.some(revocationUrl), 'synthetic keys outside pinned NUC chains never reach revocation services');
  if (!liveTsp) assert.equal(tsaRequests, tsaStubbed, 'every TSA request outside NCA_LIVE_TSP was served by a local stub');
  assert.deepEqual(errors, []);
  const stored = await sw.evaluate(async () => ({ local: await chrome.storage.local.get(null), session: await chrome.storage.session.get(null) }));
  assert.deepEqual(stored.local, {});
  // Session keeps only the per-tab request log: names, fixed reasons and argument structure, never values.
  const logged = Object.entries(stored.session);
  assert.ok(logged.length && logged.every(([key]) => /^diagnostic:\d+$/.test(key)), Object.keys(stored.session).join(', '));
  const structure = value => typeof value === 'string' ? /^(string|empty|number|boolean|null|undefined|object|array\(\d+\))$/.test(value)
    : Array.isArray(value) ? value.every(structure) : Object.entries(value).every(([key, item]) => key === 'array' ? Number.isInteger(item) : structure(item));
  for (const entry of logged.flatMap(([, list]) => list)) {
    assert.deepEqual(Object.keys(entry).sort(), ['args', 'at', 'class', 'code', 'method', 'module', 'reason', 'stage']);
    assert.ok(structure(entry.args), JSON.stringify(entry.args));
  }
  assert.ok(!JSON.stringify(stored.session).includes(PASSWORD));
  console.log('PASS: network limited to local fixture and optional NUC TSA; no persistent keys or pending session data; the request log holds structure only');
  console.log('Browser E2E completed.');
} finally {
  await context?.close();
  await new Promise(resolve => server.close(resolve));
  rmSync(folder, { recursive: true, force: true });
}
