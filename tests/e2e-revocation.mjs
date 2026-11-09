import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { forge } from '../extension/crypto/encoding.js';
import { syntheticPki, ocspResponse, parseOcspRequest, crl, serialHex, fingerprintOf } from './helpers/pki.js';
import { PASSWORD } from './helpers/fixtures.js';

// Revocation checks in the built extension. A separate test build maps the synthetic CAs to the
// pinned NCA URLs; every such URL is served by a local route and the real hosts never resolve.
const folder = mkdtempSync(join(tmpdir(), 'tegin-revocation-e2e-'));
const pki = syntheticPki();
const { root: rootCa, ca, leaf, responder } = pki;
const container = key => new Uint8Array(Buffer.from(forge.asn1.toDer(forge.pkcs12.toPkcs12Asn1(key.privateKey, [key.certificate, ca.certificate], PASSWORD, { algorithm: '3des' })).getBytes(), 'binary'));
const leafKey = container(leaf);
const testIssuers = { [await fingerprintOf(ca)]: { like: 'nca_rsa_2022', name: 'Tegin synthetic CA' }, [await fingerprintOf(rootCa)]: { like: 'root' } };
execFileSync('node', ['scripts/build.mjs'], { stdio: 'pipe', env: { ...process.env, TEGIN_TEST_REVOCATION_ISSUERS: JSON.stringify(testIssuers), TEGIN_DIST: join(folder, 'build') } });
const extension = join(folder, 'build', 'chromium');

const OCSP = 'http://ocsp.pki.gov.kz/', ROOT_CRL = 'https://crl.root.gov.kz/rsa2020.crl';
const CA_CRLS = ['https://crl.pki.gov.kz/nca_rsa_2022.crl', 'https://crl1.pki.gov.kz/nca_rsa_2022.crl'];
const DELTAS = ['https://crl.pki.gov.kz/nca_d_rsa_2022.crl', 'https://crl1.pki.gov.kz/nca_d_rsa_2022.crl'];
const NCA_HOSTS = ['tsp.pki.gov.kz', 'ocsp.pki.gov.kz', 'crl.pki.gov.kz', 'crl1.pki.gov.kz', 'crl.root.gov.kz'];

const server = createServer((req, res) => { res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end('<!doctype html><title>Tegin revocation fixture</title><h1>Synthetic site</h1>'); });
await new Promise(done => server.listen(0, '127.0.0.1', done));
const port = server.address().port;

let mode = {}, held = null;
const requests = [];
const reset = (next = {}) => { mode = { ocsp: 'good', caCrl: 'good', delta: 'good', root: 'good', ...next }; requests.length = 0; };
reset();
const fulfill = (route, body, contentType) => route.fulfill({ status: 200, contentType, body: Buffer.from(body) });
async function revocationRoute(route, url) {
  requests.push(url);
  if (url === OCSP) {
    const answer = async status => {
      if (status === 'down') return route.abort('connectionrefused');
      const parsed = parseOcspRequest(new Uint8Array(route.request().postDataBuffer()));
      return fulfill(route, ocspResponse(parsed, { signer: responder, status, revocationTime: Date.now() - 3600000, reason: 1 }), 'application/ocsp-response');
    };
    if (mode.ocsp === 'hold') { held = { release: status => answer(status).catch(error => error) }; return; }
    return answer(mode.ocsp);
  }
  if (url === ROOT_CRL) return mode.root === 'down' ? route.abort('connectionrefused') : fulfill(route, crl(rootCa), 'application/pkix-crl');
  if (CA_CRLS.includes(url)) return mode.caCrl === 'down' ? route.abort('connectionrefused') : fulfill(route, crl(ca, { number: 7, entries: mode.caCrl === 'revoked' ? [{ serial: serialHex(leaf), reason: 1 }] : [] }), 'application/octet-stream');
  if (DELTAS.includes(url)) return mode.delta === 'down' ? route.abort('connectionrefused') : fulfill(route, crl(ca, { number: 8, deltaBase: 7 }), 'application/octet-stream');
  return route.abort();
}

let context;
try {
  context = await chromium.launchPersistentContext(join(folder, 'profile'), {
    executablePath: process.env.CHROMIUM_EXECUTABLE || chromium.executablePath(), headless: true, viewport: { width: 870, height: 900 },
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`, '--no-first-run', `--host-resolver-rules=${NCA_HOSTS.map(host => `MAP ${host} ~NOTFOUND`).join(', ')}`]
  });
  const errors = [], escaped = [];
  context.on('page', page => page.on('pageerror', error => errors.push(error.message)));
  await context.route('**/*', route => {
    const url = route.request().url();
    if (url.startsWith(`http://127.0.0.1:${port}/`) || url.startsWith('chrome-extension:')) return route.continue();
    if (NCA_HOSTS.some(host => new URL(url).host === host)) return revocationRoute(route, url);
    escaped.push(url); return route.abort();
  });
  const sw = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  const extensionId = new URL(sw.url()).host;
  assert.match((await sw.evaluate(() => chrome.runtime.getManifest().name)), /test revocation build/);
  const page = await context.newPage();
  await page.goto(`http://127.0.0.1:${port}/`);
  await page.evaluate(() => new Promise((done, fail) => { window.socket = new WebSocket('wss://127.0.0.1:13579'); window.socket.onmessage = () => done(); window.socket.onerror = fail; }));
  const request = { module: 'kz.gov.pki.knca.basics', method: 'sign', args: { allowedStorages: ['PKCS12'], format: 'xml', data: '<login><nonce>revocation</nonce></login>', signingParams: {},
    signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'], chain: [rootCa.pem] } } };
  async function open(next, { submit = true, keepCache = false } = {}) {
    if (!keepCache) await sw.evaluate(() => caches.delete('tegin-crl-v1'));
    reset(next);
    const opened = context.waitForEvent('page');
    await page.evaluate(message => { window.answer = new Promise(done => { window.socket.onmessage = event => done(JSON.parse(event.data)); }); window.socket.send(JSON.stringify(message)); }, request);
    const popup = await opened;
    await popup.waitForURL(`chrome-extension://${extensionId}/signing/approve.html#*`);
    await popup.locator('#revocation-network-note').waitFor();
    await popup.locator('#key-file').setInputFiles({ name: 'synthetic-leaf.p12', mimeType: 'application/x-pkcs12', buffer: Buffer.from(leafKey) });
    await popup.locator('#password').fill(PASSWORD);
    if (submit) await popup.locator('#unlock').click();
    return popup;
  }
  const state = popup => popup.locator('#revocation-state').getAttribute('data-state');
  const cancel = async popup => { await popup.locator('#cancel').click(); return page.evaluate(() => window.answer); };
  mkdirSync(resolve('artifacts'), { recursive: true });

  let popup = await open({});
  await popup.locator('#certificate:not([hidden])').waitFor();
  await popup.locator('#revocation-state[data-state=good]').waitFor();
  assert.equal(await popup.locator('#revocation-state').innerText(), 'Статус отзыва: не отозван по актуальным данным');
  assert.equal(await popup.locator('#approve').isEnabled(), true);
  assert.deepEqual(requests, [OCSP, ROOT_CRL], 'leaf via OCSP, intermediate via root CRL');
  await popup.locator('#certificate-technical > summary').click();
  assert.match(await popup.locator('#cert-revocation').innerText(), /Tegin synthetic leaf: Не отозван по актуальным данным · OCSP НУЦ[\s\S]*Tegin synthetic CA: Не отозван по актуальным данным · список отзыва \(CRL\)/);
  await popup.screenshot({ path: resolve('artifacts/revocation-good.png'), fullPage: true });
  await popup.locator('#approve').click();
  const signed = await page.evaluate(() => window.answer);
  assert.equal(signed.status, true); assert.ok(signed.body.result);
  console.log('PASS: leaf (OCSP) and intermediate (root CRL) not revoked: certificate card shows it and signing completes');

  popup = await open({}, { keepCache: true });
  await popup.locator('#revocation-state[data-state=good]').waitFor();
  assert.deepEqual(requests, [OCSP], 'verified root CRL reused from cache until nextUpdate; OCSP asked again in a new operation');
  assert.ok(await sw.evaluate(async () => (await (await caches.open('tegin-crl-v1')).keys()).map(item => item.url).join() === 'https://crl.root.gov.kz/rsa2020.crl'));
  await cancel(popup);
  console.log('PASS: only the public CRL is cached; the OCSP answer about the user certificate is not kept between operations');

  popup = await open({ ocsp: 'revoked' });
  await popup.locator('#status[data-error]').filter({ hasText: 'отозван' }).waitFor();
  assert.equal(await state(popup), 'revoked');
  assert.match(await popup.locator('#revocation-note').innerText(), /отозван .*компрометация ключа.*Операция заблокирована/);
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  await popup.screenshot({ path: resolve('artifacts/revocation-revoked.png'), fullPage: true });
  assert.deepEqual(await cancel(popup), { status: true, body: {} });
  console.log('PASS: revoked certificate is blocked before confirmation; the site gets only a cancellation');

  popup = await open({ ocsp: 'unknown' });
  await popup.locator('#status[data-error]').waitFor();
  assert.equal(await state(popup), 'unknown');
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  assert.ok(!requests.some(url => CA_CRLS.includes(url)), 'definitive OCSP answer, no CRL fallback');
  await cancel(popup);
  console.log('PASS: OCSP "unknown" is blocked and not overridden by CRL');

  popup = await open({ ocsp: 'down', caCrl: 'down' });
  await popup.locator('#status[data-error]').filter({ hasText: 'Проверка отзыва недоступна' }).waitFor();
  assert.equal(await state(popup), 'unavailable');
  assert.equal(await popup.locator('#revocation-state').innerText(), 'Статус отзыва: проверка недоступна');
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  assert.deepEqual(requests.filter(url => CA_CRLS.includes(url)), CA_CRLS, 'primary and mirror CRL tried');
  await popup.screenshot({ path: resolve('artifacts/revocation-unavailable.png'), fullPage: true });
  await cancel(popup);
  console.log('PASS: unreachable OCSP and CRL: "проверка недоступна", operation cannot be confirmed');

  popup = await open({ ocsp: 'down' });
  await popup.locator('#revocation-state[data-state=good]').waitFor();
  await popup.locator('#certificate-technical > summary').click();
  assert.match(await popup.locator('#cert-revocation').innerText(), /список отзыва \(CRL \+ delta\)/);
  await cancel(popup);
  popup = await open({ ocsp: 'down', caCrl: 'revoked' });
  await popup.locator('#status[data-error]').waitFor();
  assert.equal(await state(popup), 'revoked');
  await cancel(popup);
  console.log('PASS: OCSP outage falls back to verified CRL + delta CRL (good and revoked)');

  popup = await open({ root: 'down' });
  await popup.locator('#status[data-error]').waitFor();
  assert.equal(await state(popup), 'unavailable', 'a good leaf with an unchecked intermediate is not a successful check');
  await popup.locator('#certificate-technical > summary').click();
  assert.match(await popup.locator('#cert-revocation').innerText(), /Tegin synthetic leaf: Не отозван[\s\S]*Tegin synthetic CA: Проверка недоступна/);
  await cancel(popup);
  console.log('PASS: overall status needs every non-anchor certificate; intermediate unavailable blocks');

  // A late answer from an abandoned check must not reach the next one. The UI disables key
  // controls during a check, so the key change is dispatched directly to the page.
  popup = await open({ ocsp: 'hold' });
  await popup.waitForFunction(() => document.querySelector('#status').hasAttribute('data-busy'));
  const waitHeld = async () => { for (let attempt = 0; attempt < 100 && !held; attempt++) await new Promise(done => setTimeout(done, 50)); assert.ok(held, 'OCSP request held'); };
  await waitHeld();
  const late = held; held = null;
  await popup.evaluate(() => document.querySelector('#key-file').dispatchEvent(new Event('change')));
  mode.ocsp = 'revoked';
  await popup.locator('#password').fill(PASSWORD);
  await popup.locator('#unlock').click();
  await popup.locator('#status[data-error]').filter({ hasText: 'отозван' }).waitFor();
  await late.release('good');
  await popup.waitForTimeout(500);
  assert.equal(await state(popup), 'revoked');
  assert.equal(await popup.locator('#approve').isDisabled(), true);
  assert.match(await popup.locator('#status').innerText(), /отозван/);
  await cancel(popup);
  console.log('PASS: a late "good" from an abandoned check is ignored; the new "revoked" result stays and blocks');

  // Local verification stays offline unless the user opts in.
  const tool = await context.newPage();
  await tool.goto(`chrome-extension://${extensionId}/signing/approve.html?mode=verify`);
  assert.equal(await tool.locator('#check-revocation').isChecked(), false);
  assert.equal(await tool.locator('#footer-note').innerText(), 'Данные не отправляются в сеть');
  await tool.locator('#check-revocation').check();
  assert.equal(await tool.locator('#footer-note').innerText(), 'В НУЦ уйдут только серийные номера сертификатов');
  await tool.screenshot({ path: resolve('artifacts/revocation-verify-option.png'), fullPage: true });
  await tool.close();
  console.log('PASS: verification tool asks before any revocation request');

  assert.deepEqual(escaped, []);
  assert.deepEqual(errors, []);
  console.log('Revocation browser E2E completed.');
} finally {
  await context?.close();
  await new Promise(done => server.close(done));
  rmSync(folder, { recursive: true, force: true });
  leafKey.fill(0);
}
