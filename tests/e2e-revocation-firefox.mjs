import { arch, platform, tmpdir } from 'node:os';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { createServer } from 'node:http';
import { createServer as createTlsServer } from 'node:https';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import puppeteer from 'puppeteer-core';
import { Browser, detectBrowserPlatform, install, resolveBuildId } from '@puppeteer/browsers';
import { forge } from '../extension/crypto/encoding.js';
import { syntheticPki, ocspResponse, parseOcspRequest, crl, serialHex, fingerprintOf } from './helpers/pki.js';
import { PASSWORD } from './helpers/fixtures.js';

// Revocation checks of the built Firefox extension. Firefox sends all non-local traffic to a local
// proxy: plain HTTP (OCSP) arrives as absolute URLs, HTTPS (CRL) is terminated with a throwaway
// certificate that only this test profile accepts. The pinned NCA URLs get synthetic answers;
// every other host is refused, so the real services are never contacted.
async function firefox() {
  if (process.env.FIREFOX_EXECUTABLE) return process.env.FIREFOX_EXECUTABLE;
  const target = detectBrowserPlatform();
  const buildId = await resolveBuildId(Browser.FIREFOX, target, 'stable');
  return (await install({ browser: Browser.FIREFOX, buildId, platform: target, cacheDir: resolve('.browsers') })).executablePath;
}
const executablePath = await firefox();
if (!existsSync(executablePath)) throw new Error(`Firefox not found: ${executablePath}`);
const folder = mkdtempSync(join(tmpdir(), 'tegin-revocation-firefox-'));
const pki = syntheticPki();
const { root: rootCa, ca, leaf, responder } = pki;
const leafKey = new Uint8Array(Buffer.from(forge.asn1.toDer(forge.pkcs12.toPkcs12Asn1(leaf.privateKey, [leaf.certificate, ca.certificate], PASSWORD, { algorithm: '3des' })).getBytes(), 'binary'));
const testIssuers = { [await fingerprintOf(ca)]: { like: 'nca_rsa_2022', name: 'Tegin synthetic CA' }, [await fingerprintOf(rootCa)]: { like: 'root' } };
execFileSync('node', ['scripts/build.mjs'], { stdio: 'pipe', env: { ...process.env, TEGIN_TEST_REVOCATION_ISSUERS: JSON.stringify(testIssuers), TEGIN_DIST: join(folder, 'build') } });
const extension = join(folder, 'build', 'firefox');
const ADDON_ID = JSON.parse(readFileSync(join(extension, 'manifest.json'), 'utf8')).browser_specific_settings.gecko.id;
const uuid = randomUUID();
const BASE = `moz-extension://${uuid}`;

const OCSP = 'http://ocsp.pki.gov.kz/', ROOT_CRL = 'https://crl.root.gov.kz/rsa2020.crl';
const CA_CRLS = ['https://crl.pki.gov.kz/nca_rsa_2022.crl', 'https://crl1.pki.gov.kz/nca_rsa_2022.crl'];
const DELTAS = ['https://crl.pki.gov.kz/nca_d_rsa_2022.crl', 'https://crl1.pki.gov.kz/nca_d_rsa_2022.crl'];
const NCA_HOSTS = ['tsp.pki.gov.kz', 'ocsp.pki.gov.kz', 'crl.pki.gov.kz', 'crl1.pki.gov.kz', 'crl.root.gov.kz'];

let mode = {};
const requests = [], refused = [];
const reset = (next = {}) => { mode = { ocsp: 'good', caCrl: 'good', delta: 'good', root: 'good', ...next }; requests.length = 0; };
reset();
const body = req => new Promise(done => { const parts = []; req.on('data', part => parts.push(part)); req.on('end', () => done(Buffer.concat(parts))); });
const send = (res, data, type) => { res.writeHead(200, { 'Content-Type': type }); res.end(Buffer.from(data)); };
async function answer(req, res, url) {
  const data = await body(req);
  if (!NCA_HOSTS.includes(new URL(url).host)) { refused.push(url); res.writeHead(403); return res.end(); }
  if (req.method !== 'GET' && req.method !== 'POST' || url === OCSP && req.method !== 'POST') { requests.push(`${req.method} ${url}`); res.writeHead(405); return res.end(); }
  requests.push(url);
  const down = () => req.socket.destroy();
  if (url === OCSP) return mode.ocsp === 'down' ? down() : send(res, ocspResponse(parseOcspRequest(new Uint8Array(data)), { signer: responder, status: mode.ocsp, revocationTime: Date.now() - 3600000, reason: 1 }), 'application/ocsp-response');
  if (url === ROOT_CRL) return mode.root === 'down' ? down() : send(res, crl(rootCa), 'application/pkix-crl');
  if (CA_CRLS.includes(url)) return mode.caCrl === 'down' ? down() : send(res, crl(ca, { number: 7, entries: mode.caCrl === 'revoked' ? [{ serial: serialHex(leaf), reason: 1 }] : [] }), 'application/octet-stream');
  if (DELTAS.includes(url)) return mode.delta === 'down' ? down() : send(res, crl(ca, { number: 8, deltaBase: 7 }), 'application/octet-stream');
  res.writeHead(404); res.end();
}

const tlsKeys = forge.pki.rsa.generateKeyPair(2048);
const tlsCert = forge.pki.createCertificate();
tlsCert.publicKey = tlsKeys.publicKey; tlsCert.serialNumber = '01';
tlsCert.validity.notBefore = new Date(Date.now() - 86400000); tlsCert.validity.notAfter = new Date(Date.now() + 86400000);
tlsCert.setSubject([{ name: 'commonName', value: 'Tegin test proxy' }]); tlsCert.setIssuer([{ name: 'commonName', value: 'Tegin test proxy' }]);
tlsCert.setExtensions([{ name: 'subjectAltName', altNames: NCA_HOSTS.map(value => ({ type: 2, value })) }]);
tlsCert.sign(tlsKeys.privateKey, forge.md.sha256.create());
const tls = createTlsServer({ key: forge.pki.privateKeyToPem(tlsKeys.privateKey), cert: forge.pki.certificateToPem(tlsCert) }, (req, res) => answer(req, res, `https://${req.headers.host}${req.url}`));
const proxy = createServer((req, res) => answer(req, res, req.url));
proxy.on('connect', (req, socket) => {
  const host = req.url.replace(/:443$/, '');
  if (!NCA_HOSTS.includes(host)) { refused.push(req.url); return socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); }
  socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  tls.emit('connection', socket);
});
const site = createServer((req, res) => { res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end('<!doctype html><title>Tegin revocation fixture</title><h1>Synthetic site</h1>'); });
await Promise.all([proxy, site].map(server => new Promise(done => server.listen(0, '127.0.0.1', done))));

// acceptInsecureCerts is a session capability of this test profile; it lets the proxy terminate HTTPS.
const browser = await puppeteer.launch({ browser: 'firefox', executablePath, headless: true, userDataDir: join(folder, 'profile'), acceptInsecureCerts: true,
  env: { ...process.env, MOZ_REMOTE_ALLOW_SYSTEM_ACCESS: '1' },
  extraPrefsFirefox: {
    'extensions.webextensions.uuids': JSON.stringify({ [ADDON_ID]: uuid }),
    'network.proxy.type': 1, 'network.proxy.share_proxy_settings': false,
    'network.proxy.http': '127.0.0.1', 'network.proxy.http_port': proxy.address().port,
    'network.proxy.ssl': '127.0.0.1', 'network.proxy.ssl_port': proxy.address().port
  } });
const errors = [];
async function extensionWindow(path, known) {
  for (let i = 0; i < 300; i++) {
    for (const candidate of await browser.pages()) {
      if (known.has(candidate)) continue;
      const href = await candidate.evaluate(() => location.href).catch(() => '');
      if (href.startsWith(`${BASE}/${path}#`)) { candidate.on('pageerror', error => errors.push(error.message)); return candidate; }
    }
    await new Promise(done => setTimeout(done, 50));
  }
  throw new Error(`no extension window ${path}`);
}

try {
  assert.equal(await browser.installExtension(extension), ADDON_ID);
  console.log(`ENV: firefox on ${platform()} ${arch()}: ${await browser.version()}`);
  const page = await browser.newPage();
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(`http://127.0.0.1:${site.address().port}/`);
  await page.waitForFunction(() => window.WebSocket.__ncaBrowserAdapter === true);
  await page.evaluate(() => new Promise((done, fail) => { window.socket = new WebSocket('wss://127.0.0.1:13579'); window.socket.onopen = done; window.socket.onerror = fail; }));
  const request = { module: 'kz.gov.pki.knca.basics', method: 'sign', args: { allowedStorages: ['PKCS12'], format: 'xml', data: '<login><nonce>revocation</nonce></login>', signingParams: {},
    signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'], chain: [rootCa.pem] } } };
  async function open(next) {
    reset(next);
    const known = new Set(await browser.pages());
    await page.evaluate(message => { window.answer = new Promise(done => { window.socket.onmessage = event => done(JSON.parse(event.data)); }); window.socket.send(JSON.stringify(message)); }, request);
    const popup = await extensionWindow('signing/approve.html', known);
    await popup.evaluate(() => caches.delete('tegin-crl-v1'));
    await popup.waitForSelector('#revocation-network-note');
    // input.setFiles is refused in privileged contexts; the same File reaches the input through DataTransfer.
    await popup.evaluate((bytes, name) => {
      const transfer = new DataTransfer(); transfer.items.add(new File([Uint8Array.from(bytes)], name, { type: 'application/x-pkcs12' }));
      const input = document.querySelector('#key-file'); input.files = transfer.files; input.dispatchEvent(new Event('change', { bubbles: true }));
    }, Array.from(leafKey), 'synthetic-leaf.p12');
    await popup.type('#password', PASSWORD);
    await popup.click('#unlock');
    return popup;
  }
  const state = popup => popup.$eval('#revocation-state', node => node.dataset.state);
  const approveDisabled = popup => popup.$eval('#approve', node => node.disabled);
  const cancel = async popup => { await popup.click('#cancel'); return page.evaluate(() => window.answer); };

  let popup = await open({});
  assert.equal(await popup.evaluate(origins => browser.permissions.contains({ origins }), ['http://ocsp.pki.gov.kz/*', 'https://*.kz/*']), true);
  await popup.waitForSelector('#revocation-state[data-state=good]', { timeout: 30000 });
  assert.equal(await popup.$eval('#revocation-state', node => node.innerText), 'Статус отзыва: не отозван по актуальным данным');
  assert.equal(await approveDisabled(popup), false);
  assert.deepEqual(requests, [OCSP, ROOT_CRL], 'leaf via OCSP over HTTP, intermediate via root CRL over HTTPS');
  await popup.click('#approve');
  const signed = await page.evaluate(() => window.answer);
  assert.equal(signed.status, true); assert.ok(signed.body.result);
  console.log('PASS: host permissions for OCSP and CRL are granted; leaf (OCSP) and intermediate (root CRL) not revoked; signing completes');

  popup = await open({ ocsp: 'revoked' });
  await popup.waitForSelector('#revocation-state[data-state=revoked]', { timeout: 30000 });
  assert.match(await popup.$eval('#revocation-note', node => node.innerText), /отозван .*компрометация ключа.*Операция заблокирована/);
  assert.equal(await approveDisabled(popup), true);
  assert.deepEqual(await cancel(popup), { status: true, body: {} });
  console.log('PASS: revoked certificate is blocked before confirmation; the site gets only a cancellation');

  popup = await open({ ocsp: 'down' });
  await popup.waitForSelector('#revocation-state[data-state=good]', { timeout: 30000 });
  assert.ok(requests.includes(CA_CRLS[0]) && requests.includes(DELTAS[0]), 'CRL and delta CRL fetched over HTTPS after the OCSP failure');
  await cancel(popup);
  popup = await open({ ocsp: 'down', caCrl: 'revoked' });
  await popup.waitForSelector('#revocation-state[data-state=revoked]', { timeout: 30000 });
  assert.equal(await approveDisabled(popup), true);
  await cancel(popup);
  console.log('PASS: OCSP outage falls back to verified CRL + delta CRL (good and revoked)');

  popup = await open({ ocsp: 'down', caCrl: 'down' });
  await popup.waitForSelector('#revocation-state[data-state=unavailable]', { timeout: 30000 });
  assert.equal(await popup.$eval('#revocation-state', node => node.innerText), 'Статус отзыва: проверка недоступна');
  assert.equal(await approveDisabled(popup), true);
  // Firefox itself repeats a GET whose connection drops, so each address may appear several times.
  assert.deepEqual([...new Set(requests.filter(url => CA_CRLS.includes(url)))], CA_CRLS, 'primary and mirror CRL tried');
  await cancel(popup);
  console.log('PASS: unreachable OCSP and CRL: "проверка недоступна", operation cannot be confirmed');

  assert.deepEqual(errors, []);
  if (refused.length) console.log(`INFO: browser requests to other hosts refused by the proxy: ${[...new Set(refused.map(url => new URL(url.includes('://') ? url : `https://${url}`).host))].join(', ')}`);
  console.log('Firefox revocation E2E completed.');
} finally {
  await browser.close();
  await Promise.all([proxy, site].map(server => new Promise(done => { server.close(done); server.closeAllConnections(); })));
  rmSync(folder, { recursive: true, force: true });
  leafKey.fill(0);
}
