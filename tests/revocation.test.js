import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildOcspRequest, verifyOcspResponse } from '../extension/crypto/ocsp.js';
import { parseCrl, verifyCrl, statusFromCrls } from '../extension/crypto/crl.js';
import { RevocationChecker, memoryStore, fetchBounded, blocks, assessHistory, summarize } from '../extension/crypto/revocation.js';
import { ALLOWED_URLS, OCSP_URL, profileFor } from '../extension/crypto/revocation-profiles.js';
import { certificateInfo } from '../extension/crypto/signer.js';
import { trustStore } from '../extension/crypto/trust-store.js';
import { unbase64 } from '../extension/crypto/encoding.js';
import { syntheticPki, issue, ocspResponse, parseOcspRequest, crl, serialHex, fingerprintOf, OCSP_SIGNING } from './helpers/pki.js';

const pki = syntheticPki();
const { root: rootCa, ca, leaf, responder } = pki;
const rejects = (promise, code) => assert.rejects(promise, error => { assert.equal(error.code, code, error.message); return true; });
const serialBytes = item => Uint8Array.from(Buffer.from(serialHex(item).padStart(2, '0'), 'hex'));

async function exchange(certificate = leaf, issuer = ca) {
  const request = await buildOcspRequest(certificate.info, issuer.info);
  return { request, parsed: parseOcspRequest(request.body) };
}

test('OCSP: good, revoked and unknown are reported only after full verification', async () => {
  const { request, parsed } = await exchange();
  assert.equal((await verifyOcspResponse(ocspResponse(parsed, { signer: responder }), request, ca.info)).status, 'good');
  const revoked = await verifyOcspResponse(ocspResponse(parsed, { signer: responder, status: 'revoked', revocationTime: Date.now() - 60000, reason: 1 }), request, ca.info);
  assert.equal(revoked.status, 'revoked'); assert.equal(revoked.reason, 'keyCompromise'); assert.ok(revoked.revocationTime);
  assert.equal((await verifyOcspResponse(ocspResponse(parsed, { signer: responder, status: 'unknown' }), request, ca.info)).status, 'unknown');
  const byKey = await verifyOcspResponse(ocspResponse(parsed, { signer: responder, byKey: true }), request, ca.info);
  assert.equal(byKey.status, 'good');
  assert.equal((await verifyOcspResponse(ocspResponse(parsed, { signer: responder, nonceRaw: true }), request, ca.info)).status, 'good', 'nonce echoed without the inner OCTET STRING');
});

test('OCSP: "not issued" convention (RFC 6960 2.2) is unknown, never good', async () => {
  const { request, parsed } = await exchange();
  const notIssued = await verifyOcspResponse(ocspResponse(parsed, { signer: responder, status: 'revoked', revocationTime: 0, reason: 6, extendedRevoke: true }), request, ca.info);
  assert.equal(notIssued.status, 'unknown'); assert.equal(notIssued.detail, 'not-issued');
  const hold = await verifyOcspResponse(ocspResponse(parsed, { signer: responder, status: 'revoked', revocationTime: 0, reason: 6 }), request, ca.info);
  assert.equal(hold.status, 'revoked', 'without the extended revoke extension it stays a revocation');
});

test('OCSP: foreign serial, foreign issuer and request/issuer mismatch are rejected', async () => {
  const { request, parsed } = await exchange();
  const other = await exchange(issue({ name: 'Other leaf', issuer: ca }));
  await rejects(verifyOcspResponse(ocspResponse(parsed, { signer: responder, certIdDer: other.parsed.certIdDer }), request, ca.info), 'OCSP_MISMATCH');
  const otherCa = issue({ name: 'Other CA', issuer: rootCa, ca: true });
  await rejects(verifyOcspResponse(ocspResponse(parsed, { signer: responder }), request, otherCa.info), 'OCSP_RESPONDER');
  await rejects(buildOcspRequest(leaf.info, rootCa.info), 'OCSP_ISSUER');
});

test('OCSP: bad signature and unauthorized responders are rejected', async () => {
  const { request, parsed } = await exchange();
  await rejects(verifyOcspResponse(ocspResponse(parsed, { signer: responder, tamper: true }), request, ca.info), 'OCSP_SIGNATURE');
  const cases = {
    'no OCSPSigning EKU': issue({ name: 'No EKU responder', issuer: ca, nocheck: true }),
    'no id-pkix-ocsp-nocheck': issue({ name: 'No nocheck responder', issuer: ca, eku: [OCSP_SIGNING] }),
    'issued by another CA': issue({ name: 'Root-issued responder', issuer: rootCa, eku: [OCSP_SIGNING], nocheck: true }),
    'expired': issue({ name: 'Expired responder', issuer: ca, eku: [OCSP_SIGNING], nocheck: true, notBefore: Date.now() - 10 * 86400000, notAfter: Date.now() - 86400000 }),
    'unknown critical extension': issue({ name: 'Critical responder', issuer: ca, eku: [OCSP_SIGNING], nocheck: true, unknownCritical: true }),
    'the end-entity certificate itself': leaf
  };
  for (const [name, signer] of Object.entries(cases)) await rejects(verifyOcspResponse(ocspResponse(parsed, { signer }), request, ca.info), 'OCSP_RESPONDER').catch(error => { throw new Error(`${name}: ${error.message}`); });
  await rejects(verifyOcspResponse(ocspResponse(parsed, { signer: ca }), request, ca.info), 'OCSP_RESPONDER');
  await rejects(verifyOcspResponse(ocspResponse(parsed, { signer: responder, certificates: [] }), request, ca.info), 'OCSP_RESPONDER');
});

test('OCSP: stale, future, expired nextUpdate and allowed clock skew', async () => {
  const { request, parsed } = await exchange();
  const minute = 60000;
  await rejects(verifyOcspResponse(ocspResponse(parsed, { signer: responder, thisUpdate: Date.now() - 10 * minute }), request, ca.info), 'OCSP_STALE');
  await rejects(verifyOcspResponse(ocspResponse(parsed, { signer: responder, thisUpdate: Date.now() + 10 * minute }), request, ca.info), 'OCSP_FUTURE');
  await rejects(verifyOcspResponse(ocspResponse(parsed, { signer: responder, thisUpdate: Date.now() - 2 * minute, nextUpdate: Date.now() - 6 * minute }), request, ca.info), 'OCSP_STALE');
  assert.equal((await verifyOcspResponse(ocspResponse(parsed, { signer: responder, thisUpdate: Date.now() + 2 * minute }), request, ca.info)).status, 'good', 'within 5 minutes of skew');
  const fresh = await verifyOcspResponse(ocspResponse(parsed, { signer: responder, nextUpdate: Date.now() + 60 * minute }), request, ca.info);
  assert.ok(fresh.expires <= Date.now() + 5 * minute + 1000, 'cache lifetime never exceeds the maximum age');
});

test('OCSP: nonce, critical extensions, error status and corrupt responses', async () => {
  const { request, parsed } = await exchange();
  await rejects(verifyOcspResponse(ocspResponse(parsed, { signer: responder, nonce: null }), request, ca.info), 'OCSP_NONCE');
  await rejects(verifyOcspResponse(ocspResponse(parsed, { signer: responder, nonce: new Uint8Array(16) }), request, ca.info), 'OCSP_NONCE');
  await rejects(verifyOcspResponse(ocspResponse(parsed, { signer: responder, criticalExtension: true }), request, ca.info), 'OCSP_CRITICAL');
  await rejects(verifyOcspResponse(ocspResponse(parsed, { responseStatus: 3 }), request, ca.info), 'OCSP_STATUS');
  const good = ocspResponse(parsed, { signer: responder });
  await rejects(verifyOcspResponse(good.slice(0, good.length - 7), request, ca.info), 'OCSP_MALFORMED');
  await rejects(verifyOcspResponse(Uint8Array.of(...good, 0), request, ca.info), 'OCSP_MALFORMED');
  await rejects(verifyOcspResponse(new TextEncoder().encode('<html>ok</html>'), request, ca.info), 'OCSP_MALFORMED');
});

test('CRL: signature, issuer, freshness, scope and required extensions', async () => {
  const verify = (raw, options) => verifyCrl(parseCrl(raw), ca.info, options);
  const listed = await verify(crl(ca, { entries: [{ serial: serialHex(leaf), reason: 1 }] }));
  assert.equal(statusFromCrls(listed, null, serialBytes(leaf)).status, 'revoked');
  assert.equal(statusFromCrls(listed, null, serialBytes(leaf)).reason, 'keyCompromise');
  assert.equal(statusFromCrls(await verify(crl(ca)), null, serialBytes(leaf)).status, 'good');
  await rejects(verify(crl(ca, { tamper: true })), 'CRL_SIGNATURE');
  await rejects(verify(crl(ca, { signer: rootCa })), 'CRL_SIGNATURE');
  await rejects(verifyCrl(parseCrl(crl(ca)), rootCa.info), 'CRL_ISSUER');
  await rejects(verify(crl(ca, { thisUpdate: Date.now() - 2 * 86400000, nextUpdate: Date.now() - 60000 })), 'CRL_STALE');
  await rejects(verify(crl(ca, { thisUpdate: Date.now() + 3600000 })), 'CRL_FUTURE');
  await rejects(verify(crl(ca, { nextUpdate: null })), 'CRL_UNSUPPORTED');
  await rejects(verify(crl(ca, { number: null })), 'CRL_UNSUPPORTED');
  await rejects(verify(crl(ca, { scoped: true })), 'CRL_UNSUPPORTED');
  await rejects(verify(crl(ca, { criticalExtension: true })), 'CRL_UNSUPPORTED');
  await rejects(verify(crl(ca, { deltaBase: 1 })), 'CRL_UNSUPPORTED');
  await rejects(verify(crl(ca), { kind: 'delta' }), 'CRL_UNSUPPORTED');
  assert.throws(() => parseCrl(crl(ca, { version: null })), { code: 'CRL_UNSUPPORTED' });
  assert.throws(() => parseCrl(new Uint8Array([0x30, 0x03, 0x02, 0x01])), { code: 'CRL_MALFORMED' });
  // Indirect entries or unknown critical entry extensions anywhere in the list fail the whole list.
  const indirect = await verify(crl(ca, { entries: [{ serial: 'abcd' }], indirectEntry: true }));
  assert.throws(() => statusFromCrls(indirect, null, serialBytes(leaf)), { code: 'CRL_UNSUPPORTED' });
  const critical = await verify(crl(ca, { entries: [{ serial: 'abcd' }], criticalEntryExtension: true }));
  assert.throws(() => statusFromCrls(critical, null, serialBytes(leaf)), { code: 'CRL_UNSUPPORTED' });
});

test('CRL: delta lists refine the complete list, including removeFromCRL', async () => {
  const full = await verifyCrl(parseCrl(crl(ca, { number: 10, entries: [{ serial: serialHex(leaf), reason: 6 }] })), ca.info);
  const unhold = await verifyCrl(parseCrl(crl(ca, { number: 11, deltaBase: 10, entries: [{ serial: serialHex(leaf), reason: 8 }] })), ca.info, { kind: 'delta' });
  assert.equal(statusFromCrls(full, null, serialBytes(leaf)).status, 'revoked');
  assert.equal(statusFromCrls(full, unhold, serialBytes(leaf)).status, 'good');
  assert.equal(statusFromCrls(full, unhold, serialBytes(leaf)).source, 'crl+delta');
  const clean = await verifyCrl(parseCrl(crl(ca, { number: 10 })), ca.info);
  const fresh = await verifyCrl(parseCrl(crl(ca, { number: 12, deltaBase: 10, entries: [{ serial: serialHex(leaf), reason: 1 }] })), ca.info, { kind: 'delta' });
  assert.equal(statusFromCrls(clean, fresh, serialBytes(leaf)).status, 'revoked');
  const ahead = await verifyCrl(parseCrl(crl(ca, { number: 13, deltaBase: 11 })), ca.info, { kind: 'delta' });
  assert.throws(() => statusFromCrls(clean, ahead, serialBytes(leaf)), { code: 'CRL_UNSUPPORTED' });
});

// Fake network for the checker: synthetic CAs are mapped to the pinned NCA URLs.
async function harness({ ocsp = 'good', rootList = 'good', caList = 'good', delta = 'good', clock } = {}) {
  const testIssuers = { [await fingerprintOf(ca)]: { like: 'nca_rsa_2022' }, [await fingerprintOf(rootCa)]: { like: 'root' } };
  const calls = [];
  const now = clock || { value: Date.now() };
  const reply = (body, type) => new Response(body, { status: 200, headers: { 'content-type': type } });
  const fetchImpl = async (url, init) => {
    calls.push(url);
    if (init.redirect !== 'error' || init.credentials !== 'omit' || init.cache !== 'no-store') throw new Error('unsafe fetch options');
    if (url === OCSP_URL) {
      if (ocsp === 'down') throw new TypeError('Failed to fetch');
      const parsed = parseOcspRequest(new Uint8Array(init.body));
      const options = typeof ocsp === 'object' ? ocsp : { status: ocsp, revocationTime: now.value - 60000, reason: 1 };
      return reply(ocspResponse(parsed, { signer: responder, thisUpdate: now.value, ...options }), 'application/ocsp-response');
    }
    if (url === 'https://crl.root.gov.kz/rsa2020.crl') {
      if (rootList === 'down') throw new TypeError('Failed to fetch');
      return reply(crl(rootCa, { thisUpdate: now.value - 3600000, nextUpdate: now.value + 86400000, entries: rootList === 'revoked' ? [{ serial: serialHex(ca), reason: 2 }] : [] }), 'application/pkix-crl');
    }
    if (url.endsWith('/nca_rsa_2022.crl')) {
      if (caList === 'down') throw new TypeError('Failed to fetch');
      return reply(crl(ca, { number: 5, thisUpdate: now.value - 3600000, nextUpdate: now.value + 86400000, entries: caList === 'revoked' ? [{ serial: serialHex(leaf), reason: 1 }] : [] }), 'application/octet-stream');
    }
    if (url.endsWith('/nca_d_rsa_2022.crl')) {
      if (delta === 'down') throw new TypeError('Failed to fetch');
      return reply(crl(ca, { number: 6, deltaBase: 5, thisUpdate: now.value - 600000, nextUpdate: now.value + 43200000, entries: delta === 'revoked' ? [{ serial: serialHex(leaf), reason: 4 }] : [] }), 'application/octet-stream');
    }
    throw new Error('unexpected URL ' + url);
  };
  const checker = new RevocationChecker({ fetchImpl, store: memoryStore(), testIssuers, now: () => now.value });
  return { checker, calls, now, path: [leaf.info, ca.info, rootCa.info] };
}

test('chain: every non-anchor certificate is checked; overall good needs all of them', async () => {
  const { checker, calls, path } = await harness();
  const result = await checker.checkPath(path);
  assert.equal(result.state, 'good'); assert.equal(result.required, true); assert.equal(blocks(result), false);
  assert.deepEqual(result.certificates.map(entry => [entry.role, entry.state, entry.source]), [['end-entity', 'good', 'ocsp'], ['ca', 'good', 'crl']]);
  assert.deepEqual(calls, [OCSP_URL, 'https://crl.root.gov.kz/rsa2020.crl']);
  assert.ok(calls.every(url => ALLOWED_URLS.includes(url)));

  const missingRoot = await (await harness({ rootList: 'down' })).checker.checkPath(path);
  assert.equal(missingRoot.certificates[0].state, 'good');
  assert.equal(missingRoot.state, 'unavailable', 'a good leaf with an unchecked CA is not a successful check');
  assert.equal(blocks(missingRoot), true);

  const revokedCa = await (await harness({ rootList: 'revoked' })).checker.checkPath(path);
  assert.equal(revokedCa.state, 'revoked'); assert.equal(revokedCa.certificates[1].reason, 'cACompromise');
});

test('chain: revoked, unknown and unavailable block; OCSP errors fall back to CRL + delta', async () => {
  const { path } = await harness();
  const revoked = await (await harness({ ocsp: 'revoked' })).checker.checkPath(path);
  assert.equal(revoked.state, 'revoked'); assert.equal(blocks(revoked), true);

  const unknown = await harness({ ocsp: 'unknown' });
  const unknownResult = await unknown.checker.checkPath(path);
  assert.equal(unknownResult.state, 'unknown'); assert.equal(blocks(unknownResult), true);
  assert.ok(!unknown.calls.some(url => url.includes('nca_rsa_2022')), 'a definitive OCSP answer is final, no CRL fallback');

  const fallback = await harness({ ocsp: 'down' });
  const viaCrl = await fallback.checker.checkPath(path);
  assert.equal(viaCrl.state, 'good'); assert.equal(viaCrl.certificates[0].source, 'crl+delta');
  assert.deepEqual(viaCrl.certificates[0].errors, ['NETWORK']);
  assert.equal((await (await harness({ ocsp: 'down', delta: 'revoked' })).checker.checkPath(path)).state, 'revoked');
  assert.equal((await (await harness({ ocsp: { tamper: true }, caList: 'revoked' })).checker.checkPath(path)).state, 'revoked', 'an invalid OCSP response is not trusted; CRL decides');
  const fullOnly = await (await harness({ ocsp: 'down', delta: 'down' })).checker.checkPath(path);
  assert.equal(fullOnly.state, 'good'); assert.equal(fullOnly.certificates[0].source, 'crl');

  const offline = await harness({ ocsp: 'down', caList: 'down' });
  const unavailable = await offline.checker.checkPath(path);
  assert.equal(unavailable.state, 'unavailable'); assert.equal(blocks(unavailable), true);
  assert.deepEqual(offline.calls.filter(url => url.includes('nca_rsa_2022')), ['https://crl.pki.gov.kz/nca_rsa_2022.crl', 'https://crl1.pki.gov.kz/nca_rsa_2022.crl'], 'mirror tried once');
});

test('chain: issuers without pinned sources are "not checked" and never shown as good', async () => {
  const foreignRoot = issue({ name: 'Unpinned root', ca: true });
  const foreignLeaf = issue({ name: 'Unpinned leaf', issuer: foreignRoot });
  const { checker, calls } = await harness();
  const result = await checker.checkPath([foreignLeaf.info, foreignRoot.info]);
  assert.equal(result.state, 'not-checked'); assert.equal(result.required, false); assert.equal(blocks(result), false);
  assert.equal(calls.length, 0, 'no network for unpinned issuers');
  // Partially pinned chain: required, so "not checked" blocks.
  const partial = await checker.checkPath([leaf.info, ca.info, foreignRoot.info]);
  assert.equal(partial.state, 'not-checked'); assert.equal(partial.required, true); assert.equal(blocks(partial), true);
  assert.equal(summarize([], new Date().toISOString(), 'untrusted').state, 'not-checked');
});

test('cache: OCSP for at most five minutes in memory, CRLs until nextUpdate', async () => {
  const clock = { value: Date.now() };
  const { checker, calls, path } = await harness({ clock });
  await checker.checkPath(path);
  await checker.checkPath(path);
  assert.deepEqual(calls, [OCSP_URL, 'https://crl.root.gov.kz/rsa2020.crl'], 'second check served from cache');
  clock.value += 6 * 60000;
  await checker.checkPath(path);
  assert.deepEqual(calls.slice(2), [OCSP_URL], 'OCSP refreshed after maximum age; root CRL still valid');
  clock.value += 2 * 86400000;
  await checker.checkPath(path);
  assert.deepEqual(calls.slice(3), [OCSP_URL, 'https://crl.root.gov.kz/rsa2020.crl'], 'CRL refetched after nextUpdate');
  const store = memoryStore();
  await store.put('https://crl.root.gov.kz/rsa2020.crl', new Uint8Array(4), Date.now() - 1);
  assert.equal(await store.get('https://crl.root.gov.kz/rsa2020.crl'), null);
});

test('network: allowlist, redirects, content type, size, timeout and cancellation', async () => {
  const ok = body => async () => new Response(body, { headers: { 'content-type': 'application/ocsp-response' } });
  const options = { method: 'POST', types: ['application/ocsp-response'], limit: 1024, timeout: 1000 };
  await rejects(fetchBounded('http://ocsp.example.kz/', { ...options, fetchImpl: ok('x') }), 'URL_NOT_ALLOWED');
  await rejects(fetchBounded('http://ocsp.pki.gov.kz', { ...options, fetchImpl: ok('x') }), 'URL_NOT_ALLOWED');
  await rejects(fetchBounded(OCSP_URL, { ...options, fetchImpl: ok('x'), limit: 0 }), 'TOO_LARGE');
  await rejects(fetchBounded(OCSP_URL, { ...options, fetchImpl: async () => ({ ...await ok('x')(), redirected: true, ok: true, headers: new Headers({ 'content-type': 'application/ocsp-response' }) }) }), 'REDIRECT');
  await rejects(fetchBounded(OCSP_URL, { ...options, fetchImpl: async () => new Response('x', { headers: { 'content-type': 'text/html' } }) }), 'CONTENT_TYPE');
  await rejects(fetchBounded(OCSP_URL, { ...options, fetchImpl: async () => new Response('x', { status: 503, headers: { 'content-type': 'application/ocsp-response' } }) }), 'HTTP');
  await rejects(fetchBounded(OCSP_URL, { ...options, fetchImpl: async () => new Response('x', { headers: { 'content-type': 'application/ocsp-response', 'content-length': '999999' } }) }), 'TOO_LARGE');
  const endless = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(512)); } });
  await rejects(fetchBounded(OCSP_URL, { ...options, fetchImpl: async () => new Response(endless, { headers: { 'content-type': 'application/ocsp-response' } }) }), 'TOO_LARGE');
  const hanging = async (url, init) => new Promise((resolve, reject) => init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))));
  await rejects(fetchBounded(OCSP_URL, { ...options, timeout: 30, fetchImpl: hanging }), 'TIMEOUT');
  const controller = new AbortController();
  const pending = fetchBounded(OCSP_URL, { ...options, signal: controller.signal, fetchImpl: hanging });
  controller.abort();
  await rejects(pending, 'ABORTED');
  await rejects(fetchBounded(OCSP_URL, { ...options, signal: AbortSignal.abort(), fetchImpl: ok('x') }), 'ABORTED');
  const stalled = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(4)); } });
  await rejects(fetchBounded(OCSP_URL, { ...options, timeout: 30, fetchImpl: async (url, init) => new Response(stalled.pipeThrough(new TransformStream(), { signal: init.signal }), { headers: { 'content-type': 'application/ocsp-response' } }) }), 'TIMEOUT');
  assert.deepEqual([...await fetchBounded(OCSP_URL, { ...options, fetchImpl: ok('abc') })], [97, 98, 99]);
});

test('chain check can be cancelled', async () => {
  const { path } = await harness();
  const controller = new AbortController();
  const checker = new RevocationChecker({ store: memoryStore(), testIssuers: { [await fingerprintOf(ca)]: { like: 'nca_rsa_2022' } },
    fetchImpl: (url, init) => new Promise((resolve, reject) => init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))) });
  const pending = checker.checkPath(path, { signal: controller.signal });
  setTimeout(() => controller.abort(), 20);
  await rejects(pending, 'ABORTED');
});

test('history: current status is compared with the timestamp, without a verdict', () => {
  const revokedAt = '2026-05-01T00:00:00.000Z';
  const revoked = { state: 'revoked', certificates: [{ state: 'revoked', revocationTime: revokedAt }] };
  assert.equal(assessHistory(revoked, { time: '2026-04-01T00:00:00.000Z' }).relation, 'revoked-after-timestamp');
  assert.equal(assessHistory(revoked, { time: '2026-06-01T00:00:00.000Z' }).relation, 'revoked-before-timestamp');
  assert.equal(assessHistory(revoked, null).relation, 'signing-time-unproven');
  assert.equal(assessHistory({ state: 'good', certificates: [] }, null).relation, 'not-revoked-now');
  assert.equal(assessHistory({ state: 'unavailable', certificates: [] }, { time: revokedAt }).relation, 'undetermined');
});

test('profiles: only pinned NCA endpoints, keyed by issuer fingerprint; manifest grants exactly these origins', async () => {
  const fingerprint = async name => Buffer.from(await crypto.subtle.digest('SHA-256', unbase64(trustStore.find(entry => entry.name === name).certificate))).toString('hex');
  assert.deepEqual(profileFor(await fingerprint('nca_gost_2022'), null).ocsp, [OCSP_URL]);
  assert.deepEqual(profileFor(await fingerprint('root_rsa_2020'), null).crl, ['https://crl.root.gov.kz/rsa2020.crl']);
  assert.equal(profileFor(await fingerprintOf(ca), null), null);
  assert.deepEqual(ALLOWED_URLS.toSorted(), [
    'http://ocsp.pki.gov.kz/',
    'https://crl.pki.gov.kz/nca_d_gost_2022.crl', 'https://crl.pki.gov.kz/nca_d_rsa_2022.crl', 'https://crl.pki.gov.kz/nca_gost_2022.crl', 'https://crl.pki.gov.kz/nca_rsa_2022.crl',
    'https://crl.root.gov.kz/gost2015_2022.crl', 'https://crl.root.gov.kz/rsa2020.crl',
    'https://crl1.pki.gov.kz/nca_d_gost_2022.crl', 'https://crl1.pki.gov.kz/nca_d_rsa_2022.crl', 'https://crl1.pki.gov.kz/nca_gost_2022.crl', 'https://crl1.pki.gov.kz/nca_rsa_2022.crl'
  ].toSorted());
  const manifest = JSON.parse(readFileSync(new URL('../extension/manifest.json', import.meta.url)));
  const connect = manifest.content_security_policy.extension_pages.match(/connect-src ([^;]+)/)[1].split(' ');
  for (const url of ALLOWED_URLS) {
    assert.ok(connect.includes(new URL(url).origin), `CSP connect-src allows ${url}`);
    assert.ok(manifest.host_permissions.some(pattern => new RegExp('^' + pattern.replace(/[.]/g, '\\.').replace(/\*/g, '[^/]*') + '$').test(url) || new RegExp('^' + pattern.replace(/[.]/g, '\\.').replace(/\*/g, '.*') + '$').test(url)), `host permission covers ${url}`);
  }
  assert.deepEqual(connect.toSorted(), ['http://ocsp.pki.gov.kz', 'http://tsp.pki.gov.kz', 'https://crl.pki.gov.kz', 'https://crl.root.gov.kz', 'https://crl1.pki.gov.kz']);
});

// Public NCA material captured on 2026-11-09 (tests/fixtures/revocation/provenance.json).
test('real NCA evidence: OCSP good for the public TSA certificate, "not issued" serials, root CRLs', async () => {
  const fixture = name => new Uint8Array(readFileSync(new URL(`fixtures/revocation/${name}`, import.meta.url)));
  const meta = JSON.parse(readFileSync(new URL('fixtures/revocation/provenance.json', import.meta.url)));
  const nca = name => certificateInfo(unbase64(trustStore.find(entry => entry.name === name).certificate));
  const replay = (name, issuer, certificate) => {
    const parsed = parseOcspRequest(fixture(`${name}.req`));
    return verifyOcspResponse(fixture(`${name}.der`), { certId: parsed.certId, nonce: parsed.nonce }, issuer, { now: Date.parse(meta.files[name].producedAt) });
  };
  const good = await replay('ocsp-tsa-good', nca('nca_gost_2022'));
  assert.equal(good.status, 'good'); assert.equal(good.nextUpdate, null);
  for (const kind of ['rsa', 'gost']) {
    const result = await replay(`ocsp-${kind}-not-issued`, nca(`nca_${kind}_2022`));
    assert.equal(result.status, 'unknown'); assert.equal(result.detail, 'not-issued');
  }
  await rejects(replay('ocsp-tsa-good', nca('nca_rsa_2022')), 'OCSP_RESPONDER');
  const late = parseOcspRequest(fixture('ocsp-tsa-good.req'));
  await rejects(verifyOcspResponse(fixture('ocsp-tsa-good.der'), late, nca('nca_gost_2022'), { now: Date.parse(meta.files['ocsp-tsa-good'].producedAt) + 6 * 60000 }), 'OCSP_STALE');
  for (const [file, rootName, ncaName] of [['root-rsa2020.crl', 'root_rsa_2020', 'nca_rsa_2022'], ['root-gost2015_2022.crl', 'root_gost_2022', 'nca_gost_2022']]) {
    const list = parseCrl(fixture(file));
    await verifyCrl(list, nca(rootName), { now: list.thisUpdate + 3600000 });
    assert.equal(statusFromCrls(list, null, Uint8Array.from(nca(ncaName).serial.value, char => char.charCodeAt(0))).status, 'good');
    await rejects(verifyCrl(list, nca(rootName), { now: list.nextUpdate + 1 }), 'CRL_STALE');
  }
});
