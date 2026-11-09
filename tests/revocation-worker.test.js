import test from 'node:test';
import assert from 'node:assert/strict';
import { forge } from '../extension/crypto/encoding.js';
import { syntheticPki, ocspResponse, parseOcspRequest, crl, serialHex, fingerprintOf } from './helpers/pki.js';
import { PASSWORD } from './helpers/fixtures.js';

// The real crypto/worker.js in Node: fake `self` and network, synthetic CAs mapped to the pinned NCA
// URLs (as in the test build). Time is controlled by mocking Date in this process; the system clock
// is never touched.
const MINUTE = 60000, HOUR = 60 * MINUTE, DAY = 24 * HOUR;
const { root: rootCa, ca, leaf, responder } = syntheticPki();
globalThis.__TEGIN_TEST_REVOCATION_ISSUERS__ = { [await fingerprintOf(ca)]: { like: 'nca_rsa_2022' }, [await fingerprintOf(rootCa)]: { like: 'root' } };
const OCSP = 'http://ocsp.pki.gov.kz/', ROOT_CRL = 'https://crl.root.gov.kz/rsa2020.crl';
const CA_CRLS = ['https://crl.pki.gov.kz/nca_rsa_2022.crl', 'https://crl1.pki.gov.kz/nca_rsa_2022.crl'];
const DELTAS = ['https://crl.pki.gov.kz/nca_d_rsa_2022.crl', 'https://crl1.pki.gov.kz/nca_d_rsa_2022.crl'];
const container = () => new Uint8Array(Buffer.from(forge.asn1.toDer(forge.pkcs12.toPkcs12Asn1(leaf.privateKey, [leaf.certificate, ca.certificate], PASSWORD, { algorithm: '3des' })).getBytes(), 'binary')).buffer;
const request = { operation: 'sign', format: 'raw', documents: ['VGVnaW4='], decode: true, signerParams: { chain: [rootCa.pem] }, trustRequired: true };

let net;
const reset = next => { net = { ocsp: 'good', ocspAge: 0, crl: 'good', crlLife: DAY, calls: [], ...next }; };
const reply = (body, type) => new Response(body, { headers: { 'content-type': type } });
globalThis.fetch = async (url, init) => {
  net.calls.push(url);
  const now = Date.now();
  if (url === OCSP) {
    if (net.ocsp === 'down') throw new TypeError('Failed to fetch');
    return reply(ocspResponse(parseOcspRequest(new Uint8Array(init.body)), { signer: responder, status: net.ocsp, thisUpdate: now - net.ocspAge, revocationTime: now - HOUR, reason: 1 }), 'application/ocsp-response');
  }
  if (url === ROOT_CRL) { const body = crl(rootCa, { thisUpdate: now - HOUR, nextUpdate: now + DAY }); net.slowRoot?.(); return reply(body, 'application/pkix-crl'); }
  if (net.crl === 'down') throw new TypeError('Failed to fetch');
  const entries = net.crl === 'revoked' ? [{ serial: serialHex(leaf), reason: 1 }] : [];
  if (CA_CRLS.includes(url)) return reply(crl(ca, { number: 7, thisUpdate: now - HOUR, nextUpdate: now + net.crlLife, entries }), 'application/octet-stream');
  if (DELTAS.includes(url)) return reply(crl(ca, { number: 900, deltaBase: 7, thisUpdate: now - HOUR, nextUpdate: now + net.crlLife }), 'application/octet-stream');
  throw new Error('unexpected URL ' + url);
};

let generation = 0;
async function worker() {
  const messages = [];
  globalThis.self = { postMessage: message => messages.push(message), close() {} };
  await import(`../extension/crypto/worker.js?instance=${++generation}`);
  const handler = globalThis.self.onmessage;
  return { messages, send: data => handler({ data }) };
}
async function opened(t, next) {
  const start = Date.now();
  t.mock.timers.enable({ apis: ['Date'], now: start });
  reset(next);
  const session = await worker();
  await session.send({ kind: 'open', container: container(), password: PASSWORD, request });
  const message = session.messages.at(-1);
  assert.equal(message.kind, 'opened', message.message);
  assert.equal(message.certificate.trust.revocation.state, 'good');
  return { ...session, start, revocation: message.certificate.trust.revocation, at: offset => t.mock.timers.setTime(start + offset) };
}
const signedNothing = messages => assert.ok(!messages.some(message => message.kind === 'signed'), 'no signature leaves the worker');
// Documents that record whether the worker started signing them.
function watched() {
  const documents = [], seen = { read: false };
  Object.defineProperty(documents, 0, { enumerable: true, get() { seen.read = true; return 'VGVnaW4='; } });
  return { documents, seen };
}

test('OCSP answer expires between opening and confirmation, before five minutes: recheck, revoked blocks', async t => {
  // thisUpdate three minutes before the check: the answer applies for two more minutes only.
  const session = await opened(t, { ocspAge: 3 * MINUTE });
  assert.ok(Math.abs(Date.parse(session.revocation.expires) - (session.start + 2 * MINUTE)) < 1000);
  session.at(2.5 * MINUTE);
  net.ocsp = 'revoked';
  const { documents, seen } = watched();
  await session.send({ kind: 'sign', request: { ...request, documents } });
  assert.equal(session.messages.at(-1).kind, 'error');
  assert.equal(session.messages.at(-1).code, 'REVOCATION_REVOKED');
  assert.equal(net.calls.filter(url => url === OCSP).length, 2, 'the status was requested again');
  assert.equal(seen.read, false, 'checked before any signature is formed');
  signedNothing(session.messages);
});

test('OCSP answer expires before confirmation and the services are down: unavailable blocks', async t => {
  const session = await opened(t, { ocspAge: 3 * MINUTE });
  session.at(2.5 * MINUTE);
  net.ocsp = 'down'; net.crl = 'down';
  await session.send({ kind: 'sign', request });
  assert.equal(session.messages.at(-1).code, 'REVOCATION_UNAVAILABLE');
  signedNothing(session.messages);
});

test('CRL nextUpdate passes between opening and confirmation: recheck, revoked or unavailable blocks', async t => {
  for (const [state, code] of [['revoked', 'REVOCATION_REVOKED'], ['down', 'REVOCATION_UNAVAILABLE']]) {
    const session = await opened(t, { ocsp: 'down', crlLife: 2 * MINUTE });
    assert.equal(session.revocation.certificates[0].source, 'crl+delta');
    assert.ok(Math.abs(Date.parse(session.revocation.expires) - (session.start + 2 * MINUTE)) < 1000);
    session.at(3 * MINUTE);
    net.crl = state; net.calls.length = 0;
    const { documents, seen } = watched();
    await session.send({ kind: 'sign', request: { ...request, documents } });
    assert.equal(session.messages.at(-1).code, code, state);
    assert.ok(net.calls.includes(CA_CRLS[0]), 'the CRL was downloaded again');
    assert.equal(seen.read, false, 'checked before any signature is formed');
    signedNothing(session.messages);
    t.mock.timers.reset();
  }
});

test('a long batch outlasts the evidence: it is checked again before the signature is released', async t => {
  const session = await opened(t, {});
  session.at(MINUTE);
  const documents = ['VGVnaW4='];
  Object.defineProperty(documents, 1, { enumerable: true, get() { session.at(5 * MINUTE + 1000); net.ocsp = 'revoked'; return 'VGVnaW4y'; } });
  await session.send({ kind: 'sign', request: { ...request, documents } });
  assert.equal(session.messages.at(-1).code, 'REVOCATION_REVOKED');
  signedNothing(session.messages);
});

test('a check that outlives its own evidence counts as unavailable', async t => {
  const start = Date.now();
  t.mock.timers.enable({ apis: ['Date'], now: start });
  // The OCSP answer is fresh when verified, but the root CRL download ends after it has lapsed.
  reset({ ocspAge: 4 * MINUTE, slowRoot: () => t.mock.timers.setTime(start + 90000) });
  const session = await worker();
  await session.send({ kind: 'open', container: container(), password: PASSWORD, request });
  const message = session.messages.at(-1);
  assert.equal(message.kind, 'error'); assert.equal(message.code, 'REVOCATION_UNAVAILABLE');
  assert.equal(message.certificate.trust.revocation.reason, 'expired');
});

test('evidence that still applies signs without a request; renewed good evidence signs', async t => {
  let session = await opened(t, {});
  session.at(MINUTE);
  net.calls.length = 0;
  await session.send({ kind: 'sign', request });
  assert.equal(session.messages.at(-1).kind, 'signed');
  assert.deepEqual(net.calls, []);
  t.mock.timers.reset();

  session = await opened(t, { ocspAge: 3 * MINUTE });
  session.at(2.5 * MINUTE);
  net.ocspAge = 0;
  await session.send({ kind: 'sign', request });
  assert.equal(session.messages.at(-1).kind, 'signed');
});
