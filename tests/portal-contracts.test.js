import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { SignedXml } from 'xml-crypto';
import { DOMParser } from '@xmldom/xmldom';
import { rsaFixture, PASSWORD } from './helpers/fixtures.js';
import { normalizeRequest, successResponse, errorResponse } from '../extension/signing/protocol.js';
import { serviceOperation } from '../extension/lib/operation-summary.js';
import { openContainer, certificateInfo } from '../extension/crypto/signer.js';
import { signXml } from '../extension/crypto/xml.js';
import { signCms } from '../extension/crypto/cms.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';
import { verifyChain } from '../extension/crypto/chain.js';
import { trustStore } from '../extension/crypto/trust-store.js';
import { checkSignerConstraints } from '../extension/crypto/constraints.js';
import { makeTimestampRequest, verifyTimestampResponse, TSA_URL } from '../extension/crypto/timestamp.js';
import { syntheticTsa } from './helpers/tsa.js';

const fixture = name => JSON.parse(readFileSync(new URL(`./fixtures/portals/${name}.json`, import.meta.url), 'utf8'));
const egovLogin = fixture('egov-login');
const egovService = fixture('egov-service-sign');
const nucCabinet = fixture('nuc-cabinet-login');
const nucSdk = fixture('nuc-sdk-login');
const teginEdo = fixture('tegin-edo-test-chain');
const teginLogin = fixture('tegin-edo-login');
const teginDocument = fixture('tegin-edo-document-sign');
const AUTH = '1.3.6.1.5.5.7.3.2';
const SIGN = '1.3.6.1.5.5.7.3.4';
const pemBytes = pem => new Uint8Array(Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ''), 'base64'));
const withArgs = (base, args) => ({ ...base, args: { ...base.args, ...args } });

test('observed portal requests normalize to the exact documents, purpose and trust policy', () => {
  const login = normalizeRequest(egovLogin.request);
  assert.deepEqual(login.documents, [egovLogin.request.args.data]);
  assert.equal(login.format, 'xml'); assert.equal(login.timestamp, false); assert.equal(login.decode, false);
  assert.deepEqual(login.signerParams.extKeyUsageOids, [AUTH]);
  assert.equal(login.signerParams.chain, undefined);
  assert.equal(login.trustRequired, true, 'eGov sends no chain: only certificates chaining to NUC roots are acceptable');
  assert.deepEqual(serviceOperation(login, egovLogin.origin)?.button, 'Подтвердить вход');

  const service = normalizeRequest(egovService.request);
  assert.deepEqual(service.signerParams.extKeyUsageOids, [SIGN]); assert.equal(service.trustRequired, true);
  assert.equal(serviceOperation(service, egovService.origin), null, 'a service XML must keep its full document preview');

  const cabinet = normalizeRequest(nucCabinet.request);
  assert.deepEqual(cabinet.documents, [nucCabinet.request.args.data]);
  assert.equal(cabinet.timestamp, false); assert.equal(cabinet.trustRequired, true);
  assert.equal(cabinet.signerParams.chain.length, 12);
  assert.ok(serviceOperation(cabinet, nucCabinet.origin), 'NUC challenge with standalone declaration and indentation is recognised');
  assert.equal(serviceOperation(cabinet, 'https://nca.pki.gov.kz.evil.test'), null);

  const sdk = normalizeRequest(nucSdk.request);
  assert.equal(sdk.trustRequired, false, 'chain: [] makes the chain optional as documented by NUC');

  const auth = normalizeRequest(teginEdo.requests.authChallenge);
  assert.equal(auth.format, 'cms'); assert.equal(auth.decode, true); assert.equal(auth.encapsulate, true); assert.equal(auth.digested, false);
  const document = normalizeRequest(teginEdo.requests.documentSign);
  assert.equal(document.encapsulate, false); assert.equal(document.decode, true);
});

test('Tegin EDO production defaults (2961da5, owner-reported) require the NUC chain; only the document asks for a timestamp', () => {
  for (const profile of [teginLogin, teginDocument]) {
    assert.equal(Object.hasOwn(profile.request.args.signerParams, 'chain'), false, 'production build without VITE_ALLOW_TEST_CHAIN omits chain');
    assert.match(profile.deployment, /не установлено/);
  }
  const login = normalizeRequest(teginLogin.request);
  assert.equal(login.format, 'cms'); assert.equal(login.decode, true); assert.equal(login.digested, false);
  assert.equal(login.trustRequired, true); assert.equal(login.timestamp, false); assert.equal(login.encapsulate, true);
  assert.deepEqual(login.signerParams.extKeyUsageOids, [AUTH]); assert.equal(login.signerParams.chain, undefined);
  assert.deepEqual(login.documents, [teginLogin.request.args.data]);

  const document = normalizeRequest(teginDocument.request);
  assert.equal(document.format, 'cms'); assert.equal(document.decode, true); assert.equal(document.digested, false);
  assert.equal(document.trustRequired, true); assert.equal(document.timestamp, true); assert.equal(document.encapsulate, false);
  assert.deepEqual(document.signerParams.extKeyUsageOids, [SIGN]); assert.equal(document.signerParams.chain, undefined);
});

test('Tegin EDO test-chain configurations stay distinct from production: chain [] drops required trust, TSA follows VITE_CMS_TSP', () => {
  assert.match(teginEdo.configuration, /VITE_ALLOW_TEST_CHAIN=true/);
  const expected = { authChallenge: [false, true], documentSign: [false, false], documentSignTsa: [true, false] };
  for (const [name, [timestamp, encapsulate]] of Object.entries(expected)) {
    assert.ok(teginEdo.variants[name], `${name} is labelled with its configuration`);
    const normalized = normalizeRequest(teginEdo.requests[name]);
    assert.equal(normalized.trustRequired, false, name); assert.equal(normalized.timestamp, timestamp, name); assert.equal(normalized.encapsulate, encapsulate, name);
  }
});

test('Tegin EDO production profiles refuse a synthetic certificate outside the bundled NUC chain', async () => {
  for (const [profile, purpose] of [[teginLogin, 'clientAuth'], [teginDocument, 'emailProtection']]) {
    const key = rsaFixture({ purpose });
    const leaf = certificateInfo(pemBytes(key.certificate));
    const request = normalizeRequest(profile.request);
    // The worker passes site anchors only for a non-empty chain; production sends none.
    const trust = await verifyChain(leaf, [], { anchors: request.signerParams.chain?.length ? request.signerParams.chain.map(pemBytes) : undefined });
    assert.equal(trust.trusted, false);
    assert.throws(() => checkSignerConstraints(leaf, request, trust), /доверенную цепочку/, profile.portal);
    const wrongPurpose = rsaFixture({ purpose: purpose === 'clientAuth' ? 'emailProtection' : 'clientAuth' });
    assert.throws(() => checkSignerConstraints(certificateInfo(pemBytes(wrongPurpose.certificate)), request, { trusted: true }), /(аутентификации|Назначение)/);
  }
});

test('Tegin EDO document profile: a failed or untrusted required timestamp never yields an unstamped signature', async () => {
  const request = normalizeRequest(teginDocument.request);
  assert.equal(request.timestamp, true);
  const key = rsaFixture({ purpose: 'emailProtection' });
  const signer = await openContainer(key.container, PASSWORD);
  const tsa = syntheticTsa();
  const bytes = new Uint8Array(Buffer.from(teginDocument.request.args.data, 'base64'));
  const original = globalThis.fetch;
  const calls = [];
  const reply = (body, type = 'application/timestamp-reply', status = 200) => new Response(body, { status, headers: { 'content-type': type } });
  const cases = [
    ['service unreachable', async () => { throw new TypeError('fetch failed'); }, /недоступна. Подпись без запрошенной метки не выдавалась/],
    ['HTTP error', async () => reply('busy', 'text/plain', 503), /неожиданный ответ/],
    ['HTML instead of a timestamp reply', async () => reply('<html></html>', 'text/html'), /неожиданный ответ/],
    ['malformed DER', async () => reply(new Uint8Array([0x30, 0x82, 0xff, 0xff, 0x01])), /./],
    ['rejection status', async () => reply(new Uint8Array([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02])), /не выдал/],
    ['well-formed reply from a TSA outside the NUC chain', async (url, init) => reply(tsa.reply(Buffer.from(init.body))), /службы меток времени не прошёл проверку/]
  ];
  try {
    for (const [name, handler, message] of cases) {
      globalThis.fetch = async (url, init) => { calls.push({ url, init }); return handler(url, init); };
      let result;
      await assert.rejects(async () => { result = await signCms(signer, bytes, { encapsulate: request.encapsulate, digested: request.digested, timestamp: request.timestamp }); }, message, name);
      assert.equal(result, undefined, `${name}: no signature is returned`);
    }
  } finally { globalThis.fetch = original; signer.destroy(); tsa.destroy(); }
  assert.equal(calls.length, cases.length);
  for (const { url, init } of calls) {
    assert.equal(url, TSA_URL); assert.equal(init.credentials, 'omit'); assert.equal(init.redirect, 'error');
    assert.ok(!Buffer.from(init.body).includes(Buffer.from(bytes)), 'the TSA request carries no document bytes');
  }
});

test('separate synthetic scenario: explicit test anchors let the document profile produce a verified detached CAdES-T', async () => {
  const request = normalizeRequest(teginDocument.request);
  const key = rsaFixture({ purpose: 'emailProtection' });
  const leaf = certificateInfo(pemBytes(key.certificate));
  // Test-only anchors: the extension never trusts a self-signed signer or TSA for a chain-less request.
  checkSignerConstraints(leaf, request, await verifyChain(leaf, [], { anchors: [pemBytes(key.certificate)] }));
  const signer = await openContainer(key.container, PASSWORD);
  const tsa = syntheticTsa();
  const bytes = new Uint8Array(Buffer.from(teginDocument.request.args.data, 'base64'));
  const stamps = [];
  try {
    const signed = await signCms(signer, bytes, { encapsulate: request.encapsulate, digested: request.digested, timestamp: request.timestamp,
      timestampRequester: async signature => { const query = await makeTimestampRequest(signature); return verifyTimestampResponse(tsa.reply(query.body), query, { anchors: [tsa.anchor] }); },
      onTimestamp: stamp => stamps.push(stamp) });
    const verified = await verifyCms(signed, { detached: bytes });
    assert.equal(verified.valid, true); assert.equal(verified.attached, false);
    assert.ok(verified.signers[0].info.value.some(node => node.tagClass === 128 && node.type === 1), 'unsigned attributes carry the timestamp token');
    assert.equal(stamps.length, 1); assert.equal(stamps[0].authority, 'Tegin synthetic TSA'); assert.equal(stamps[0].revocation, 'not-checked');
    const changed = Uint8Array.from(bytes); changed[changed.length - 2] ^= 1;
    await assert.rejects(verifyCms(signed, { detached: changed }));
  } finally { signer.destroy(); tsa.destroy(); }
});

test('portal XML is signed over the canonical document, keeps its declaration and rejects changes', async () => {
  const key = rsaFixture({ purpose: 'clientAuth' });
  const signer = await openContainer(key.container, PASSWORD);
  try {
    for (const xml of [egovLogin.request.args.data, nucCabinet.request.args.data, egovService.request.args.data]) {
      const signed = await signXml(signer, xml);
      assert.match(signed, /^<\?xml version="1\.0" encoding="UTF-8"( standalone="yes")?\?>/);
      const doc = new DOMParser().parseFromString(signed, 'application/xml');
      const verifier = new SignedXml({ publicCert: key.certificate, getCertFromKeyInfo: () => null });
      verifier.loadSignature(doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0]);
      assert.equal(verifier.checkSignature(signed), true);
      const tampered = signed.replace(/PORTAL|00000000-0000-4000-8000-000000000000|SYNTH-0001/, 'CHANGED');
      assert.notEqual(tampered, signed);
      const other = new SignedXml({ publicCert: key.certificate, getCertFromKeyInfo: () => null });
      other.loadSignature(new DOMParser().parseFromString(tampered, 'application/xml').getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0]);
      assert.throws(() => { if (!other.checkSignature(tampered)) throw new Error('invalid'); });
    }
  } finally { signer.destroy(); }
});

test('Tegin EDO profile signs the decoded challenge bytes attached and the document bytes detached', async () => {
  const key = rsaFixture({ purpose: 'clientAuth' });
  const signer = await openContainer(key.container, PASSWORD);
  try {
    const challenge = Buffer.from(teginEdo.requests.authChallenge.args.data, 'base64');
    const attached = await signCms(signer, new Uint8Array(challenge), { encapsulate: true, cades: false });
    assert.deepEqual(Buffer.from((await verifyCms(attached)).content), challenge);
    const bytes = new Uint8Array(Buffer.from(teginEdo.requests.documentSign.args.data, 'base64'));
    const detached = await signCms(signer, bytes, { encapsulate: false, cades: false });
    assert.equal((await verifyCms(detached, { detached: bytes })).valid, true);
    const changed = Uint8Array.from(bytes); changed[changed.length - 2] ^= 1;
    await assert.rejects(verifyCms(detached, { detached: changed }));
  } finally { signer.destroy(); }
});

test('the NUC cabinet CA list covers the bundled trust store and site anchors never add trust to a foreign certificate', async () => {
  const listed = new Set(nucCabinet.request.args.signerParams.chain.map(pem => createHash('sha256').update(pemBytes(pem)).digest('hex')));
  for (const entry of trustStore) assert.ok(listed.has(entry.sha256), `${entry.name} is published by NUC`);
  const now = Date.parse('2026-11-09T00:00:00Z');
  const current = [];
  for (const pem of nucCabinet.request.args.signerParams.chain) {
    try { const info = certificateInfo(pemBytes(pem)); if (now <= Date.parse(info.summary.notAfter)) current.push(createHash('sha256').update(pemBytes(pem)).digest('hex')); }
    catch (error) { assert.equal(error.code, 'UNSUPPORTED_CERTIFICATE_ALGORITHM'); }
  }
  assert.deepEqual(current.sort(), trustStore.map(entry => entry.sha256).sort(), 'every currently valid NUC CA is bundled');

  const key = rsaFixture({ purpose: 'clientAuth' });
  const leaf = certificateInfo(pemBytes(key.certificate));
  const anchors = nucCabinet.request.args.signerParams.chain.map(pemBytes);
  const trust = await verifyChain(leaf, [], { anchors });
  assert.equal(trust.trusted, false); assert.match(trust.reason, /Цепочка до доверенного корня не найдена/);
  const request = normalizeRequest(nucCabinet.request);
  assert.throws(() => checkSignerConstraints(leaf, request, trust), /доверенную цепочку/);
  const bundled = await verifyChain(leaf);
  assert.throws(() => checkSignerConstraints(leaf, normalizeRequest(egovLogin.request), bundled), /доверенную цепочку/);
});

test('portal-shaped requests fail explicitly instead of being weakened', () => {
  const cases = [
    [withArgs(egovLogin.request, { allowedStorages: ['AKKaztokenStore', 'AKKZIDCardStore'] }), /PKCS#12/],
    [withArgs(egovLogin.request, { signingParams: { tsaProfile: {} } }), /Метка времени/],
    [withArgs(egovLogin.request, { signingParams: { digested: true } }), /XML/],
    [withArgs(egovLogin.request, { signingParams: { xpath: '//login' } }), /Неизвестные параметры/],
    [withArgs(egovLogin.request, { format: 'pdf' }), /CMS, XML/],
    [withArgs(nucCabinet.request, { signerParams: { extKeyUsageOids: [AUTH], chain: [''] } }), /цепочка/],
    [withArgs(nucCabinet.request, { signerParams: { extKeyUsageOids: [AUTH], policy: 'any' } }), /Условия выбора/],
    [withArgs(nucCabinet.request, { signerParams: { extKeyUsageOids: 'clientAuth' } }), /назначение/],
    [withArgs(teginEdo.requests.documentSign, { signingParams: { decode: true, encapsulate: true, digested: true } }), /encapsulate=false/],
    [withArgs(teginEdo.requests.documentSign, { signingParams: { tsaProfile: { url: 'http://tsa.invalid' } } }), /tsaProfile=\{\}/],
    [withArgs(teginEdo.requests.documentSign, { data: Array(11).fill('AA==') }), /данные/],
    [{ module: 'kz.gov.pki.knca.basics', method: 'signXml', args: {} }, /не поддерживается/],
    [{ module: 'kz.digiflow.mobile.extensions', method: 'getVersion' }, /не поддерживается/]
  ];
  for (const [request, message] of cases) assert.throws(() => normalizeRequest(request), message, JSON.stringify(request).slice(0, 120));
  assert.throws(() => normalizeRequest(withArgs(egovLogin.request, { allowedStorages: ['', 'AKKaztokenStore'] })), /PKCS#12/);
});

test('an empty hidden storage field ([""] from split) leaves basics.sign unrestricted, as for generateCsr', () => {
  const empty = normalizeRequest(withArgs(nucCabinet.request, { allowedStorages: [''] }));
  assert.deepEqual(empty, normalizeRequest(withArgs(nucCabinet.request, { allowedStorages: undefined })));
  assert.equal(empty.trustRequired, true);
  assert.equal(empty.signerParams.chain.length, nucCabinet.request.args.signerParams.chain.length);
});

// signXml() of /js/signature-basics.js on the cabinet pages that sign an application (IS, reissue)
// or confirm an employee's application. The EKU list is the page's hidden key purpose, split by ",";
// the real values behind the login are not observed, so the first-head OID from the NUC SDK is used.
test('NUC application signing and first-head confirmation keep purpose, trust and exact XML', () => {
  const FIRST_HEAD = '1.2.398.3.3.4.1.2.1';
  const application = '<?xml version="1.0" encoding="UTF-8" standalone="no"?><application><id>00000000</id><action>confirm</action></application>';
  const confirm = (keyPurpose, chain = nucCabinet.request.args.signerParams.chain) => normalizeRequest(withArgs(nucCabinet.request, {
    allowedStorages: [''], format: 'xml', data: application, signingParams: { decode: false, encapsulate: false, digested: false, tsaProfile: null },
    signerParams: { extKeyUsageOids: keyPurpose ? keyPurpose.split(',') : [], chain } }));
  const request = confirm(`${SIGN},${FIRST_HEAD}`);
  assert.deepEqual(request.documents, [application]);
  assert.equal(request.format, 'xml'); assert.equal(request.timestamp, false); assert.equal(request.trustRequired, true);
  assert.deepEqual(request.signerParams.extKeyUsageOids, [SIGN, FIRST_HEAD]);
  const info = eku => ({ ca: false, keyOid: '1.2.840.113549.1.1.1', keyUsage: 192, eku, summary: { notBefore: '2025-01-01T00:00:00Z' } });
  const trusted = { trusted: true, ncaTrusted: true };
  assert.doesNotThrow(() => checkSignerConstraints(info([SIGN, FIRST_HEAD]), request, trusted));
  // An employee's signing certificate cannot confirm on behalf of the first head.
  assert.throws(() => checkSignerConstraints(info([SIGN, '1.2.398.3.3.4.1.2.2']), request, trusted), new RegExp(FIRST_HEAD.replaceAll('.', '\\.')));
  assert.throws(() => checkSignerConstraints(info([SIGN, FIRST_HEAD]), request, { trusted: false, reason: 'нет цепочки' }), /доверенную цепочку/);
  // An empty purpose field allows any purpose; an empty CA field is refused rather than treated as "no chain".
  assert.deepEqual(confirm('').signerParams.extKeyUsageOids, []);
  assert.throws(() => confirm(`${SIGN},${FIRST_HEAD}`, ['']), /цепочка/);
});

test('response envelopes match what the observed portal clients read', () => {
  const basics = successResponse(egovLogin.request, { result: ['<signed/>'] });
  assert.deepEqual(basics, { status: true, body: { result: ['<signed/>'] } });
  assert.equal(basics.body.result.length, 1, 'eGov proceeds only when body.result has items');
  const cancelled = errorResponse(egovLogin.request, 'Операция отменена пользователем.', true);
  assert.deepEqual(cancelled, { status: true, body: {} }, 'ncalayer-js-client reports canceledByUser; eGov and NUC ignore it');
  const failed = errorResponse(nucCabinet.request, 'Сайт не разрешает файловые ключи PKCS#12.');
  assert.equal(failed.status, false); assert.equal(typeof failed.code, 'string'); assert.equal(failed.body, undefined);
  const probe = errorResponse({ module: 'kz.digiflow.mobile.extensions', method: 'getVersion' }, 'Этот метод NCALayer пока не поддерживается.');
  assert.equal(probe.code, '400'); assert.equal(probe.responseObject, null);
  assert.equal(probe.status, undefined, 'a commonUtils-style error must not look like a basics result');
});
