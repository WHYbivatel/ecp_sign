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

const fixture = name => JSON.parse(readFileSync(new URL(`./fixtures/portals/${name}.json`, import.meta.url), 'utf8'));
const egovLogin = fixture('egov-login');
const egovService = fixture('egov-service-sign');
const nucCabinet = fixture('nuc-cabinet-login');
const nucSdk = fixture('nuc-sdk-login');
const teginEdo = fixture('tegin-edo');
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
