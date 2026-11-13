import test from 'node:test';
import assert from 'node:assert/strict';
import { longTermHarness, evaluateHistorical } from './helpers/long-term.js';
import { issue, ocspResponse, parseOcspRequest, crl, serialHex, OCSP_SIGNING } from './helpers/pki.js';
import { signLongTerm, verifyLongTerm, embeddedRevocation, addValidationData } from '../extension/crypto/cades-lt.js';
import { historicalRevocation } from '../extension/crypto/historical.js';
import { buildOcspRequest } from '../extension/crypto/ocsp.js';
import { signCms } from '../extension/crypto/cms.js';

const DAY = 86400000, HOUR = 3600000;
const h = await longTermHarness();
test.after(() => h.destroy());
const data = new TextEncoder().encode('Tegin synthetic historical revocation document');

const evaluate = cms => evaluateHistorical(h, cms);

test('CAdES-LT: every certificate of the signer and TSA paths is good at the time-stamp from embedded OCSP and CRL', async () => {
  const { cms } = await signLongTerm(h.signer, data, { level: 'lt', signerPath: h.signerPath, evidence: h.evidence, requester: h.requester });
  const result = await evaluate(cms);
  assert.equal(result.state, 'good');
  assert.deepEqual(result.certificates.map(entry => [entry.role, entry.ca, entry.source, entry.provenBy]),
    [['signer', false, 'ocsp', 'present'], ['signer', true, 'crl', 'present'], ['timestamp', false, 'ocsp', 'present'], ['timestamp', true, 'crl', 'present']]);
  assert.deepEqual(result.certificates.map(entry => entry.freshness), ['after', 'window', 'after', 'window'], 'OCSP after the stamp; CRLs published before it and still current');
});

test('CAdES-LTA: the embedded evidence is proven to exist by the archive time-stamp', async () => {
  const { cms } = await signLongTerm(h.signer, data, { level: 'lta', signerPath: h.signerPath, evidence: h.evidence, requester: h.requester });
  const result = await evaluate(cms);
  assert.equal(result.state, 'good');
  assert.ok(result.certificates.every(entry => entry.provenBy === 'archive'));
  const verified = await verifyLongTerm(cms, { anchors: h.anchors });
  assert.equal(verified.archives[0].revocationItems.length, embeddedRevocation(cms).length);
});

test('CAdES-T without embedded evidence is indeterminate (NO_EVIDENCE), never good', async () => {
  const cms = await signCms(h.signer, data, { cades: true, timestamp: true, timestampRequester: h.requester });
  const result = await evaluate(cms);
  assert.equal(result.state, 'indeterminate');
  assert.ok(result.certificates.every(entry => entry.state === 'indeterminate' && entry.code === 'NO_EVIDENCE'));
});

// A hand-built path: root, CA, leaf valid well before the moment, a responder valid until `responderUntil`.
function pastPki({ responderUntil = Date.now() + 30 * DAY } = {}) {
  const root = issue({ name: 'Tegin historical root', ca: true, notBefore: Date.now() - 60 * DAY });
  const ca = issue({ name: 'Tegin historical CA', issuer: root, ca: true, notBefore: Date.now() - 60 * DAY });
  const leaf = issue({ name: 'Tegin historical leaf', issuer: ca, notBefore: Date.now() - 30 * DAY });
  const responder = issue({ name: 'Tegin historical OCSP', issuer: ca, eku: [OCSP_SIGNING], nocheck: true, notBefore: Date.now() - 30 * DAY, notAfter: responderUntil });
  return { root, ca, leaf, responder, path: [leaf.info, ca.info, root.info] };
}
async function leafOcsp(pki, options) {
  const request = parseOcspRequest((await buildOcspRequest(pki.leaf.info, pki.ca.info)).body);
  return ocspResponse(request, { signer: pki.responder, nonce: null, ...options });
}
const items = (...raws) => raws.map(([kind, raw], index) => ({ kind, raw, index }));
const leafEntry = result => result.certificates.find(entry => !entry.ca);
const run = (pki, evidence, moment, archives) => historicalRevocation({ paths: [{ role: 'signer', certificates: pki.path, time: new Date(moment).toISOString() }], evidence, archives });

test('evidence issued before the moment cannot show "good" at the moment', async () => {
  const pki = pastPki(), moment = Date.now() - 2 * DAY;
  const result = await run(pki, items(['ocsp', await leafOcsp(pki, { thisUpdate: moment - HOUR })], ['crl', crl(pki.root, { thisUpdate: moment + HOUR })]), moment);
  assert.equal(leafEntry(result).state, 'indeterminate');
  assert.equal(leafEntry(result).code, 'EVIDENCE_BEFORE_TIME');
  assert.equal(result.certificates.find(entry => entry.ca).state, 'good');
  assert.equal(result.state, 'indeterminate');
});

test('a CRL published before the moment counts only while the moment is before its nextUpdate', async () => {
  const pki = pastPki(), moment = Date.now() - 2 * DAY;
  const leaf = ['ocsp', await leafOcsp(pki, { thisUpdate: moment + HOUR })];
  const current = await run(pki, items(leaf, ['crl', crl(pki.root, { thisUpdate: moment - DAY, nextUpdate: moment + DAY })]), moment);
  assert.equal(current.state, 'good');
  assert.equal(current.certificates.find(entry => entry.ca).freshness, 'window');
  const lapsed = await run(pki, items(leaf, ['crl', crl(pki.root, { thisUpdate: moment - 2 * DAY, nextUpdate: moment - DAY })]), moment);
  assert.equal(lapsed.certificates.find(entry => entry.ca).code, 'EVIDENCE_BEFORE_TIME');
});

test('a revocation dated before the moment is conclusive; one dated after it leaves the signature good at the moment', async () => {
  const pki = pastPki(), moment = Date.now() - 2 * DAY;
  const caCrl = ['crl', crl(pki.root, { thisUpdate: moment + HOUR })];
  const before = await run(pki, items(['ocsp', await leafOcsp(pki, { status: 'revoked', revocationTime: moment - HOUR, reason: 1, thisUpdate: moment - 30 * 60000 })], caCrl), moment);
  assert.equal(before.state, 'revoked');
  assert.equal(leafEntry(before).reason, 'keyCompromise');
  const after = await run(pki, items(['ocsp', await leafOcsp(pki, { status: 'revoked', revocationTime: moment + HOUR, reason: 1, thisUpdate: moment + 2 * HOUR })], caCrl), moment);
  assert.equal(after.state, 'good');
  assert.equal(leafEntry(after).revokedLater, new Date(Math.floor((moment + HOUR) / 1000) * 1000).toISOString());
});

test('a CRL entry before the moment is revoked; certificateHold before the moment is not conclusive', async () => {
  const pki = pastPki(), moment = Date.now() - 2 * DAY;
  const caCrl = ['crl', crl(pki.root, { thisUpdate: moment + HOUR })];
  const revoked = await run(pki, items(['crl', crl(pki.ca, { thisUpdate: moment + HOUR, entries: [{ serial: serialHex(pki.leaf), time: moment - DAY, reason: 1 }] })], caCrl), moment);
  assert.equal(leafEntry(revoked).state, 'revoked'); assert.equal(leafEntry(revoked).source, 'crl');
  const held = await run(pki, items(['crl', crl(pki.ca, { thisUpdate: moment - HOUR, entries: [{ serial: serialHex(pki.leaf), time: moment - DAY, reason: 6 }] })], caCrl), moment);
  assert.equal(leafEntry(held).state, 'indeterminate');
});

test('a responder that expired before the evidence is proven to exist needs an archive time-stamp before its expiry', async () => {
  const pki = pastPki({ responderUntil: Date.now() - DAY }), moment = Date.now() - 5 * DAY;
  const evidence = items(['ocsp', await leafOcsp(pki, { thisUpdate: moment + HOUR, producedAt: moment + HOUR })], ['crl', crl(pki.root, { thisUpdate: moment + HOUR })]);
  const unproven = await run(pki, evidence, moment);
  assert.equal(leafEntry(unproven).code, 'EVIDENCE_NOT_PROVEN');
  const archived = await run(pki, evidence, moment, [{ time: new Date(moment + 2 * HOUR).toISOString(), revocationItems: [0, 1] }]);
  assert.equal(leafEntry(archived).state, 'good'); assert.equal(leafEntry(archived).provenBy, 'archive');
  const late = await run(pki, evidence, moment, [{ time: new Date(Date.now() - HOUR).toISOString(), revocationItems: [0] }]);
  assert.equal(leafEntry(late).code, 'EVIDENCE_NOT_PROVEN');
});

test('tampered, foreign or unrelated evidence never counts', async () => {
  const pki = pastPki(), other = pastPki(), moment = Date.now() - 2 * DAY;
  const caCrl = ['crl', crl(pki.root, { thisUpdate: moment + HOUR })];
  const tampered = await run(pki, items(['ocsp', await leafOcsp(pki, { thisUpdate: moment + HOUR, tamper: true })], caCrl), moment);
  assert.equal(leafEntry(tampered).code, 'OCSP_SIGNATURE');
  const foreign = await run(pki, items(['ocsp', await leafOcsp(other, { thisUpdate: moment + HOUR })], ['crl', crl(other.ca, { thisUpdate: moment + HOUR })], caCrl), moment);
  assert.equal(leafEntry(foreign).code, 'NO_EVIDENCE');
  const unknown = await run(pki, items(['ocsp', await leafOcsp(pki, { status: 'unknown', thisUpdate: moment + HOUR })], caCrl), moment);
  assert.equal(leafEntry(unknown).code, 'STATUS_UNKNOWN');
  const statusAfterResponse = await run(pki, items(['ocsp', await leafOcsp(pki, { thisUpdate: moment + 2 * HOUR, producedAt: moment + HOUR })], caCrl), moment);
  assert.equal(leafEntry(statusAfterResponse).code, 'OCSP_FUTURE');
});

test('SHA-1 CertIDs of embedded responses are matched', async () => {
  const pki = pastPki(), moment = Date.now() - 2 * DAY;
  const request = parseOcspRequest((await buildOcspRequest(pki.leaf.info, pki.ca.info, { hash: 'SHA-1' })).body);
  const result = await run(pki, items(['ocsp', ocspResponse(request, { signer: pki.responder, nonce: null, thisUpdate: moment + HOUR })], ['crl', crl(pki.root, { thisUpdate: moment + HOUR })]), moment);
  assert.equal(result.state, 'good');
});

test('evidence added after the archive time-stamp is proven only by the present', async () => {
  const { cms } = await signLongTerm(h.signer, data, { level: 'lta', signerPath: h.signerPath, evidence: h.evidence, requester: h.requester });
  const status = await h.evidence(h.signerPath);
  const extended = addValidationData(cms, { ocsp: status.evidence.ocsp });
  const verified = await verifyLongTerm(extended, { anchors: h.anchors });
  const evidence = embeddedRevocation(extended);
  assert.equal(evidence.length, verified.archives[0].revocationItems.length + status.evidence.ocsp.length);
  assert.ok(evidence.slice(-1).every(item => !verified.archives[0].revocationItems.includes(item.index)));
});
