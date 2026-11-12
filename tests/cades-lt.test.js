import test from 'node:test';
import assert from 'node:assert/strict';
import { longTermHarness, editSignedData } from './helpers/long-term.js';
import { gostFixture, PASSWORD } from './helpers/fixtures.js';
import { signLongTerm, verifyLongTerm, addArchiveTimestamp, addValidationData, checkLongTermKey, LT_OIDS, LONG_TERM_MESSAGE } from '../extension/crypto/cades-lt.js';
import { signCms } from '../extension/crypto/cms.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';
import { openContainer } from '../extension/crypto/signer.js';
import { forge } from '../extension/crypto/encoding.js';

const h = await longTermHarness();
test.after(() => h.destroy());
const data = new TextEncoder().encode('Tegin synthetic long-term document');
const sign = (level, options = {}) => signLongTerm(h.signer, data, { level, signerPath: h.signerPath, evidence: h.evidence, requester: h.requester, ...options });
const rejects = (promise, pattern) => assert.rejects(promise, error => { assert.equal(error.code, 'CADES_LT', error.message); assert.match(error.message, pattern); return true; });
const signedAttributeTypes = cms => {
  const asn1 = forge.asn1.fromDer(forge.util.binary.raw.encode(cms));
  const signerInfo = asn1.value[1].value[0].value.at(-1).value[0];
  return signerInfo.value[3].value.map(item => forge.asn1.derToOid(item.value[0].value));
};
const unsignedTypes = cms => {
  const asn1 = forge.asn1.fromDer(forge.util.binary.raw.encode(cms));
  const signerInfo = asn1.value[1].value[0].value.at(-1).value[0];
  return signerInfo.value.at(-1).value.map(item => forge.asn1.derToOid(item.value[0].value));
};
const ltaPromise = sign('lta');

test('CAdES-LT embeds the signer and TSA paths, CRLs and OCSP responses obtained after the time-stamp', async () => {
  const { cms, stamp, signerStatus, stampStatus } = await sign('lt');
  const summary = await verifyLongTerm(cms, { anchors: h.anchors });
  assert.deepEqual(summary, { certificates: 4, crls: 1, ocsp: 2, archives: [] });
  assert.equal(signerStatus.state, 'good'); assert.equal(stampStatus.state, 'good');
  assert.ok(stamp.time);
  assert.ok(signedAttributeTypes(cms).includes('1.2.840.113549.1.9.5'), 'EN 319 122-1 B-B signing-time');
  assert.deepEqual(unsignedTypes(cms), [LT_OIDS.signatureTimestamp]);
  const verified = await verifyCms(cms, { anchors: h.anchors });
  assert.equal(verified.signers.length, 1);
  const version = forge.asn1.fromDer(forge.util.binary.raw.encode(cms)).value[1].value[0].value[0].value.charCodeAt(0);
  assert.equal(version, 5, 'RFC 5652: other RevocationInfoChoice requires SignedData v5');
});

test('existing CAdES formats keep their signed attributes', async () => {
  const cms = await signCms(h.signer, data, { cades: true });
  assert.ok(!signedAttributeTypes(cms).includes('1.2.840.113549.1.9.5'));
});

test('CAdES-LTA adds one archive-time-stamp-v3 with ats-hash-index-v3 and verifies it', async () => {
  const { cms, archive } = await ltaPromise;
  assert.deepEqual(unsignedTypes(cms), [LT_OIDS.signatureTimestamp, LT_OIDS.archiveTimestampV3]);
  const summary = await verifyLongTerm(cms, { anchors: h.anchors });
  assert.equal(summary.archives.length, 1);
  assert.equal(summary.archives[0].time, archive.time);
  assert.equal(h.stampCount() >= 3, true);
});

test('detached CAdES-LTA needs the original document for the archive imprint', async () => {
  const { cms } = await sign('lta', { encapsulate: false });
  assert.equal((await verifyLongTerm(cms, { detached: data, anchors: h.anchors })).archives.length, 1);
  await rejects(verifyLongTerm(cms, { anchors: h.anchors }), /исходный документ/);
  const other = data.slice(); other[0] ^= 1;
  await assert.rejects(verifyLongTerm(cms, { detached: other, anchors: h.anchors }), /другой подписи|не совпадает/);
});

test('re-archiving covers the previous archive time-stamp and the new validation data', async () => {
  const { cms, archive } = await ltaPromise;
  const status = await h.evidence(archive.certificates);
  const renewed = (await addArchiveTimestamp(addValidationData(cms, status.evidence), { requester: h.requester })).cms;
  assert.equal((await verifyLongTerm(renewed, { anchors: h.anchors })).archives.length, 2);
});

test('validation data added after the archive time-stamp is allowed', async () => {
  const { cms } = await ltaPromise;
  const extended = addValidationData(cms, { certificates: [h.pki.responder.der] });
  assert.equal((await verifyLongTerm(extended, { anchors: h.anchors })).certificates, 5);
  assert.deepEqual(addValidationData(extended, { certificates: [h.pki.responder.der] }), extended, 'duplicates are not repeated');
});

test('removing or replacing archived evidence breaks the archive time-stamp', async () => {
  const { cms } = await ltaPromise;
  const withoutOcsp = editSignedData(cms, ({ crls }) => crls.splice(crls.findIndex(item => item.type === 1), 1));
  await rejects(verifyLongTerm(withoutOcsp, { anchors: h.anchors }), /данные об отзыве/);
  const withoutCrl = editSignedData(cms, ({ crls }) => crls.splice(crls.findIndex(item => item.type === 16), 1));
  await rejects(verifyLongTerm(withoutCrl, { anchors: h.anchors }), /данные об отзыве/);
  const withoutCertificate = editSignedData(cms, ({ certificates }) => certificates.pop());
  await rejects(verifyLongTerm(withoutCertificate, { anchors: h.anchors }), /сертификаты/);
  const changedCertificate = editSignedData(cms, ({ certificates }) => { const last = certificates.at(-1); const value = forge.asn1.toDer(last).getBytes(); certificates[certificates.length - 1] = forge.asn1.fromDer(value.slice(0, -1) + String.fromCharCode(value.charCodeAt(value.length - 1) ^ 1)); });
  await rejects(verifyLongTerm(changedCertificate, { anchors: h.anchors }), /сертификаты/);
});

test('changing the signature time-stamp or the content breaks the archive time-stamp', async () => {
  const { cms } = await ltaPromise;
  const asn1 = forge.asn1.fromDer(forge.util.binary.raw.encode(cms));
  const unsigned = asn1.value[1].value[0].value.at(-1).value[0].value.at(-1);
  unsigned.value.shift();
  const strippedStamp = Uint8Array.from(forge.asn1.toDer(asn1).getBytes(), c => c.charCodeAt(0));
  await rejects(verifyLongTerm(strippedStamp, { anchors: h.anchors }), /неподписанные атрибуты/);
  const changed = editSignedData(cms, ({ content }) => { content.value = content.value.replace('Tegin', 'Tegim'); });
  await assert.rejects(verifyLongTerm(changed, { anchors: h.anchors }), /другой подписи|Метка/);
});

test('archive time-stamps are verified against the trust anchors', async () => {
  const { cms } = await ltaPromise;
  await assert.rejects(verifyLongTerm(cms, { anchors: [] }), /Сертификат|довер/);
});

test('an archive time-stamp requires CAdES-T and a single signer', async () => {
  const plain = await signCms(h.signer, data, { cades: true });
  await rejects(addArchiveTimestamp(plain, { requester: h.requester }), /CAdES-T/);
  await rejects(verifyLongTerm(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]), {}), /Некорректная структура/);
  await rejects(verifyLongTerm(new Uint8Array([0x30, 0x80]), {}), /Некорректная структура/);
});

test('long-term signing is refused for GOST keys and when revocation evidence is not good', async () => {
  const gost = await openContainer(gostFixture('512').container, PASSWORD);
  try {
    assert.throws(() => checkLongTermKey(gost), error => error.code === 'CADES_LT' && error.message === LONG_TERM_MESSAGE);
    await rejects(signLongTerm(gost, data, { level: 'lt', signerPath: [], evidence: h.evidence, requester: h.requester }), /ГОСТ/);
  } finally { gost.destroy(); }
  await rejects(sign('b'), /Неизвестный уровень/);
  const revoked = await longTermHarness({ ocspStatus: 'revoked' });
  try {
    await assert.rejects(signLongTerm(revoked.signer, data, { level: 'lt', signerPath: revoked.signerPath, evidence: revoked.evidence, requester: revoked.requester }), /revocation revoked/);
  } finally { revoked.destroy(); }
});
