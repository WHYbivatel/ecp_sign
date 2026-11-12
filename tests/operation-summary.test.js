import test from 'node:test';
import assert from 'node:assert/strict';
import { serviceOperation, keyInfoResult } from '../extension/lib/operation-summary.js';
import { certificateInfo } from '../extension/crypto/signer.js';
import { unbase64 } from '../extension/crypto/encoding.js';
import { gostFixture } from './helpers/fixtures.js';
import { readFileSync } from 'node:fs';
import { kncaKeyTypes } from '../extension/crypto/constraints.js';

test('certificate information for a site carries the public certificate fields only', () => {
  const fixture = gostFixture('512', { eku: ['1.3.6.1.5.5.7.3.4'] });
  const summary = certificateInfo(unbase64(fixture.certificate)).summary;
  const selected = { ...summary, unifiedNca: false, fingerprint: 'ab'.repeat(32), trust: { trusted: true, scope: 'nca', ncaTrusted: true, reason: 'Цепочка доверия проверена локально.',
    path: [{ name: 'NCA', fingerprint: 'cd'.repeat(32) }], revocation: { state: 'good', required: true, checkedAt: '2026-11-09T10:00:00.000Z', expires: '2026-11-09T11:00:00.000Z',
      certificates: [{ state: 'good', source: 'crl', reason: 'ocsp-unavailable' }] } } };
  const result = keyInfoResult(selected);
  assert.deepEqual(Object.keys(result).sort(), ['algorithm', 'bin', 'cert', 'certNotAfter', 'certNotBefore', 'certificate', 'extendedKeyUsageOids', 'iin', 'issuer', 'issuerCn', 'issuerDn',
    'name', 'notAfter', 'notBefore', 'organization', 'pem', 'serialNumber', 'subjectCn', 'subjectDn']);
  assert.equal(result.cert, fixture.certificate);
  assert.equal(result.certificate, fixture.certificate);
  assert.equal(result.subjectDn, summary.knca.subjectDn);
  assert.deepEqual(result.extendedKeyUsageOids, ['1.3.6.1.5.5.7.3.4']);
  assert.notEqual(result.extendedKeyUsageOids, selected.extendedKeyUsageOids);
  for (const leaked of ['ocsp-unavailable', 'checkedAt', 'trust', 'fingerprint', 'unifiedNca']) assert.ok(!JSON.stringify(result).includes(leaked), leaked);
});
const auth = { operation: 'sign', format: 'xml', documents: ['<login><client-type>PORTAL</client-type></login>'], signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'] } };
test('only complete known service requests can replace the default XML preview', () => {
  assert.equal(serviceOperation(auth, 'https://egov.kz').title, 'Вход на сайт');
  const nuc = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><key_settings_digi_sign><uuid>70fea973-f64c-41b5-958f-9da1547c7d15</uuid><date>2026-10-29T16:46:03.956+05:00</date></key_settings_digi_sign>';
  assert.equal(serviceOperation({ ...auth, documents: [nuc] }, 'https://nca.pki.gov.kz').title, 'Подтверждение на сайте НУЦ');
  for (const origin of ['https://example.kz', 'https://egov.kz.example.kz', 'http://egov.kz', 'https://nca.pki.gov.kz']) assert.equal(serviceOperation(auth, origin), null);
  for (const change of [{ signerParams: {} }, { decode: true }, { digested: true }, { format: 'cms' }, { documents: [...auth.documents, '<other/>'] }, { documents: ['<login><client-type>PORTAL</client-type><amount>500</amount></login>'] }, { documents: ['<!DOCTYPE login><login><client-type>PORTAL</client-type></login>'] }, { documents: ['<login purpose="payment"><client-type>PORTAL</client-type></login>'] }]) assert.equal(serviceOperation({ ...auth, ...change }, 'https://egov.kz'), null);
  assert.equal(serviceOperation({ ...auth, documents: [nuc.replace('</key_settings_digi_sign>', '<amount>500</amount></key_settings_digi_sign>')] }, 'https://nca.pki.gov.kz'), null);
});
test('getKeyInfo matches the fields NCALayer Common Utils computes for the same certificate', () => {
  const reference = JSON.parse(readFileSync(new URL('./fixtures/ncalayer-keyinfo.json', import.meta.url), 'utf8'));
  for (const { name, certificate, types, expected } of reference.cases) {
    const info = certificateInfo(unbase64(certificate));
    const result = keyInfoResult(info.summary);
    for (const [field, value] of Object.entries(expected)) assert.equal(result[field], value, `${name}.${field}`);
    if (!('keyId' in expected)) assert.ok(!('keyId' in result) && !('authorityKeyIdentifier' in result), name);
    assert.deepEqual([...kncaKeyTypes(info)].sort(), [...types].sort(), name);
  }
});
