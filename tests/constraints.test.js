import test from 'node:test';
import assert from 'node:assert/strict';
import { checkSignerConstraints, CLIENT_AUTH, isUnifiedNcaCertificate } from '../extension/crypto/constraints.js';
import { O } from '../extension/crypto/encoding.js';
const EMAIL = '1.3.6.1.5.5.7.3.4';
const request = { signerParams: { extKeyUsageOids: [CLIENT_AUTH] }, trustRequired: true };
const trusted = { trusted: true };
test('authentication requirements remain mandatory and produce actionable errors', () => {
  assert.doesNotThrow(() => checkSignerConstraints({ eku: [CLIENT_AUTH], summary: {} }, request, trusted));
  assert.throws(() => checkSignerConstraints({ eku: [EMAIL], summary: {} }, request, trusted), /единый ГОСТ/);
  assert.throws(() => checkSignerConstraints({ eku: [], summary: {} }, request, trusted), /аутентификации/);
  assert.throws(() => checkSignerConstraints({ eku: [CLIENT_AUTH], summary: {} }, request, { trusted: false }), /доверенную цепочку/);
  assert.throws(() => checkSignerConstraints({ eku: [CLIENT_AUTH], summary: {} }, { signerParams: { extKeyUsageOids: [CLIENT_AUTH, EMAIL] } }, trusted), /Требуемые назначения/);
});


test('unified NUC GOST policy resolves legacy clientAuth filter only for a verified modern subscriber', () => {
  const info = { keyOid: O.gost512, ca: false, keyUsage: 192,
    eku: [EMAIL, '1.2.398.3.3.4.1.1', '1.2.398.3.3.4.3.2'],
    summary: { notBefore: '2026-07-27T00:00:00Z' } };
  const pinned = { trusted: true, ncaTrusted: true };
  assert.equal(isUnifiedNcaCertificate(info, pinned), true);
  assert.doesNotThrow(() => checkSignerConstraints(info, request, pinned));
  for (const trust of [undefined, { trusted: true }, { trusted: true, ncaTrusted: false }]) {
    assert.equal(isUnifiedNcaCertificate(info, trust), false);
    assert.throws(() => checkSignerConstraints(info, request, trust), /аутентификации/);
  }
  for (const change of [{ keyOid: O.rsa }, { keyOid: O.gost2004 }, { ca: true }, { keyUsage: null }, { keyUsage: 4 },
    { eku: [EMAIL] }, { eku: ['1.2.398.3.3.4.1.1'] }, { summary: { notBefore: '2020-01-01T00:00:00Z' } }]) {
    assert.equal(isUnifiedNcaCertificate({ ...info, ...change }, pinned), false);
    assert.throws(() => checkSignerConstraints({ ...info, ...change }, request, pinned), /аутентификации/);
  }
  // Other portal requirements, such as a particular organizational role, remain exact.
  assert.throws(() => checkSignerConstraints(info, { signerParams: { extKeyUsageOids: [CLIENT_AUTH, '1.2.398.3.3.4.1.2.1'] } }, pinned), /Требуемые назначения/);
  assert.throws(() => checkSignerConstraints(info, { ...request, signerParams: { ...request.signerParams, iin: 'different' } }, pinned), /требованиям сайта/);
  const organization = { ...info, eku: [EMAIL, '1.2.398.3.3.4.1.2', '1.2.398.3.3.4.1.2.1'] };
  assert.equal(isUnifiedNcaCertificate(organization, pinned), true);
  assert.equal(isUnifiedNcaCertificate({ ...organization, summary: { notBefore: '2023-01-01T00:00:00Z' } }, pinned), false);
});
