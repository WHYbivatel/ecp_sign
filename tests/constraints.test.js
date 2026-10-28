import test from 'node:test';
import assert from 'node:assert/strict';
import { checkSignerConstraints, CLIENT_AUTH } from '../extension/crypto/constraints.js';
const EMAIL = '1.3.6.1.5.5.7.3.4';
const request = { signerParams: { extKeyUsageOids: [CLIENT_AUTH] }, trustRequired: true };
const trusted = { trusted: true };
test('authentication requirements remain mandatory and produce actionable errors', () => {
  assert.doesNotThrow(() => checkSignerConstraints({ eku: [CLIENT_AUTH], summary: {} }, request, trusted));
  assert.throws(() => checkSignerConstraints({ eku: [EMAIL], summary: {} }, request, trusted), /AUTH_RSA/);
  assert.throws(() => checkSignerConstraints({ eku: [], summary: {} }, request, trusted), /аутентификации/);
  assert.throws(() => checkSignerConstraints({ eku: [CLIENT_AUTH], summary: {} }, request, { trusted: false }), /доверенную цепочку/);
  assert.throws(() => checkSignerConstraints({ eku: [CLIENT_AUTH], summary: {} }, { signerParams: { extKeyUsageOids: [CLIENT_AUTH, EMAIL] } }, trusted), /Требуемые назначения/);
});
