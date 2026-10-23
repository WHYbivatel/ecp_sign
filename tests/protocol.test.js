import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeRequest, errorResponse, successResponse } from '../extension/signing/protocol.js';
const common = 'kz.gov.pki.knca.commonUtils';
const basics = 'kz.gov.pki.knca.basics';
test('normalizes commonUtils and basics without silently dropping unsupported requirements', () => {
  assert.deepEqual(normalizeRequest({ module: common, method: 'getActiveTokens' }).value, []);
  assert.equal(normalizeRequest({ module: common, method: 'signXml', args: ['PKCS12', 'SIGNATURE', '<x/>', '', ''] }).format, 'xml');
  assert.throws(() => normalizeRequest({ module: common, method: 'signXml', args: ['PKCS12', 'SIGNATURE', '<x/>', '//x', ''] }), /XPath/);
  const request = { module: basics, method: 'sign', args: { format: 'cms', allowedStorages: ['PKCS12'], data: 'dGVzdA==', signingParams: { decode: true, encapsulate: false } } };
  assert.equal(normalizeRequest(request).decode, true);
  for (const signingParams of [{ tsaProfile: { url: 'https://other.test' } }, { digested: true }, { unexpected: true }]) {
    assert.throws(() => normalizeRequest({ ...request, args: { ...request.args, signingParams } }));
  }
  assert.throws(() => normalizeRequest({ ...request, args: { ...request.args, allowedStorages: ['Kaztoken'] } }));
  assert.equal(normalizeRequest({ ...request, args: { ...request.args, signerParams: { chain: [] } } }).trustRequired, false);
  assert.equal(normalizeRequest(request).trustRequired, true);
  assert.equal(normalizeRequest({ ...request, args: { ...request.args, signingParams: { tsaProfile: {} } } }).timestamp, true);
  assert.equal(normalizeRequest({ ...request, args: { ...request.args, signingParams: {} } }).encapsulate, true);
  assert.equal(normalizeRequest({ ...request, args: { ...request.args, signingParams: { digested: true, encapsulate: false } } }).digested, true);
  assert.throws(() => normalizeRequest({ module: common, method: 'runShell', args: ['PKCS12'] }));
});
test('response formats preserve the two protocol families and cancellation', () => {
  assert.deepEqual(successResponse({ module: common }, 'signature').responseObject, 'signature');
  assert.deepEqual(successResponse({ module: basics }, { result: ['signature'] }).body.result, ['signature']);
  assert.equal(errorResponse({ module: common }, 'cancel', true).code, '500');
  assert.deepEqual(errorResponse({ module: basics }, 'cancel', true), { status: true, body: {} });
});
