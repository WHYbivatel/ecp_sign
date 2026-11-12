import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeRequest, errorResponse, successResponse, PASSWORD_PAGE_REFUSAL } from '../extension/signing/protocol.js';
const common = 'kz.gov.pki.knca.commonUtils';
const basics = 'kz.gov.pki.knca.basics';
test('normalizes commonUtils and basics without silently dropping unsupported requirements', () => {
  assert.deepEqual(normalizeRequest({ module: common, method: 'getActiveTokens' }).value, []);
  assert.equal(normalizeRequest({ module: common, method: 'signXml', args: ['PKCS12', 'SIGNATURE', '<x/>', '', ''] }).format, 'xml');
  assert.equal(normalizeRequest({ module: common, method: 'signXml', args: ['PKCS12', 'SIGNATURE', '<x/>', '', '//ignored'] }).xpath, undefined);
  assert.deepEqual(normalizeRequest({ module: common, method: 'signXmls', args: ['PKCS12', 'SIGNATURE', ['<x/>'], '//x', '//y'] }).xpath, { tbsXPath: '//x', parentXPath: '//y' });
  for (const value of [{}, 7, 'x'.repeat(513)]) assert.throws(() => normalizeRequest({ module: common, method: 'signXml', args: ['PKCS12', 'SIGNATURE', '<x/>', value, ''] }), /XPath/);
  assert.throws(() => normalizeRequest({ module: 'kz.uchet.signUtil.commonUtils', method: 'signXml', args: ['PKCS12', 'SIGNATURE', '<x/>', '//x', '//y'] }), /без XPath/);
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
test('the NUC password page flow is refused with a pointer to the local tool', () => {
  for (const request of [{ method: 'browseKeyStore', args: ['PKCS12', 'P12', ''] }, { module: 'kz.gov.pki.knca.applet.Applet', method: 'changePassword', args: ['PKCS12', '/path/key.p12', 'old', 'new'] }]) {
    assert.throws(() => normalizeRequest(request), error => error.message === PASSWORD_PAGE_REFUSAL);
    assert.deepEqual(errorResponse(request, PASSWORD_PAGE_REFUSAL), { code: '400', message: PASSWORD_PAGE_REFUSAL, responseObject: null });
  }
  assert.throws(() => normalizeRequest({ method: 'loadSlotList', args: ['PKCS12'] }), /пока не поддерживается/);
});
test('response formats preserve the two protocol families and cancellation', () => {
  assert.deepEqual(successResponse({ module: common }, 'signature').responseObject, 'signature');
  assert.deepEqual(successResponse({ module: basics }, { result: ['signature'] }).body.result, ['signature']);
  assert.equal(errorResponse({ module: common }, 'cancel', true).code, '500');
});
test('Common Utils responses follow the NCALayer Common Bundle 0.3.4 shape', () => {
  assert.deepEqual(successResponse({ module: common, method: 'getKeyInfo', uuid: 'u-1' }, { a: 1 }), { code: '200', responseObject: { a: 1 }, uuid: 'u-1' });
  assert.deepEqual(successResponse({ module: common, method: 'changeLocale', args: ['kk'] }, true), { code: '200' });
  assert.deepEqual(errorResponse({ module: common, method: 'signXml', uuid: 7 }, 'reason'), { code: '500', message: 'reason', uuid: '7' });
  assert.deepEqual(errorResponse({ module: common, method: 'signXml', uuid: '' }, 'reason', true), { code: '500', message: 'action.canceled' });
  assert.deepEqual(errorResponse({ module: basics }, 'cancel', true), { status: true, body: {} });
});

test('NUC XML request permits null TSA profile and twelve trust certificates without weakening limits', () => {
  const pem = '-----BEGIN CERTIFICATE-----\npublic-test-only\n-----END CERTIFICATE-----';
  const request = { module: basics, method: 'sign', args: { allowedStorages: ['PKCS12', 'JKS'], format: 'xml', data: '<login/>', signingParams: { decode: false, encapsulate: false, digested: false, tsaProfile: null }, signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'], chain: Array(12).fill(pem) } } };
  const normalized = normalizeRequest(request);
  assert.equal(normalized.timestamp, false); assert.equal(normalized.trustRequired, true); assert.equal(normalized.signerParams.chain.length, 12);
  assert.throws(() => normalizeRequest({ ...request, args: { ...request.args, signerParams: { chain: Array(25).fill(pem) } } }), /цепочка/);
  assert.throws(() => normalizeRequest({ ...request, args: { ...request.args, signingParams: { tsaProfile: {} } } }), /Метка времени/);
});
