import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeRequest, successResponse, errorResponse } from '../extension/signing/protocol.js';
import { assembleResult } from '../extension/modules/adapters.js';
import { modules, enforceSettings, validateSettings, findModule } from '../extension/modules/registry.js';
import { catalog, catalogEvidence } from '../extension/modules/catalog.js';
import { rsaFixture, gostFixture, PASSWORD } from './helpers/fixtures.js';
import { openContainer } from '../extension/crypto/signer.js';
import { signXml, verifyCreatedXml } from '../extension/crypto/xml.js';
const nur = { module: 'NURSign', type: 'xml', data: '<request/>' };
const samruk = { module: 'kz.sapa.eproc.osgi.EprocModule', method: 'signXml', uid: 'request-1', storageName: 'PKCS12', keyType: 'SIGN', xml: '<request/>' };
function answer(input, result) { return successResponse(input, assembleResult(normalizeRequest(input), result)); }

test('inspected module requests preserve data, signing profiles and response envelopes', () => {
  assert.deepEqual(normalizeRequest(nur).documents, ['<request/>']);
  assert.deepEqual(answer(nur, ['signed']), { errorCode: 'NONE', result: 'signed' });
  assert.deepEqual(answer({ ...nur, type: 'multixml', data: ['<a/>','<b/>'] }, ['one','two']).result, ['one','two']);
  const binary = normalizeRequest({ ...nur, type: 'binary', data: 'YWJj' });
  assert.equal(binary.decode, true); assert.equal(binary.encapsulate, false); assert.equal(binary.cades, true); assert.equal(binary.timestamp, undefined);
  assert.equal(normalizeRequest({ ...nur, type: 'text', data: 'abc' }).timestamp, true);
  const batch = { ...nur, type: 'multitext', data: JSON.parse('{"one":"abc","__proto__":"def"}') };
  assert.deepEqual(answer(batch, ['first','second']).result.items, JSON.parse('{"one":"first","__proto__":"second"}'));
  assert.equal(answer(samruk, ['signed']).uid, 'request-1'); assert.equal(answer(samruk, ['signed']).newChain, null);
  assert.equal(normalizeRequest(samruk).signerParams.extKeyUsageOids[0], '1.3.6.1.5.5.7.3.4');
  const qiwi = { module: 'kz.qiwi.osgi.SecurityUtils', method: 'signXml', args: ['call-1','<a/>'] };
  assert.deepEqual(answer(qiwi, ['signed']).responseObject, { callID: 'call-1', signedXml: 'signed', verificationResult: true });
  const rating = { module: 'kz.rating1c.edo.signUtils', method: 'signXml', args: ['PKCS12','SIGNATURE','<r/>','',''], uuid: 'correlation' };
  assert.equal(answer(rating, ['signed']).uuid, 'correlation'); assert.equal(normalizeRequest(rating).moduleId, 'rating');
  assert.equal(errorResponse(nur, 'cancel', true).errorCode, '500');
  assert.equal(errorResponse(samruk, 'cancel', true).uid, 'request-1');
  assert.throws(() => normalizeRequest({ ...nur, type: 'file' }));
  assert.throws(() => normalizeRequest({ ...nur, source: 'remote', upload_url: 'https://example.kz/document' }));
  assert.throws(() => normalizeRequest({ ...nur, needHash: 'true' }));
  assert.throws(() => normalizeRequest({ ...samruk, tbsElementXPath: '//Amount' }));
  assert.throws(() => normalizeRequest({ ...samruk, storageName: 'AKKaztokenStore' }));
  assert.throws(() => normalizeRequest({ ...samruk, password: 'must-not-store' }));
  assert.throws(() => normalizeRequest({ module: 'kz.uchet.esfSignUtil', method: 'signXml', args: { pkcsPassword: 'must-not-store' } }));
  assert.throws(() => normalizeRequest({ module: 'kz.rating1c.edo.signUtils', method: 'getKeyInfo', args: ['PKCS12','must-not-store'] }));
  assert.throws(() => normalizeRequest({ module: 'NURSignButUnknown', method: 'signXml', args: ['PKCS12','SIGN','<a/>'] }));
});
test('module restrictions cannot silently alter a request or admit credentials in settings', () => {
  const module = findModule('NURSign'), origin = 'https://portal.goszakup.gov.kz';
  assert.doesNotThrow(() => enforceSettings(module, normalizeRequest(nur), origin));
  assert.throws(() => enforceSettings(module, normalizeRequest(nur), origin, { enabled: false }), /выключен/);
  assert.throws(() => enforceSettings(module, normalizeRequest(nur), origin, { xml: false }), /формат/);
  assert.throws(() => enforceSettings(module, normalizeRequest(nur), origin, { origins: ['https://other.kz'] }), /сайт/);
  assert.throws(() => enforceSettings(module, normalizeRequest({ ...nur, type: 'text' }), origin, { timestamp: 'deny' }), /обязательную метку/);
  assert.throws(() => enforceSettings(module, normalizeRequest({ ...nur, type: 'multixml', data: ['<a/>','<b/>'] }), origin, { maxBatch: 1 }), /Число/);
  for (const value of [{ password: 'secret' }, { maxBatch: 11 }, { origins: ['https://user:password@egov.kz'] }, { origins: ['https://egov.kz/path'] }, { origins: ['http://example.kz'] }, { timestamp: 'omit' }]) assert.throws(() => validateSettings(value));
  assert.deepEqual(validateSettings({ origins: ['https://egov.kz/','https://egov.kz'] }).origins, ['https://egov.kz']);
  assert.equal(catalog.length, catalogEvidence.count); assert.equal(new Set(catalog.map(entry => entry.symname)).size, catalog.length);
  assert.ok(modules.every(module => module.vendor && module.services.every(service => findModule(service)?.id === module.id)));
});
test('QIWI self-verification checks both generated XML content and cryptographic signature', async () => {
  for (const fixture of [rsaFixture(), gostFixture()]) {
    const signer = await openContainer(fixture.container, PASSWORD);
    try {
      const xml = await signXml(signer, '<root><amount>123</amount></root>');
      assert.equal(await verifyCreatedXml(signer, xml), true);
      assert.equal(await verifyCreatedXml(signer, xml.replace('123','124')), false);
      assert.equal(await verifyCreatedXml(signer, xml.replace(/(<ds:SignatureValue>)[A-Za-z0-9+/]/, '$1!')), false);
    } finally { signer.destroy(); fixture.container.fill(0); }
  }
});
