import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { argumentShape, diagnosticEntry, responseCode } from '../extension/signing/diagnostics.js';
import { normalizeRequest, errorResponse } from '../extension/signing/protocol.js';

const PEM = '-----BEGIN CERTIFICATE-----\nMIIBsecret\n-----END CERTIFICATE-----';
const secrets = ['123456789012', '987654321098', 'Pa55word!', 'MIIBsecret', 'did.pki.gov.kz', 'JSESSIONID', 'ТЕСТОВ'];

test('request diagnostics keep names and structure and drop every value', () => {
  const request = { module: 'kz.gov.pki.knca.basics', method: 'generateCsr', class: 'PKIEssentials', args: {
    allowedStorages: [''], defaultPassword: 'Pa55word!', dn: { '2.5.4.3': 'ТЕСТОВ ТЕСТ', '2.5.4.5': 'IIN123456789012', '2.5.4.11': 'BIN987654321098' },
    email: '', subjectAltNames: '', params: [{ algorithm: 'ECGOST3410-2015', length: 512 }], locale: 'ru', omittedKeyIds: [''],
    'https://did.pki.gov.kz/?JSESSIONID=1': 'x', chain: [PEM, PEM] } };
  const entry = diagnosticEntry(request, 'refused', 'UNSUPPORTED_OR_FAILED', 'Этот метод NCALayer пока не поддерживается.');
  const text = JSON.stringify(entry);
  for (const secret of secrets) assert.ok(!text.includes(secret), secret);
  assert.equal(entry.method, 'generateCsr');
  assert.equal(entry.class, 'PKIEssentials');
  assert.deepEqual(entry.args.allowedStorages, { array: 1, items: ['empty'] });
  assert.deepEqual(entry.args.dn, { '2.5.4.3': 'string', '2.5.4.5': 'string', '2.5.4.11': 'string' });
  assert.deepEqual(entry.args.params, { array: 1, items: [{ algorithm: 'string', length: 'number' }] });
  assert.equal(entry.args['?'], 'string');
  assert.deepEqual(entry.args.chain, { array: 2, items: ['string'] });
  assert.equal(diagnosticEntry({ module: 'x'.repeat(200), method: 'a b' }, 'refused', 'X').module, '?');
  assert.equal(diagnosticEntry(null, 'refused', 'X').args, 'null');
  assert.equal(argumentShape({ a: { b: { c: { d: 1 } } } }).a.b.c, 'object');
  assert.equal(argumentShape([[['deep']]]).items[0].items[0], 'array(1)');
});

test('response codes distinguish refusal, cancellation and success', () => {
  const generate = { module: 'kz.gov.pki.knca.basics', method: 'generateCsr', class: 'PKIEssentials', args: {} };
  // Tegin 0.5.2 sent generateCsr through normalizeRequest: this is the portal's UNSUPPORTED_OR_FAILED.
  assert.throws(() => normalizeRequest(generate), /пока не поддерживается/);
  assert.equal(responseCode(errorResponse(generate, 'x')), 'UNSUPPORTED_OR_FAILED');
  assert.equal(responseCode(errorResponse(generate, 'x', true)), 'cancelled');
  assert.equal(responseCode({ status: true, body: { pems: ['x'] } }), 'ok');
  assert.equal(responseCode({ code: '200', message: '', responseObject: 1 }), '200');
  assert.equal(responseCode(errorResponse({ module: 'kz.gov.pki.knca.commonUtils' }, 'x')), '500');
  assert.equal(responseCode(errorResponse({ module: 'kz.gov.pki.knca.commonUtils' }, 'x', true)), 'cancelled');
});

test('the page channel is private to this version and an older adapter is reported', async () => {
  const inject = await readFile(new URL('../extension/content/inject.js', import.meta.url), 'utf8');
  const bridge = await readFile(new URL('../extension/content/bridge.js', import.meta.url), 'utf8');
  for (const source of [inject, bridge]) assert.doesNotMatch(source, /'ncabrowser:(request|response|cancel)'/);
  assert.match(inject, /__teginChannel !== 'tegin'\) document\.documentElement\.setAttribute\('data-tegin-conflict', 'legacy'\)/);
  assert.match(bridge, /respond\(\{ active: !conflict, conflict \}\)/);
});
