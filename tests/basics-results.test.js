import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { rsaFixture, PASSWORD } from './helpers/fixtures.js';
import { openContainer } from '../extension/crypto/signer.js';
import { signCms } from '../extension/crypto/cms.js';
import { base64, forge } from '../extension/crypto/encoding.js';
import { normalizeRequest } from '../extension/signing/protocol.js';
import { assembleResult } from '../extension/modules/adapters.js';

const reference = JSON.parse(readFileSync(new URL('./fixtures/ncalayer-basics-results.json', import.meta.url), 'utf8'));
const official = Object.fromEntries(reference.cases.map(item => [item.name, item]));
const PEM_CMS = /^-----BEGIN CMS-----\n(?:[A-Za-z0-9+/=]{1,64}\n)+-----END CMS-----\n$/;
const isDer = text => forge.asn1.fromDer(forge.util.decode64(text)).type === forge.asn1.Type.SEQUENCE;
const request = args => ({ module: 'kz.gov.pki.knca.basics', method: 'sign', args: { allowedStorages: ['PKCS12'], signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.4'] }, ...args } });

test('NCALayer 0.4.10 result shapes: PEM CMS in an array, a lone raw signature as a string', () => {
  for (const item of reference.cases) assert.equal(item.response.status, true, item.name);
  for (const name of ['cms-single', 'cms-batch']) {
    const { result } = official[name].response.body;
    assert.ok(Array.isArray(result) && result.length === [official[name].args.data].flat().length, name);
    for (const pem of result) {
      assert.match(pem, PEM_CMS, name);
      assert.ok(isDer(pem.replace(/-----(BEGIN|END) CMS-----|\s/g, '')), 'stripping the armor leaves DER CMS');
    }
  }
  assert.equal(typeof official['raw-single'].response.body.result, 'string');
  assert.equal(official['raw-batch'].response.body.result.length, 2);
  assert.deepEqual(Object.keys(official['raw-cert'].response.body.result).sort(), ['certificate', 'signatures']);
  assert.equal(official['raw-cert'].response.body.result.signatures.length, 1);
  assert.equal(official['xml-batch'].response.body.result.length, 2);
});

// The Tegin contract stays as it is until the deployed Tegin EDO and other Tegin clients are checked.
test('Tegin keeps its Basics contract: base64 DER CMS and an array for every format', async () => {
  for (const name of ['cms-single', 'cms-batch', 'raw-single', 'raw-batch', 'xml-batch']) {
    const normalized = normalizeRequest(request(official[name].args));
    const signatures = [official[name].args.data].flat().map((_, index) => `signature-${index}`);
    assert.deepEqual(assembleResult(normalized, signatures), { result: signatures }, name);
  }
  assert.throws(() => normalizeRequest(request(official['raw-cert'].args)), /Неизвестные параметры/);
  const fixture = rsaFixture();
  try {
    const signer = await openContainer(fixture.container, PASSWORD);
    const cms = base64(await signCms(signer, new TextEncoder().encode('test')));
    assert.doesNotMatch(cms, /-----|\s/);
    assert.ok(isDer(cms));
  } finally { fixture.container.fill(0); }
});
