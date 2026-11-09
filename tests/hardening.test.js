import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { forge, A, parse, der, bytes, oid } from '../extension/crypto/encoding.js';
import { rsaFixture, PASSWORD } from './helpers/fixtures.js';
import { openContainer } from '../extension/crypto/signer.js';
import { signCms } from '../extension/crypto/cms.js';
import { verifyCms, describeCms } from '../extension/crypto/cms-verify.js';

function length(n) {
  if (n < 128) return String.fromCharCode(n);
  let value = '';
  for (; n; n >>>= 8) value = String.fromCharCode(n & 255) + value;
  return String.fromCharCode(128 | value.length) + value;
}

test('nested BIT STRINGs from untrusted DER are decoded one level only (GHSA-rhr8-3pm8-cq29)', () => {
  let der = '\x05\x00';
  for (let i = 0; i < 3000; i++) der = '\x03' + length(der.length + 1) + '\x00' + der;
  const started = Date.now();
  const root = parse(der);
  assert.ok(Date.now() - started < 1000, 'node-forge 1.4.0 needed seconds for this 15 KB input');
  assert.equal(root.type, A.Type.BITSTRING);
  assert.equal(typeof root.value[0].value, 'string', 'the second level stays undecoded');
});

test('PEM from a site is decoded in linear time (GHSA-7wch-p9px-956x)', () => {
  const started = Date.now();
  assert.throws(() => forge.pem.decode('-----BEGIN CERTIFICATE-----\nProc-Type: ' + ' '.repeat(60000) + 'x'), /Invalid PEM/);
  assert.ok(Date.now() - started < 1000, 'node-forge 1.4.0 needed about 7 s for this input');
});

test('CMS fields outside the signature keep the RFC 5652 shape (regression: fuzzing accepted variants)', async () => {
  const fixture = rsaFixture({ password: PASSWORD });
  const signer = await openContainer(fixture.container, PASSWORD);
  const data = new TextEncoder().encode('Tegin CMS shape regression');
  const cms = await signCms(signer, data, { cades: true });
  signer.destroy();
  assert.deepEqual((await verifyCms(cms)).content, data);
  const variant = change => { const root = parse(cms); change(root, root.value[1].value[0].value); return bytes(der(root)); };
  const variants = {
    'ContentInfo as SET': root => { root.type = A.Type.SET; },
    'extra ContentInfo field': root => { root.value.push(A.create(0, A.Type.NULL, false, '')); },
    'eContent tagged [1]': (root, fields) => { fields[2].value[1].type = 1; },
    'eContent tagged [2]': (root, fields) => { fields[2].value[1].type = 2; },
    'SignedData version with an application tag': (root, fields) => { fields[0].tagClass = A.Class.APPLICATION; },
    'digestAlgorithms as SEQUENCE': (root, fields) => { fields[1].type = A.Type.SEQUENCE; },
    'digestAlgorithms OID with another tag': (root, fields) => { fields[1].value[0].value[0].tagClass = A.Class.APPLICATION; },
    'certificates repeated': (root, fields) => { fields.splice(3, 0, fields[3]); },
    'unknown [2] field': (root, fields) => { fields.splice(4, 0, A.create(A.Class.CONTEXT_SPECIFIC, 2, true, [])); },
    'SignerInfo version with an application tag': (root, fields) => { fields.at(-1).value[0].value[0].tagClass = A.Class.APPLICATION; },
    'signerInfos with an application tag': (root, fields) => { fields.at(-1).tagClass = A.Class.APPLICATION; },
    'signerInfos as SEQUENCE': (root, fields) => { fields.at(-1).type = A.Type.SEQUENCE; },
    'certificate with an application tag': (root, fields) => { fields[3].value[0].tagClass = A.Class.APPLICATION; },
    'crls with an application-tagged entry': (root, fields) => { fields.splice(4, 0, A.create(A.Class.CONTEXT_SPECIFIC, 1, true, [A.create(A.Class.APPLICATION, A.Type.SEQUENCE, true, [])])); },
    'SignerInfo version 3 with issuerAndSerialNumber': (root, fields) => { fields.at(-1).value[0].value[0].value = '\x03'; },
    'sid with an application tag': (root, fields) => { fields.at(-1).value[0].value[1].tagClass = A.Class.APPLICATION; },
    'digestAlgorithm with an application tag': (root, fields) => { fields.at(-1).value[0].value[2].tagClass = A.Class.APPLICATION; },
    'signedAttrs tagged [2]': (root, fields) => { fields.at(-1).value[0].value[3].type = 2; },
    'signedAttrs attribute with an application tag': (root, fields) => { fields.at(-1).value[0].value[3].value[0].tagClass = A.Class.APPLICATION; },
    'signatureAlgorithm with an application tag': (root, fields) => { fields.at(-1).value[0].value[4].tagClass = A.Class.APPLICATION; },
    'signature with an application tag': (root, fields) => { fields.at(-1).value[0].value[5].tagClass = A.Class.APPLICATION; },
    'signature as a constructed OCTET STRING': (root, fields) => { const value = fields.at(-1).value[0].value[5]; fields.at(-1).value[0].value[5] = A.create(0, A.Type.OCTETSTRING, true, [A.create(0, A.Type.OCTETSTRING, false, value.value)]); },
    'signedAttrs after signatureAlgorithm': (root, fields) => { const info = fields.at(-1).value[0].value; info.splice(4, 0, ...info.splice(3, 1)); },
    'empty unsignedAttrs': (root, fields) => { fields.at(-1).value[0].value.push(A.create(A.Class.CONTEXT_SPECIFIC, 1, true, [])); },
    'unsignedAttrs tagged [2]': (root, fields) => { fields.at(-1).value[0].value.push(A.create(A.Class.CONTEXT_SPECIFIC, 2, true, [fields.at(-1).value[0].value[3].value[0]])); },
    'extra field after unsignedAttrs': (root, fields) => { const info = fields.at(-1).value[0].value; info.push(A.create(A.Class.CONTEXT_SPECIFIC, 1, true, [info[3].value[0]]), A.create(0, A.Type.NULL, false, '')); }
  };
  for (const [name, change] of Object.entries(variants)) {
    const raw = variant(change);
    await assert.rejects(verifyCms(raw), /CMS/, name);
    assert.throws(() => describeCms(raw), /CMS/, name);
  }
});

test('correct CMS from OpenSSL still verifies: BER, attached, detached, CAdES, SKI, unsigned attributes', async () => {
  const fixture = rsaFixture({ password: PASSWORD });
  const folder = mkdtempSync(join(tmpdir(), 'tegin-cms-shape-'));
  try {
    const data = new TextEncoder().encode('Tegin OpenSSL CMS shape');
    writeFileSync(join(folder, 'key.pem'), fixture.publicKey); writeFileSync(join(folder, 'cert.pem'), fixture.certificate); writeFileSync(join(folder, 'doc.bin'), data);
    const sign = (...args) => new Uint8Array(execFileSync('openssl', ['cms', '-sign', '-binary', '-in', join(folder, 'doc.bin'), '-signer', join(folder, 'cert.pem'), '-inkey', join(folder, 'key.pem'), '-outform', 'DER', ...args]));
    for (const [name, raw, detached] of [['attached', sign('-nodetach')], ['BER', sign('-nodetach', '-stream', '-indef')], ['detached', sign(), data], ['CAdES', sign('-nodetach', '-cades')], ['SKI', sign('-nodetach', '-keyid')]]) {
      const result = await verifyCms(raw, { detached });
      assert.deepEqual(result.content, data, name);
      assert.equal(result.signers[0].cades, name === 'CAdES', name);
    }
    const root = parse(sign('-nodetach'));
    const info = root.value[1].value[0].value.at(-1).value[0];
    info.value.push(A.create(A.Class.CONTEXT_SPECIFIC, 1, true, [info.value[3].value[0]]));
    assert.deepEqual((await verifyCms(bytes(der(root)))).content, data, 'unsigned attributes are outside the signature');
    // eContent OCTET STRING: primitive and constructed BER parts must all be UNIVERSAL.
    const eContent = root => root.value[1].value[0].value[2].value[1];
    const primitive = parse(sign('-nodetach'));
    eContent(primitive).value[0].tagClass = A.Class.APPLICATION;
    await assert.rejects(verifyCms(bytes(der(primitive))), /CMS/, 'application-tagged eContent');
    assert.throws(() => describeCms(bytes(der(primitive))), /CMS/);
    const ber = sign('-nodetach', '-stream', '-indef');
    const nested = parse(ber);
    const outer = eContent(nested).value[0];
    assert.equal(outer.constructed, true, 'OpenSSL streams eContent as a constructed OCTET STRING');
    outer.value = [A.create(0, A.Type.OCTETSTRING, true, outer.value)];
    assert.deepEqual((await verifyCms(bytes(der(nested)))).content, data, 'nested constructed BER parts');
    for (const [name, change] of [['application-tagged BER part', root => { eContent(root).value[0].value[0].tagClass = A.Class.APPLICATION; }],
      ['application-tagged nested BER part', root => { eContent(root).value[0].value[0].value[0].tagClass = A.Class.APPLICATION; }]]) {
      const root = parse(bytes(der(nested))); change(root);
      await assert.rejects(verifyCms(bytes(der(root))), /CMS/, name);
      assert.throws(() => describeCms(bytes(der(root))), /CMS/, name);
    }
  } finally { rmSync(folder, { recursive: true, force: true }); }
});

test('PKCS#12 key derivation refuses iteration counts below one (GHSA-jc66-7q78-782g)', () => {
  assert.throws(() => forge.pkcs12.generateKey('any password', forge.util.createBuffer('anysalt'), 3, 0, 20), /iteration count/);
});
