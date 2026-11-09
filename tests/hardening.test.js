import test from 'node:test';
import assert from 'node:assert/strict';
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
    'SignerInfo version with an application tag': (root, fields) => { fields.at(-1).value[0].value[0].tagClass = A.Class.APPLICATION; }
  };
  for (const [name, change] of Object.entries(variants)) {
    const raw = variant(change);
    await assert.rejects(verifyCms(raw), /CMS/, name);
    if (!name.startsWith('SignerInfo')) assert.throws(() => describeCms(raw), /CMS/, name);
  }
});

test('PKCS#12 key derivation refuses iteration counts below one (GHSA-jc66-7q78-782g)', () => {
  assert.throws(() => forge.pkcs12.generateKey('any password', forge.util.createBuffer('anysalt'), 3, 0, 20), /iteration count/);
});
