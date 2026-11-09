import test from 'node:test';
import assert from 'node:assert/strict';
import { forge, A, parse } from '../extension/crypto/encoding.js';

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

test('PKCS#12 key derivation refuses iteration counts below one (GHSA-jc66-7q78-782g)', () => {
  assert.throws(() => forge.pkcs12.generateKey('any password', forge.util.createBuffer('anysalt'), 3, 0, 20), /iteration count/);
});
