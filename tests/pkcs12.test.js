import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ContainerError, inspectPkcs12, MAX_CONTAINER_BYTES } from '../extension/lib/pkcs12.js';

const tlv = (tag, ...parts) => {
  const body = parts.flatMap(part => [...part]);
  assert.ok(body.length < 128, 'Synthetic fixtures use short lengths');
  return [tag, body.length, ...body];
};
const seq = (...parts) => tlv(48, ...parts);
const oid = ending => tlv(6, [42, 134, 72, 134, 247, 13, 1, 7, ending]);
const fixture = () => new Uint8Array(seq(
  tlv(2, [3]),
  seq(oid(1), tlv(160, tlv(4, seq(seq(oid(1), tlv(160, tlv(4, seq())))))))
));

test('recognizes a DER PFX envelope without treating it as a verified key', () => {
  const bytes = fixture();
  const original = bytes.slice();
  assert.deepEqual(inspectPkcs12(bytes), { format: 'PKCS#12', version: 3, size: bytes.length });
  assert.deepEqual(bytes, original, 'Inspection must not modify the caller buffer');
});

test('rejects non-PFX data, truncation, trailing data, and invalid BER', () => {
  const valid = fixture();
  const samples = [
    new Uint8Array(),
    new TextEncoder().encode('not a PKCS12 container'),
    new Uint8Array([...valid, 0]),
    new Uint8Array([48, 128, 0, 0]),
    new Uint8Array([48, 132, 255, 255, 255, 255]),
    new Uint8Array([48, 129, 0]),
    new Uint8Array([48, 129, 1, 0]),
    new Uint8Array([48, 2, 31, 0])
  ];
  for (let end = 0; end < valid.length; end++) samples.push(valid.subarray(0, end));
  for (const sample of samples) assert.throws(() => inspectPkcs12(sample), ContainerError);
});

test('accepts BER indefinite-length constructed wrappers used by Kalkan containers', () => {
  const valid = fixture();
  const ber = new Uint8Array([48, 128, ...valid.slice(2), 0, 0]);
  assert.equal(inspectPkcs12(ber).format, 'PKCS#12');
});

test('rejects wrong PFX version and content type', () => {
  const version = fixture();
  version[4] = 2;
  assert.throws(() => inspectPkcs12(version), ContainerError);
  const type = fixture();
  type[17] = 9;
  assert.throws(() => inspectPkcs12(type), ContainerError);
});

test('bounds resource use before parsing', () => {
  assert.throws(() => inspectPkcs12(new Uint8Array(MAX_CONTAINER_BYTES + 1)), /4 МБ/);
  assert.throws(() => inspectPkcs12(null), ContainerError);
});

test('recognizes an OpenSSL-generated password-protected PKCS12 with a MAC', () => {
  // Generate disposable fixtures, never read a user key. Password is public test data.
  const folder = mkdtempSync(join(tmpdir(), 'ncabrowser-test-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', join(folder, 'key.pem'), '-out', join(folder, 'cert.pem'),
      '-days', '1', '-subj', '/CN=Tegin disposable test'], { stdio: 'ignore' });
    execFileSync('openssl', ['pkcs12', '-export', '-inkey', join(folder, 'key.pem'),
      '-in', join(folder, 'cert.pem'), '-out', join(folder, 'test.p12'),
      '-passout', 'pass:public-test-password'], { stdio: 'ignore' });
    const bytes = new Uint8Array(readFileSync(join(folder, 'test.p12')));
    assert.equal(inspectPkcs12(bytes).format, 'PKCS#12');
    bytes.fill(0);
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
});
