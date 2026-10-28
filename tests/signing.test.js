import test from 'node:test';
import assert from 'node:assert/strict';
import { verify, createPublicKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { SignedXml } from 'xml-crypto';
import { DOMParser } from '@xmldom/xmldom';
import { rsaFixture, gostFixture, PASSWORD } from './helpers/fixtures.js';
import { openContainer, GostDigest, GostSign } from '../extension/crypto/signer.js';
import { signCms } from '../extension/crypto/cms.js';
import { signXml } from '../extension/crypto/xml.js';

test('RSA local signatures verify with Node crypto, CMS with OpenSSL, and XML with XML-crypto', async () => {
  const fixture = rsaFixture();
  const signer = await openContainer(fixture.container, PASSWORD);
  const data = new TextEncoder().encode('Подпись Tegin\n');
  const signature = await signer.sign(data);
  assert.ok(verify('sha256', data, createPublicKey(fixture.certificate), signature));
  const folder = mkdtempSync(join(tmpdir(), 'ncabrowser-verify-'));
  try {
    writeFileSync(join(folder, 'data'), data);
    for (const encapsulate of [true, false]) {
      writeFileSync(join(folder, 'signature.der'), await signCms(signer, data, { encapsulate }));
      const args = ['cms', '-verify', '-binary', '-inform', 'DER', '-in', join(folder, 'signature.der'), '-noverify', '-out', join(folder, 'out')];
      if (!encapsulate) args.push('-content', join(folder, 'data'));
      execFileSync('openssl', args, { stdio: 'pipe' });
      assert.deepEqual(readFileSync(join(folder, 'out')), Buffer.from(data));
    }
    writeFileSync(join(folder, 'cert.pem'), fixture.certificate);
    writeFileSync(join(folder, 'cades.der'), await signCms(signer, data, { cades: true }));
    execFileSync('openssl', ['cms', '-verify', '-cades', '-binary', '-inform', 'DER', '-in', join(folder, 'cades.der'), '-CAfile', join(folder, 'cert.pem'), '-purpose', 'any', '-out', join(folder, 'out')], { stdio: 'pipe' });
    assert.deepEqual(readFileSync(join(folder, 'out')), Buffer.from(data));
  } finally { rmSync(folder, { recursive: true, force: true }); }
  const xml = await signXml(signer, '<request xmlns="urn:ncabrowser:test" b="2" a="1"><text><![CDATA[Привет & мир]]></text></request>');
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const verifier = new SignedXml({ publicCert: fixture.certificate, getCertFromKeyInfo: () => null });
  verifier.loadSignature(doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0]);
  assert.ok(verifier.checkSignature(xml));
  assert.equal(verifier.checkSignature(xml.replace('Привет', 'Подмена')), false);
  signer.destroy();
});

test('GOST-512 PKCS12 opens and makes a correctly encoded signature', async () => {
  const fixture = gostFixture();
  const signer = await openContainer(fixture.container, PASSWORD);
  const data = new TextEncoder().encode('GOST cross-check');
  const hash = await signer.digest(data);
  const signature = await signer.sign(data);
  const engine = new GostSign({ version: 2012, length: 512, namedCurve: 'T-512-A' });
  assert.equal(signature.length, 128);
  assert.ok(engine.verify(fixture.publicKey, signature, hash));
  assert.ok(!engine.verify(fixture.publicKey, signature, new Uint8Array(64)));
  signer.destroy();
});

test('Streebog matches an independently calculated known answer', () => {
  const hash = new GostDigest({ version: 2012, length: 512 }).digest(new Uint8Array());
  assert.equal(Buffer.from(hash).toString('hex'), '8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a');
});

test('wrong passwords, expired certificates, hostile XML and co-signing fail explicitly', async () => {
  const fixture = rsaFixture();
  await assert.rejects(openContainer(fixture.container, 'wrong'), /пароль/);
  await assert.rejects(openContainer(fixture.container, PASSWORD, { now: 0 }), error => {
    assert.match(error.message, /Срок/);
    assert.ok(error.certificate.notBefore); assert.ok(error.certificate.notAfter);
    assert.ok(Array.isArray(error.certificate.extendedKeyUsageOids));
    assert.equal(error.certificate.key, undefined);
    return true;
  });
  const signer = await openContainer(fixture.container, PASSWORD);
  await assert.rejects(signXml(signer, '<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><x>&x;</x>'), /DTD/);
  await assert.rejects(signXml(signer, '<x><broken></x>'), /XML/);
  const signed = await signXml(signer, '<x/>');
  await assert.rejects(signXml(signer, signed), /Доподписание/);
  signer.destroy();
});
