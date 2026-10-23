import test from 'node:test';
import assert from 'node:assert/strict';
import { rsaFixture, gostFixture, PASSWORD } from './helpers/fixtures.js';
import { openContainer, certificateInfo } from '../extension/crypto/signer.js';
import { signCms } from '../extension/crypto/cms.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';
import { verifyChain } from '../extension/crypto/chain.js';
import { trustStore } from '../extension/crypto/trust-store.js';
import { makeTimestampRequest, verifyTimestampResponse, TSA_POLICY } from '../extension/crypto/timestamp.js';
import { A, O, forge, bytes, der, parse, set, seq, oid, octet, integer, unbase64 } from '../extension/crypto/encoding.js';

for (const [family, makeFixture] of [['RSA', rsaFixture], ['GOST512', gostFixture], ['GOST256', () => gostFixture('256')], ['GOST2004', () => gostFixture('2004')]]) test(`${family}: CMS verification, detached prehash, CAdES binding and tampering`, async () => {
  const fixture = makeFixture(); const signer = await openContainer(fixture.container, PASSWORD);
  const data = new TextEncoder().encode('Public verification fixture: Привет');
  try {
    for (const cades of [false, true]) for (const encapsulate of [false, true]) {
      const raw = await signCms(signer, data, { cades, encapsulate });
      const verified = await verifyCms(raw, { detached: encapsulate ? undefined : data });
      assert.equal(verified.valid, true); assert.equal(verified.signers[0].cades, cades);
      assert.equal(verified.signers[0].trust.trusted, false);
      assert.deepEqual(verified.content, data);
      const changed = data.slice(); changed[0] ^= 1;
      await assert.rejects(verifyCms(raw, { detached: changed }));
      if (!encapsulate) await assert.rejects(verifyCms(raw), /исходный документ/);
      const corrupted = raw.slice(); corrupted[corrupted.length - 4] ^= 1;
      await assert.rejects(verifyCms(corrupted, { detached: data }));
    }
    for (const cades of [false, true]) {
      const raw = await signCms(signer, await signer.digest(data), { digested: true, encapsulate: false, cades });
      assert.equal((await verifyCms(raw, { detached: data })).valid, true);
    }
    await assert.rejects(signCms(signer, new Uint8Array(7), { digested: true, encapsulate: false }), /Длина хеша/);
    const raw = await signCms(signer, data, { cades: true });
    const parsed = parse(raw); const attrs = parsed.value[1].value[0].value.at(-1).value[0].value[3];
    attrs.value.push(attrs.value[0]);
    await assert.rejects(verifyCms(bytes(der(parsed))), /повторяются/);
  } finally { signer.destroy(); fixture.container.fill(0); }
});

test('bundled NUC certificates have pinned hashes and valid paths; fabricated roots need explicit trust', async () => {
  for (const entry of trustStore) {
    const raw = unbase64(entry.certificate);
    const hash = Buffer.from(await crypto.subtle.digest('SHA-256', raw)).toString('hex');
    assert.equal(hash, entry.sha256);
    const chain = await verifyChain(certificateInfo(raw));
    assert.equal(chain.trusted, true, chain.reason);
    assert.equal(chain.revocation, 'not-checked');
    assert.equal((await verifyChain(certificateInfo(raw), [], { now: 0 })).trusted, false);
  }
  const fixture = rsaFixture(); const cert = certificateInfo(bytes(forge.pem.decode(fixture.certificate)[0].body));
  assert.equal((await verifyChain(cert)).trusted, false);
  assert.equal((await verifyChain(cert, [], { anchors: [bytes(cert.raw)] })).trusted, true);
});

test('RFC3161 requests contain only imprint, policy and nonce; malformed responses never become optional', async () => {
  const signature = new TextEncoder().encode('synthetic-signature-no-private-data');
  const request = await makeTimestampRequest(signature);
  const fields = parse(request.body).value;
  assert.equal(fields.length, 5); assert.equal(request.nonce.length, 16);
  assert.ok(!Buffer.from(request.body).includes(Buffer.from(signature)));
  assert.equal(A.derToOid(fields[2].value), TSA_POLICY);
  assert.equal(fields[1].value[1].value.length, 64);
  await assert.rejects(verifyTimestampResponse(bytes(der(seq(seq(integer(2))))), request), /не выдал/);
  await assert.rejects(verifyTimestampResponse(new Uint8Array(256 * 1024 + 1), request), /слишком большой/);
  const fixture = rsaFixture(); const signer = await openContainer(fixture.container, PASSWORD);
  try {
    await assert.rejects(signCms(signer, signature, { timestamp: true, timestampRequester: async () => { throw new Error('TSA unavailable'); } }), /TSA unavailable/);
    const fake = await signCms(signer, signature, { cades: true });
    await assert.rejects(verifyTimestampResponse(bytes(der(seq(seq(integer(0)), parse(fake)))), request));
  } finally { signer.destroy(); }
});

test('certificate paths reject forged signatures, critical unknown extensions and untrusted issuers', async () => {
  const fixture = rsaFixture();
  const root = forge.pki.certificateFromPem(fixture.certificate);
  const key = forge.pki.privateKeyFromPem(fixture.publicKey);
  const anchor = bytes(der(forge.pki.certificateToAsn1(root)));
  const leaf = forge.pki.createCertificate(); leaf.serialNumber = '02'; leaf.publicKey = root.publicKey;
  leaf.setIssuer(root.subject.attributes); leaf.setSubject([{ name: 'commonName', value: 'Disposable leaf' }]);
  leaf.validity.notBefore = new Date(Date.now() - 60000); leaf.validity.notAfter = new Date(Date.now() + 3600000);
  leaf.setExtensions([{ name: 'basicConstraints', cA: false, critical: true }, { name: 'keyUsage', digitalSignature: true, critical: true }]);
  leaf.sign(key, forge.md.sha256.create());
  const raw = bytes(der(forge.pki.certificateToAsn1(leaf)));
  assert.equal((await verifyChain(certificateInfo(raw), [], { anchors: [anchor] })).trusted, true);
  assert.equal((await verifyChain(certificateInfo(raw))).trusted, false);
  const tampered = raw.slice(); tampered[tampered.length - 1] ^= 1;
  assert.equal((await verifyChain(certificateInfo(tampered), [], { anchors: [anchor] })).trusted, false);
  leaf.setExtensions([{ id: '1.2.3.4.5', critical: true, value: der(seq()) }]); leaf.sign(key, forge.md.sha256.create());
  const unknown = certificateInfo(forge.pki.certificateToAsn1(leaf));
  assert.equal((await verifyChain(unknown, [], { anchors: [anchor] })).trusted, false);
});
