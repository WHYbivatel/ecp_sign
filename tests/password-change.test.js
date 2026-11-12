import test from 'node:test';
import assert from 'node:assert/strict';
import { verify, createPublicKey } from 'node:crypto';
import { rsaFixture, gostFixture, pkcs12Container, certificateBag, PASSWORD } from './helpers/fixtures.js';
import { changeContainerPassword, CHANGE_PASSWORD_RULE } from '../extension/crypto/password-change.js';
import { openContainer, gostEngine, certificateInfo } from '../extension/crypto/signer.js';
import { forge, parse, der } from '../extension/crypto/encoding.js';

// Disposable keys only. Every password below is public test data.
const NEW_PASSWORD = 'NewPass2026';
const data = new TextEncoder().encode('Tegin password change: Сәлем');

async function contents(container, password) {
  const opened = await openContainer(container, password, { exportKey: true });
  try { return { key: der(opened.privateKeyInfo()), leaf: opened.info.raw, certificates: opened.certificates.map(der).sort(), alias: opened.alias, protection: opened.protection }; }
  finally { opened.destroy(); }
}
async function assertChanged(container, oldPassword, { verifySignature } = {}) {
  const original = container.slice();
  const changed = await changeContainerPassword(container, oldPassword, NEW_PASSWORD);
  assert.deepEqual(container, original, 'the selected container is not modified');
  const before = await contents(original, oldPassword), after = await contents(changed.container, NEW_PASSWORD);
  assert.equal(after.key, before.key, 'same PKCS#8');
  assert.equal(after.leaf, before.leaf);
  assert.deepEqual(after.certificates, before.certificates);
  assert.equal(after.alias, before.alias ?? after.alias);
  await assert.rejects(openContainer(changed.container, oldPassword), { code: 'PASSWORD_OR_DAMAGED' });
  assert.deepEqual(after.protection.integrity, { algorithm: '2.16.840.1.101.3.4.2.1', iterations: 100000 });
  assert.ok(after.protection.encryption.every(entry => entry.cipher === '2.16.840.1.101.3.4.1.42' && entry.prf === '1.2.840.113549.2.9' && entry.iterations === 100000));
  assert.equal(changed.protection.after.integrity, 'HMAC-SHA-256, 100\u00a0000 итераций');
  assert.deepEqual(changed.protection.after.encryption, ['PBES2 AES-256-CBC, PBKDF2-HMAC-SHA-256, 100\u00a0000 итераций']);
  const signer = await openContainer(changed.container, NEW_PASSWORD);
  try { await verifySignature(signer, await signer.sign(data)); } finally { signer.destroy(); }
  return changed;
}

for (const profile of ['default', 'legacy']) {
  test(`RSA container from OpenSSL (${profile}) gets a new password and keeps key and certificate`, async () => {
    const fixture = rsaFixture({ profile });
    const changed = await assertChanged(fixture.container, PASSWORD, {
      verifySignature: (signer, signature) => assert.ok(verify('sha256', data, createPublicKey(fixture.certificate), signature))
    });
    assert.match(changed.protection.before.integrity, profile === 'legacy' ? /^HMAC-SHA-1, / : /^HMAC-SHA-256, /);
  });
}

for (const family of ['512', '256', '2004']) {
  test(`GOST ${family} container gets a new password and keeps the original PKCS#8`, async () => {
    const fixture = gostFixture(family);
    await assertChanged(fixture.container, PASSWORD, {
      verifySignature: async (signer, signature) => {
        const engine = gostEngine(signer.info.algorithm);
        assert.ok(engine.verify(fixture.publicKey, signature, await signer.digest(data)));
      }
    });
  });
}

test('a Kazakh old password and an intermediate certificate are carried over', async () => {
  const oldPassword = 'Ұлттық куәлік әғқңөұүһі 2026';
  const leaf = gostFixture('512', { password: oldPassword, keyEncryption: 'pbes2' });
  const other = gostFixture('256');
  const pfx = parse(leaf.container);
  const authSafe = parse(pfx.value[1].value[1].value[0].value);
  const bags = authSafe.value.flatMap(content => parse(content.value[1].value[0].value).value);
  const container = pkcs12Container([...bags, certificateBag(forge.util.decode64(other.certificate))], oldPassword);
  await assertChanged(container, oldPassword, {
    verifySignature: async (signer, signature) => assert.ok(gostEngine(signer.info.algorithm).verify(leaf.publicKey, signature, await signer.digest(data)))
  });
  const changed = await changeContainerPassword(container, oldPassword, NEW_PASSWORD);
  assert.equal((await contents(changed.container, NEW_PASSWORD)).certificates.length, 2);
});

test('new passwords follow the NCALayer PKCS#12 rule', async () => {
  for (const value of ['abc123', 'Password1', 'a1'.repeat(16), 'x.?#$^+=!*()@%&_-1']) assert.ok(CHANGE_PASSWORD_RULE.test(value), value);
  for (const value of ['abc12', 'onlyletters', '12345678', 'a1'.repeat(16) + 'x', 'пароль123', 'pass word1', 'pass/word1']) assert.ok(!CHANGE_PASSWORD_RULE.test(value), value);
  const { container } = rsaFixture();
  await assert.rejects(changeContainerPassword(container, PASSWORD, 'onlyletters'), { code: 'CHANGEPASS_INCORRECT_NEWPASS_PATTERN' });
  await assert.rejects(changeContainerPassword(container, 'Same2026', 'Same2026'), { code: 'CHANGEPASS_SAME_PASSWORD' });
});

test('a wrong old password is refused without details', async () => {
  const { container } = gostFixture('512');
  await assert.rejects(changeContainerPassword(container, PASSWORD + 'x', NEW_PASSWORD), error => {
    assert.equal(error.code, 'PASSWORD_OR_DAMAGED');
    assert.ok(!error.message.includes(PASSWORD) && !error.message.includes(NEW_PASSWORD));
    return true;
  });
});

test('containers with more than the key and its certificates are not rewritten', async () => {
  const first = gostFixture('512'), second = gostFixture('256');
  const bagsOf = container => parse(parse(container).value[1].value[1].value[0].value).value.flatMap(content => parse(content.value[1].value[0].value).value);
  const twoKeys = pkcs12Container([...bagsOf(first.container), ...bagsOf(second.container)]);
  await assert.rejects(changeContainerPassword(twoKeys, PASSWORD, NEW_PASSWORD), { code: 'CHANGE_PASSWORD_CONSTRAINT' });
  // A second key without its certificate would otherwise be dropped from the new file.
  const orphanKey = bagsOf(second.container).find(bag => forge.asn1.derToOid(bag.value[0].value) === forge.pki.oids.pkcs8ShroudedKeyBag);
  const orphan = pkcs12Container([...bagsOf(first.container), orphanKey]);
  await assert.rejects(changeContainerPassword(orphan, PASSWORD, NEW_PASSWORD), { code: 'CHANGE_PASSWORD_CONSTRAINT' });
});

test('aliases and BMPString names are encoded once', async () => {
  const { container } = gostFixture('512');
  const changed = await changeContainerPassword(container, PASSWORD, NEW_PASSWORD);
  const store = forge.pkcs12.pkcs12FromAsn1(parse(changed.container), true, NEW_PASSWORD);
  const bags = store.safeContents.flatMap(safe => safe.safeBags).filter(bag => bag.attributes.friendlyName);
  const localKeyId = forge.util.bytesToHex(bags[0].attributes.localKeyId[0]);
  assert.equal(bags.length, 2);
  for (const bag of bags) assert.deepEqual(bag.attributes.friendlyName, [localKeyId]);

  const certificate = parse(forge.util.decode64(gostFixture('256').certificate));
  const tbs = certificate.value[0].value;
  tbs[5].value[0].value[0].value[1] = forge.asn1.create(0, forge.asn1.Type.BMPSTRING, false, 'Әлия Сәтбаева');
  assert.equal(certificateInfo(certificate).summary.name, 'Әлия Сәтбаева');
});

test('the export accessor is absent from ordinary opens and closed after destroy', async () => {
  const { container } = gostFixture('512');
  const ordinary = await openContainer(container, PASSWORD);
  assert.equal(ordinary.privateKeyInfo, undefined);
  ordinary.destroy();
  const exporting = await openContainer(container, PASSWORD, { exportKey: true });
  exporting.destroy();
  assert.throws(() => exporting.privateKeyInfo(), /закрыт/);
});
