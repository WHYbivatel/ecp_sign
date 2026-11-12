import test from 'node:test';
import assert from 'node:assert/strict';
import { verify, createPublicKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rsaFixture, gostFixture, pkcs12Container, pkcs12FromContents, encryptedSafe, shroudedKeyBag, certificateBag, integerBytes, opensslPassFile, PASSWORD } from './helpers/fixtures.js';
import { openContainer, GostSign } from '../extension/crypto/signer.js';
import { CONTAINER_FAILURES } from '../extension/lib/pkcs12.js';
import { forge, A, parse, der, bytes, binary, oid } from '../extension/crypto/encoding.js';

// Disposable keys only. Every password below is public test data.
const PASSWORDS = {
  ascii: PASSWORD,
  cyrillic: 'тестовый-пароль',
  kazakh: 'Ұлттық куәлік әғқңөұүһі 2026',
  spaces: '  пароль с пробелами  ',
  emoji: 'тест-🔑-ключ'
};
const data = new TextEncoder().encode('Tegin PKCS#12 regression: Сәлем');

function opensslOpens(container, password, profile) {
  const folder = mkdtempSync(join(tmpdir(), 'tegin-p12-check-'));
  try {
    writeFileSync(join(folder, 'key.p12'), container);
    execFileSync('openssl', ['pkcs12', '-in', join(folder, 'key.p12'), '-nodes', '-passin', opensslPassFile(folder, password),
      '-out', join(folder, 'out.pem'), ...(profile === 'legacy' ? ['-legacy'] : [])], { stdio: 'pipe' });
    return true;
  } catch { return false; } finally { rmSync(folder, { recursive: true, force: true }); }
}
async function rejectsWith(promise, code, stage) {
  await assert.rejects(promise, error => {
    assert.equal(error.code, code, error.message);
    assert.equal(error.stage, stage);
    const allowed = [CONTAINER_FAILURES[code][1], ...(code === 'CONTAINER_LIMITS' ? ['Число итераций защиты контейнера не поддерживается.', 'Слишком сложная структура контейнера.'] : [])];
    assert.ok(allowed.includes(error.message), `unexpected message: ${error.message}`);
    assertSafeDiagnostic(error);
    return true;
  });
}
function assertSafeDiagnostic(error, forbidden = []) {
  const diagnostic = error.diagnostic;
  assert.deepEqual(Object.keys(diagnostic).sort(), ['code', 'container', 'stage']);
  assert.equal(diagnostic.code, error.code);
  for (const key of Object.keys(diagnostic.container)) assert.ok(['size', 'encoding', 'integrity', 'encryption', 'bags', 'keyAlgorithms'].includes(key), key);
  (function leaves(value) {
    if (value === undefined || typeof value === 'number') return;
    if (typeof value === 'string') return assert.match(value, /^(\d+(\.\d+)+|DER|BER)$/);
    for (const item of Object.values(value)) leaves(item);
  })(diagnostic.container);
  const text = JSON.stringify(diagnostic);
  for (const value of forbidden) assert.ok(!text.includes(value), `diagnostic leaks ${value}`);
}
// Rewrites a container through forge ASN.1, re-encoding the nested authSafe/safeContents.
function rewrite(container, mutate) {
  const pfx = parse(container);
  const authSafe = parse(pfx.value[1].value[1].value[0].value);
  const safes = authSafe.value.map(content => content.value[0].value === A.oidToDer('1.2.840.113549.1.7.1').getBytes() ? parse(content.value[1].value[0].value) : null);
  mutate({ pfx, authSafe, safes });
  authSafe.value.forEach((content, index) => { if (safes[index]) content.value[1].value[0].value = der(safes[index]); });
  pfx.value[1].value[1].value[0].value = der(authSafe);
  return bytes(der(pfx));
}
const shroudedBag = safes => safes.flatMap(safe => safe?.value || []).find(bag => A.derToOid(bag.value[0].value) === forge.pki.oids.pkcs8ShroudedKeyBag);

test('PBES2 containers open with non-ASCII passwords exactly as OpenSSL accepts them (regression)', async () => {
  for (const profile of ['default', 'legacy', 'pbes2-key-pbe-certs', 'pbe-3des-sha1-mac']) {
    for (const [label, password] of Object.entries(PASSWORDS)) {
      const fixture = rsaFixture({ password, profile });
      assert.ok(opensslOpens(fixture.container, password, profile), `OpenSSL must open ${profile}/${label}`);
      const signer = await openContainer(fixture.container, password);
      const signature = await signer.sign(data);
      assert.ok(verify('sha256', data, createPublicKey(fixture.certificate), signature), `${profile}/${label}`);
      assert.equal(verify('sha256', new TextEncoder().encode('changed'), createPublicKey(fixture.certificate), signature), false);
      signer.destroy();
      await rejectsWith(openContainer(fixture.container, password + 'x'), 'PASSWORD_OR_DAMAGED', 'integrity');
    }
  }
});

test('passwords are neither trimmed nor Unicode-normalized; invalid UTF-16 is rejected explicitly', async () => {
  const spaced = rsaFixture({ password: PASSWORDS.spaces });
  await rejectsWith(openContainer(spaced.container, PASSWORDS.spaces.trim()), 'PASSWORD_OR_DAMAGED', 'integrity');
  const composed = 'Пароль-й'.normalize('NFC');
  const nfc = rsaFixture({ password: composed });
  assert.notEqual(composed.normalize('NFD'), composed);
  await rejectsWith(openContainer(nfc.container, composed.normalize('NFD')), 'PASSWORD_OR_DAMAGED', 'integrity');
  (await openContainer(nfc.container, composed)).destroy();
  await rejectsWith(openContainer(nfc.container, 'abc\uD800'), 'PASSWORD_ENCODING', 'password');
});

test('special empty-password containers follow OpenSSL; the UI still never sends an empty password', async () => {
  for (const profile of ['default', 'legacy']) {
    const fixture = rsaFixture({ password: '', profile });
    assert.ok(opensslOpens(fixture.container, '', profile));
    (await openContainer(fixture.container, '')).destroy();
    await rejectsWith(openContainer(fixture.container, ' '), 'PASSWORD_OR_DAMAGED', 'integrity');
  }
});

test('BER-encoded outer PFX opens with a Unicode password', async () => {
  const fixture = rsaFixture({ password: PASSWORDS.kazakh });
  const raw = fixture.container;
  const header = raw[1] < 128 ? 2 : 2 + (raw[1] & 127);
  const ber = new Uint8Array([48, 128, ...raw.subarray(header), 0, 0]);
  (await openContainer(ber, PASSWORDS.kazakh)).destroy();
  await assert.rejects(openContainer(ber, 'wrong'), error => error.diagnostic.container.encoding === 'BER');
});

test('GOST containers open with Unicode passwords for PKCS#12 PBE and PBES2 key bags', async () => {
  for (const keyEncryption of ['3des', 'pbes2']) {
    const fixture = gostFixture('512', { password: PASSWORDS.kazakh, keyEncryption });
    const signer = await openContainer(fixture.container, PASSWORDS.kazakh);
    const signature = await signer.sign(data);
    const engine = new GostSign({ version: 2012, length: 512, namedCurve: 'T-512-A' });
    assert.ok(engine.verify(fixture.publicKey, signature, await signer.digest(data)));
    assert.equal(engine.verify(fixture.publicKey, signature, await signer.digest(new TextEncoder().encode('changed'))), false);
    signer.destroy();
    await rejectsWith(openContainer(fixture.container, PASSWORDS.cyrillic), 'PASSWORD_OR_DAMAGED', 'integrity');
  }
});

test('tampered MAC, damaged encrypted data and missing MAC are rejected', async () => {
  const fixture = rsaFixture({ password: PASSWORDS.cyrillic });
  const forgedMac = rewrite(fixture.container, ({ pfx }) => {
    const digest = pfx.value[2].value[0].value[1];
    digest.value = String.fromCharCode(digest.value.charCodeAt(0) ^ 1) + digest.value.slice(1);
  });
  await rejectsWith(openContainer(forgedMac, PASSWORDS.cyrillic), 'PASSWORD_OR_DAMAGED', 'integrity');
  const damaged = rewrite(fixture.container, ({ safes }) => {
    const encrypted = shroudedBag(safes).value[1].value[0].value[1];
    const middle = encrypted.value.length >> 1;
    encrypted.value = encrypted.value.slice(0, middle) + String.fromCharCode(encrypted.value.charCodeAt(middle) ^ 1) + encrypted.value.slice(middle + 1);
  });
  await rejectsWith(openContainer(damaged, PASSWORDS.cyrillic), 'PASSWORD_OR_DAMAGED', 'integrity');
  const unprotected = rsaFixture({ password: PASSWORD, profile: 'nomac' });
  await rejectsWith(openContainer(unprotected.container, PASSWORD), 'CONTAINER_NO_INTEGRITY', 'integrity');
});

test('excessive or zero iteration counts are rejected before key derivation', async () => {
  const fixture = rsaFixture({ password: PASSWORD });
  for (const count of [0, 1000001, 2 ** 31]) {
    const mac = rewrite(fixture.container, ({ pfx }) => { pfx.value[2].value[2].value = integerBytes(count); });
    await rejectsWith(openContainer(mac, PASSWORD), 'CONTAINER_LIMITS', 'limits');
  }
  const negative = rewrite(fixture.container, ({ pfx }) => { pfx.value[2].value[2].value = '\x80'; });
  await rejectsWith(openContainer(negative, PASSWORD), 'CONTAINER_LIMITS', 'limits');
  const pbkdf2 = rewrite(fixture.container, ({ safes }) => {
    const kdfParams = shroudedBag(safes).value[1].value[0].value[0].value[1].value[0].value[1];
    kdfParams.value[1].value = integerBytes(2000000);
  });
  await rejectsWith(openContainer(pbkdf2, PASSWORD), 'CONTAINER_LIMITS', 'limits');
});

test('key bags inside EncryptedData are held to the same algorithms and iteration limits (regression)', async () => {
  const fixture = rsaFixture({ password: PASSWORD });
  const privateKey = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(forge.pki.privateKeyFromPem(fixture.publicKey)));
  const certificate = der(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(fixture.certificate)));
  const nested = encrypted => pkcs12FromContents([encryptedSafe([shroudedKeyBag(encrypted), certificateBag(certificate)])]);
  const pbe = () => forge.pki.encryptPrivateKeyInfo(privateKey, PASSWORD, { algorithm: '3des', count: 2048 });
  const pbes2 = () => forge.pki.encryptPrivateKeyInfo(privateKey, PASSWORD, { algorithm: 'aes256', prfAlgorithm: 'sha256', count: 2048 });
  const signer = await openContainer(nested(pbe()), PASSWORD);
  assert.ok(verify('sha256', data, createPublicKey(fixture.certificate), await signer.sign(data)));
  signer.destroy();
  const hooks = [forge.pki.pbe.getCipherForPBES2, forge.pki.pbe.getCipherForPKCS12PBE];
  for (const count of [0, 1000001, 2 ** 31 - 1]) {
    const key = pbe(); key.value[0].value[1].value[1].value = integerBytes(count);
    const started = Date.now();
    await rejectsWith(openContainer(nested(key), PASSWORD), 'CONTAINER_LIMITS', 'decryption');
    const derived = pbes2(); derived.value[0].value[1].value[0].value[1].value[1].value = integerBytes(count);
    await rejectsWith(openContainer(nested(derived), PASSWORD), 'CONTAINER_LIMITS', 'decryption');
    assert.ok(Date.now() - started < 5000, 'limits apply before key derivation');
  }
  const sha224 = pbes2(); sha224.value[0].value[1].value[0].value[1].value.find(node => node.type === A.Type.SEQUENCE).value[0] = oid('1.2.840.113549.2.8');
  await rejectsWith(openContainer(nested(sha224), PASSWORD), 'UNSUPPORTED_ENCRYPTION_ALGORITHM', 'decryption');
  const safe = encryptedSafe([certificateBag(certificate)]);
  safe.value[1].value[0].value[1].value[1].value[1].value[1].value = integerBytes(0);
  await rejectsWith(openContainer(pkcs12FromContents([safe]), PASSWORD), 'CONTAINER_LIMITS', 'limits');
  assert.deepEqual([forge.pki.pbe.getCipherForPBES2, forge.pki.pbe.getCipherForPKCS12PBE], hooks);
});

test('the total key-derivation work of one open is bounded', async () => {
  const fixture = rsaFixture({ password: PASSWORD });
  const privateKey = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(forge.pki.privateKeyFromPem(fixture.publicKey)));
  const certificate = der(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(fixture.certificate)));
  // Bags declare the per-step maximum but are encrypted with 2048 iterations; the hook below
  // derives with 2048 so the test stays fast while Tegin accounts the declared count.
  const encrypted = forge.pki.encryptPrivateKeyInfo(privateKey, PASSWORD, { algorithm: '3des', count: 2048 });
  encrypted.value[0].value[1].value[1].value = integerBytes(1000000);
  const key = shroudedKeyBag(encrypted);
  const original = forge.pki.pbe.getCipherForPKCS12PBE;
  const derived = [];
  const stub = (scheme, params, password) => {
    derived.push(scheme);
    return original(scheme, A.create(A.Class.UNIVERSAL, A.Type.SEQUENCE, true, [params.value[0], A.create(0, A.Type.INTEGER, false, integerBytes(2048))]), password);
  };
  forge.pki.pbe.getCipherForPKCS12PBE = stub;
  try {
    (await openContainer(pkcs12Container([key, key, key, key, key, key, certificateBag(certificate)], PASSWORD), PASSWORD)).destroy();
    assert.equal(derived.length, 6);
    await rejectsWith(openContainer(pkcs12Container([key, key, key, key, key, key, key, certificateBag(certificate)], PASSWORD), PASSWORD), 'CONTAINER_LIMITS', 'decryption');
    assert.equal(derived.length, 12, 'the seventh derivation is refused before it runs');
    assert.equal(forge.pki.pbe.getCipherForPKCS12PBE, stub);
  } finally { forge.pki.pbe.getCipherForPKCS12PBE = original; }
});

test('unsupported integrity and encryption algorithms are reported as such, not as a wrong password', async () => {
  const fixture = rsaFixture({ password: PASSWORD });
  const gostMac = rewrite(fixture.container, ({ pfx }) => { pfx.value[2].value[0].value[0].value[0] = oid('1.2.398.3.10.1.3.3'); });
  await rejectsWith(openContainer(gostMac, PASSWORD), 'UNSUPPORTED_INTEGRITY_ALGORITHM', 'integrity');
  const folder = mkdtempSync(join(tmpdir(), 'tegin-p8-'));
  try {
    writeFileSync(join(folder, 'key.pem'), fixture.publicKey);
    const certificate = der(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(fixture.certificate)));
    for (const [args, expected] of [
      [['-v2', 'aes-256-cbc', '-v2prf', 'hmacWithSHA224'], '1.2.840.113549.2.8'],
      [['-v2', 'camellia-256-cbc'], '1.2.392.200011.61.1.1.1.4']
    ]) {
      execFileSync('openssl', ['pkcs8', '-topk8', '-in', join(folder, 'key.pem'), ...args, '-passout', opensslPassFile(folder, PASSWORDS.cyrillic),
        '-outform', 'DER', '-out', join(folder, 'key.der')], { stdio: 'pipe' });
      const encrypted = A.fromDer(binary(readFileSync(join(folder, 'key.der'))));
      const container = pkcs12Container([shroudedKeyBag(encrypted), certificateBag(certificate)], PASSWORDS.cyrillic);
      await assert.rejects(openContainer(container, PASSWORDS.cyrillic), error => {
        assert.equal(error.code, 'UNSUPPORTED_ENCRYPTION_ALGORITHM');
        assert.equal(error.stage, 'decryption');
        assert.ok(JSON.stringify(error.diagnostic.container.encryption).includes(expected));
        assertSafeDiagnostic(error);
        return true;
      });
    }
  } finally { rmSync(folder, { recursive: true, force: true }); }
});

test('PBES2 password octets follow OpenSSL (UTF-8), Kalkan (low byte) and node-forge writers', async () => {
  const password = PASSWORDS.kazakh;
  const fixture = rsaFixture({ password });
  const privateKey = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(forge.pki.privateKeyFromPem(fixture.publicKey)));
  const certificate = der(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(fixture.certificate)));
  const lowByte = password.replace(/[^]/g, char => String.fromCharCode(char.charCodeAt(0) & 255));
  for (const [label, encoded] of [['utf-8', forge.util.encodeUtf8(password)], ['kalkan low byte', lowByte], ['node-forge string', password]]) {
    const bag = shroudedKeyBag(forge.pki.encryptPrivateKeyInfo(privateKey, encoded, { algorithm: 'aes256', prfAlgorithm: 'sha256', count: 2048 }));
    const container = pkcs12Container([bag, certificateBag(certificate)], password);
    const signer = await openContainer(container, password);
    assert.ok(verify('sha256', data, createPublicKey(fixture.certificate), await signer.sign(data)), label);
    signer.destroy();
    await rejectsWith(openContainer(container, PASSWORDS.cyrillic), 'PASSWORD_OR_DAMAGED', 'integrity');
  }
});

test('integrity and decryption stages are distinguished', async () => {
  const fixture = rsaFixture({ password: PASSWORD });
  const privateKey = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(forge.pki.privateKeyFromPem(fixture.publicKey)));
  const encrypted = forge.pki.encryptPrivateKeyInfo(privateKey, forge.util.encodeUtf8('другой пароль'), { algorithm: 'aes256', prfAlgorithm: 'sha256', count: 2048 });
  const certificate = der(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(fixture.certificate)));
  const container = pkcs12Container([shroudedKeyBag(encrypted), certificateBag(certificate)], PASSWORD);
  await rejectsWith(openContainer(container, PASSWORD), 'DECRYPTION_FAILED', 'decryption');
  await rejectsWith(openContainer(container, 'другой пароль'), 'PASSWORD_OR_DAMAGED', 'integrity');
});

test('key-pair, key algorithm and certificate failures have separate codes and anonymous diagnostics', async () => {
  const subject = '/CN=Иванов Иван Тестович/serialNumber=IIN123456789012';
  const owner = rsaFixture({ password: PASSWORDS.cyrillic, subject });
  const other = rsaFixture({ password: PASSWORDS.cyrillic });
  const privateKey = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(forge.pki.privateKeyFromPem(other.publicKey)));
  const encrypted = forge.pki.encryptPrivateKeyInfo(privateKey, PASSWORDS.cyrillic, { algorithm: '3des', count: 2048 });
  const ownerCertificate = der(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(owner.certificate)));
  const mismatched = pkcs12Container([shroudedKeyBag(encrypted), certificateBag(ownerCertificate)], PASSWORDS.cyrillic);
  const forbidden = ['Иванов', 'IIN123456789012', forge.util.encode64(ownerCertificate).slice(0, 40), PASSWORDS.cyrillic, '.p12'];
  await assert.rejects(openContainer(mismatched, PASSWORDS.cyrillic), error => {
    assert.equal(error.code, 'NO_KEY_PAIR'); assert.equal(error.stage, 'key-pair');
    assert.deepEqual(error.diagnostic.container.bags, { keys: 1, certificates: 1, other: 0 });
    assertSafeDiagnostic(error, forbidden);
    return true;
  });
  await assert.rejects(openContainer(owner.container, PASSWORDS.cyrillic, { now: 0 }), error => {
    assert.equal(error.code, 'CERTIFICATE_NOT_VALID_NOW'); assert.equal(error.stage, 'certificate');
    assert.ok(error.certificate.notAfter, 'Public certificate details stay available to the confirmation window');
    assertSafeDiagnostic(error, forbidden);
    return true;
  });
  const ec = rsaFixture({ password: PASSWORD, keySpec: 'ec:prime256v1' });
  await assert.rejects(openContainer(ec.container, PASSWORD), error => {
    assert.equal(error.code, 'UNSUPPORTED_KEY_ALGORITHM'); assert.equal(error.stage, 'key');
    assert.deepEqual(error.diagnostic.container.keyAlgorithms, ['1.2.840.10045.2.1']);
    assertSafeDiagnostic(error);
    return true;
  });
});

test('structural failures are coded and the forge PBES2 hook is always restored', async () => {
  const original = forge.pki.pbe.getCipherForPBES2;
  await rejectsWith(openContainer(new Uint8Array(), PASSWORD), 'CONTAINER_EMPTY', 'structure');
  await rejectsWith(openContainer(new TextEncoder().encode('not a container'), PASSWORD), 'CONTAINER_MALFORMED', 'structure');
  const fixture = rsaFixture({ password: PASSWORDS.emoji });
  await assert.rejects(openContainer(fixture.container, PASSWORD));
  (await openContainer(fixture.container, PASSWORDS.emoji)).destroy();
  assert.equal(forge.pki.pbe.getCipherForPBES2, original);
  const [, message] = CONTAINER_FAILURES.PASSWORD_OR_DAMAGED;
  assert.equal(message, 'Пароль не подошёл или контейнер повреждён.');
});
