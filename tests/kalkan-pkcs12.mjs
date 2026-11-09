// Development-only PKCS#12 interop with the official Kalkan provider.
// Disposable keys and public test passwords only. Never starts NCALayer or installs Java.
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { rsaFixture, pkcs12Container, shroudedKeyBag, certificateBag, opensslPassword } from './helpers/fixtures.js';
import { openContainer } from '../extension/crypto/signer.js';
import { signCms } from '../extension/crypto/cms.js';
import { forge, der } from '../extension/crypto/encoding.js';

const jars = process.env.NCA_KALKAN_JARS;
if (!jars) throw new Error('Set NCA_KALKAN_JARS to the provider and XMLDSig jars (separated by the OS classpath delimiter).');
const java = process.env.NCA_JAVA || 'java';
const javac = process.env.NCA_JAVAC || 'javac';
const delimiter = process.platform === 'win32' ? ';' : ':';
const passwords = { ascii: 'public-test-password', cyrillic: 'тестовый-пароль', kazakh: 'Ұлттық куәлік әғқңөұүһі 2026' };
const folder = mkdtempSync(join(tmpdir(), 'tegin-kalkan-p12-'));
const run = (password, ...args) => execFileSync(java, ['-cp', `${jars}${delimiter}${folder}`, ...args], { ...opensslPassword(password), encoding: 'utf8' });
const kalkanOpens = (password, path) => { try { return run(password, 'Pkcs12Interop', 'open', path).includes('KALKAN OPEN OK'); } catch { return false; } };
const describe = profile => `MAC ${profile.integrity.algorithm}/${profile.integrity.iterations}; ` +
  profile.encryption.map(entry => [entry.scheme, entry.kdf, entry.prf, entry.cipher, entry.iterations].filter(Boolean).join('/')).join(', ');
try {
  execFileSync(javac, ['-cp', jars, '-d', folder, resolve('tests/interop/Pkcs12Interop.java'), resolve('tests/interop/Verify.java')], { stdio: 'pipe' });
  const document = new TextEncoder().encode('Kalkan PKCS#12 interop document: Сәлем');
  const documentPath = join(folder, 'document.bin'), changedPath = join(folder, 'changed.bin');
  writeFileSync(documentPath, document);
  writeFileSync(changedPath, new TextEncoder().encode('Kalkan PKCS#12 interop document: changed'));

  // Containers generated and stored by Kalkan itself, opened and used by Tegin, verified by Kalkan.
  for (const family of ['RSA', 'GOST512', 'GOST256', 'GOST2004']) {
    for (const [label, password] of Object.entries(passwords)) {
      const path = join(folder, 'kalkan.p12');
      run(password, 'Pkcs12Interop', 'create', family, 'PKCS12', path);
      const container = new Uint8Array(readFileSync(path));
      const wrong = await openContainer(container, password + 'x').then(() => null, error => error);
      assert.equal(wrong?.code, 'PASSWORD_OR_DAMAGED');
      const signer = await openContainer(container, password);
      try {
        for (const encapsulate of [true, false]) {
          const signature = join(folder, 'signature.p7s');
          writeFileSync(signature, await signCms(signer, document, { encapsulate, cades: true }));
          assert.match(run(password, 'Verify', 'cms', signature, ...(encapsulate ? [] : [documentPath])), /KALKAN CMS VALID/);
          if (!encapsulate) assert.throws(() => run(password, 'Verify', 'cms', signature, changedPath));
        }
      } finally { signer.destroy(); container.fill(0); }
      console.log(`PASS Kalkan-created ${family} | ${label}: Tegin opens, CAdES attached/detached verified by Kalkan, changed document and wrong password rejected | ${describe(wrong.diagnostic.container)}`);
    }
  }

  // Which PBES2 password encodings Kalkan itself accepts (informational; a refusal is not proof of damage).
  const password = passwords.cyrillic;
  const fixture = rsaFixture({ password });
  const privateKey = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(forge.pki.privateKeyFromPem(fixture.publicKey)));
  const certificate = der(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(fixture.certificate)));
  const lowByte = password.replace(/[^]/g, char => String.fromCharCode(char.charCodeAt(0) & 255));
  for (const [label, encoded] of [['UTF-8', forge.util.encodeUtf8(password)], ['low byte', lowByte]]) {
    const path = join(folder, 'pbes2.p12');
    const bag = shroudedKeyBag(forge.pki.encryptPrivateKeyInfo(privateKey, encoded, { algorithm: 'aes256', prfAlgorithm: 'sha256', count: 2048 }));
    writeFileSync(path, pkcs12Container([bag, certificateBag(certificate)], password));
    (await openContainer(new Uint8Array(readFileSync(path)), password)).destroy();
    console.log(`INFO PBES2 AES-256/hmacWithSHA256, Cyrillic password as ${label}: Kalkan ${kalkanOpens(password, path) ? 'opens' : 'refuses'}; Tegin opens`);
  }
  for (const profile of ['default', 'legacy']) {
    const path = join(folder, 'openssl.p12');
    writeFileSync(path, rsaFixture({ password, profile }).container);
    console.log(`INFO OpenSSL ${profile} profile, Cyrillic password: Kalkan ${kalkanOpens(password, path) ? 'opens' : 'refuses'}`);
  }
} finally { rmSync(folder, { recursive: true, force: true }); }
