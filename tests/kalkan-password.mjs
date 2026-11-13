// Development-only check of the password change against the official Kalkan provider.
// Kalkan creates the container, Tegin changes the password, Kalkan opens both files and compares
// keys, certificates and aliases. Disposable keys and public test passwords only.
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { changeContainerPassword } from '../extension/crypto/password-change.js';
import { rsaFixture, PASSWORD } from './helpers/fixtures.js';

const jars = process.env.NCA_KALKAN_JARS;
if (!jars) throw new Error('Set NCA_KALKAN_JARS to the provider and XMLDSig jars (separated by the OS classpath delimiter).');
const java = process.env.NCA_JAVA || 'java';
const javac = process.env.NCA_JAVAC || 'javac';
const delimiter = process.platform === 'win32' ? ';' : ':';
const passwords = { ascii: 'public-test-password', cyrillic: 'тестовый-пароль', kazakh: 'Ұлттық куәлік әғқңөұүһі 2026' };
const NEW_PASSWORD = 'NewPass2026';
const folder = mkdtempSync(join(tmpdir(), 'tegin-kalkan-password-'));
const run = (password, ...args) => execFileSync(java, ['-cp', `${jars}${delimiter}${folder}`, ...args],
  { stdio: 'pipe', encoding: 'utf8', env: { ...process.env, TEGIN_TEST_P12_PASSWORD: password, TEGIN_TEST_NEW_PASSWORD: NEW_PASSWORD } });
let passed = 0;
try {
  execFileSync(javac, ['-cp', jars, '-d', folder, resolve('tests/interop/Pkcs12Interop.java')], { stdio: 'pipe' });
  for (const family of ['RSA', 'GOST512', 'GOST256', 'GOST2004']) {
    for (const [label, password] of Object.entries(passwords)) {
      const original = join(folder, 'kalkan.p12'), changed = join(folder, 'changed.p12');
      run(password, 'Pkcs12Interop', 'create', family, 'PKCS12', original);
      const before = readFileSync(original);
      const result = await changeContainerPassword(new Uint8Array(before), password, NEW_PASSWORD);
      assert.deepEqual(readFileSync(original), before, 'the original file is untouched');
      writeFileSync(changed, result.container);
      const report = run(password, 'Pkcs12Interop', 'compare', original, changed);
      assert.match(report, /KALKAN SAME KEY AND CERTIFICATES/);
      assert.match(report, /KALKAN ALIAS SAME/);
      assert.match(report, /KALKAN OLD PASSWORD REJECTED/);
      assert.match(run(NEW_PASSWORD, 'Pkcs12Interop', 'open', changed), /KALKAN OPEN OK/);
      passed++;
      console.log(`PASS Kalkan-created ${family} | old password ${label}: Tegin changed it; Kalkan opens the new file with the new password, `
        + `same key, certificates and alias, old password rejected | ${result.protection.before.integrity} -> ${result.protection.after.integrity}`);
    }
  }
  // An expired certificate: the change is allowed, Kalkan sees the same key and certificates.
  const day = 24 * 60 * 60 * 1000;
  const expired = rsaFixture({ subject: '/CN=Tegin expired disposable test', validity: { notBefore: new Date(Date.now() - 400 * day), notAfter: new Date(Date.now() - day) } });
  const original = join(folder, 'expired.p12'), changed = join(folder, 'expired-changed.p12');
  writeFileSync(original, expired.container);
  const result = await changeContainerPassword(expired.container.slice(), PASSWORD, NEW_PASSWORD);
  assert.equal(result.certificate.expired, true);
  writeFileSync(changed, result.container);
  const report = run(PASSWORD, 'Pkcs12Interop', 'compare', original, changed);
  assert.match(report, /KALKAN SAME KEY AND CERTIFICATES/);
  assert.match(report, /KALKAN OLD PASSWORD REJECTED/);
  passed++;
  console.log('PASS OpenSSL RSA with an expired certificate: Tegin changed the password; Kalkan opens the new file, same key and certificates, old password rejected');
  console.log(`Kalkan password change: ${passed}/13`);
} finally { rmSync(folder, { recursive: true, force: true }); }
