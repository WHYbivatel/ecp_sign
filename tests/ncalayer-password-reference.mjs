// Development-only reference run of the NUC password page flow in the official NCALayer Applet
// module (knca_applet 0.4.10): browseKeyStore through NCALayer's own file dialog, then
// changePassword with the returned path. Also feeds it containers whose password Tegin changed.
// Disposable Kalkan keys and public test passwords; writes tests/fixtures/ncalayer-password-results.json.
//   NCA_BUNDLES  folder with knca_applet, knca_provider_util, kalkancrypt, NCALayerServices, NCALayerCommonBundle jars
//   NCA_CORE     folder with org/json and org/slf4j (without org/slf4j/impl) from NCALayer's own jar
//   NCA_JAVA     a Java 8+ runtime with AWT, e.g. NCALayer's bundled jre8_ncalayer/bin/java
// Needs a display: run under xvfb-run on Linux.
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { changeContainerPassword } from '../extension/crypto/password-change.js';

const { NCA_BUNDLES: bundles, NCA_CORE: core } = process.env;
if (!bundles || !core) throw new Error('Set NCA_BUNDLES and NCA_CORE (see the header of this file).');
const java = process.env.NCA_JAVA || 'java', javac = process.env.NCA_JAVAC || 'javac';
const jars = ['knca_applet-0.4.10', 'knca_provider_util-0.8.8', 'kalkancrypt-0.7.8', 'NCALayerServices-0.7.4', 'NCALayerCommonBundle-0.3.4'].map(name => join(bundles, `${name}.jar`));
const folder = mkdtempSync(join(tmpdir(), 'tegin-applet-password-'));
const classes = join(folder, 'classes');
const classpath = [classes, ...jars, core].join(':');
const run = (passwords, ...args) => execFileSync(java, ['-cp', classpath, ...args],
  { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, TEGIN_TEST_P12_PASSWORD: passwords[0], TEGIN_TEST_NEW_PASSWORD: passwords[1] ?? '' } });
const CHECKS = { browseKeyStore: { result: '<selected file>', errorCode: 'NONE' }, browseKeyStoreCancel: { errorCode: 'NONE' },
  changePasswordWrongOld: { errorCode: 'CHANGEPASS_WRONG_PASSWORD' }, changePasswordWeakNew: { errorCode: 'CHANGEPASS_INCORRECT_NEWPASS_PATTERN' },
  unchangedAfterRefusals: true, changePassword: { errorCode: 'NONE' }, fileOverwrittenInPlace: true, opensWithNewPassword: true, oldPasswordRejected: true, sameKeyAndCertificates: true };
const results = [];
try {
  mkdirSync(classes);
  // The Settings and BundleLog stand-ins replace knca_applet's OSGi-only classes; everything else is official.
  execFileSync(javac, ['--release', '8', '-nowarn', '-cp', [...jars, core].join(':'), '-d', classes,
    ...['ncalayer-stub/Settings.java', 'ncalayer-stub/BundleLog.java', 'Pkcs12Interop.java', 'AppletReference.java'].map(file => resolve('tests/interop', file))], { stdio: 'pipe' });
  for (const family of ['RSA', 'GOST512', 'GOST256', 'GOST2004']) {
    for (const source of ['kalkan', 'tegin']) {
      const work = join(folder, `${family}-${source}`); mkdirSync(work);
      const container = join(work, 'key.p12'), original = join(work, 'original.bin');
      run(['Kalkan1old'], 'Pkcs12Interop', 'create', family, 'PKCS12', container);
      let oldPassword = 'Kalkan1old';
      if (source === 'tegin') {
        const changed = await changeContainerPassword(new Uint8Array(readFileSync(container)), oldPassword, 'Tegin2new');
        writeFileSync(container, changed.container);
        oldPassword = 'Tegin2new';
      }
      copyFileSync(container, original);
      const report = JSON.parse(run([oldPassword, 'Ncalayer3new'], 'AppletReference', container, original));
      assert.deepEqual(report, CHECKS, `${family} ${source}`);
      results.push({ family, container: source === 'kalkan' ? 'created by Kalkan' : 'created by Kalkan, password changed by Tegin', ...report });
      console.log(`PASS ${family} | ${source === 'kalkan' ? 'Kalkan container' : 'Tegin-changed container'}: browseKeyStore returned the path, wrong old and weak new passwords refused, changePassword overwrote the file in place, new password opens it, old password rejected, key and certificates unchanged`);
    }
  }
  writeFileSync(resolve('tests/fixtures/ncalayer-password-results.json'), JSON.stringify({
    source: 'knca_applet 0.4.10 Applet.browseKeyStore/changePassword with knca_provider_util 0.8.8 and kalkancrypt 0.7.8 on NCALayer jre8 under Xvfb; dispatcher as in KNCAAppletActivator; tests/ncalayer-password-reference.mjs',
    request: { browseKeyStore: ['PKCS12', 'P12', '<folder>'], changePassword: ['PKCS12', '<path returned by browseKeyStore>', '<old password>', '<new password>'] },
    results }, null, 2) + '\n');
  console.log(`NCALayer password reference: ${results.length}/8`);
} finally { rmSync(folder, { recursive: true, force: true }); }
