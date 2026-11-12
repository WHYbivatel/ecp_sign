// Development-only interop of NUC key issuance with the official Kalkan provider (the library
// NCALayer is built on). Disposable keys and a public test password only; needs NCA_KALKAN_JARS.
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { opensslPassword } from './helpers/fixtures.js';
import { normalizeIssuance } from '../extension/signing/issuance-protocol.js';
import { generateRequest, installCertificates, encodeName } from '../extension/crypto/issuance.js';
import { openContainer } from '../extension/crypto/signer.js';
import { signCms } from '../extension/crypto/cms.js';
import { parse, der, unbase64, forge } from '../extension/crypto/encoding.js';

const jars = process.env.NCA_KALKAN_JARS;
if (!jars) throw new Error('Set NCA_KALKAN_JARS to the provider and XMLDSig jars (separated by the OS classpath delimiter).');
const java = process.env.NCA_JAVA || 'java';
const javac = process.env.NCA_JAVAC || 'javac';
const delimiter = process.platform === 'win32' ? ';' : ':';
const PASSWORD = 'Tegin-Test-2026';
const folder = mkdtempSync(join(tmpdir(), 'tegin-kalkan-issue-'));
const run = (...args) => execFileSync(java, ['-cp', `${jars}${delimiter}${folder}`, ...args], { ...opensslPassword(PASSWORD), encoding: 'utf8' });
const hex = value => Buffer.from(value, 'binary').toString('hex');
const pemBody = pem => unbase64(pem.split('\n').filter(line => line && !line.startsWith('-----')).join(''));
// Shaped like a first-head application of a legal entity (synthetic values).
const dn = { '2.5.4.3': 'ТЕСТОВ ТЕСТ', '2.5.4.4': 'ТЕСТОВ', '2.5.4.5': 'IIN000000000000', '2.5.4.6': 'KZ', '2.5.4.42': 'ТЕСТҰЛЫ', '2.5.4.10': 'ТОО «ҚАЗАҚ СИНТЕТИКА»', '2.5.4.11': 'BIN000000000000', '1.2.840.113549.1.9.1': 'test@example.kz' };
const { '1.2.840.113549.1.9.1': _, ...dnWithoutEmail } = dn;
// The live step-3 page names GOST-512 by its OID; Kalkan compares it with its own GOST512 request.
// With the e-mail outside the DN, Tegin puts it into extensionRequest → subjectAltName → rfc822Name.
const families = [['GOST512', 'ECGOST3410-2015', 512], ['GOST512 (portal OID)', '1.2.398.3.10.1.1.2.3.2', 512, 'GOST512'],
  ['GOST512 (e-mail outside DN)', '1.2.398.3.10.1.1.2.3.2', 512, 'GOST512', dnWithoutEmail, 'test@example.kz'],
  ['GOST256', 'ECGOST3410-2015', 256], ['RSA', 'RSA', 2048]];
const exchanges = [1, 2, 3].map(n => JSON.parse(readFileSync(resolve(`tests/fixtures/ncalayer-generate/exchange-${n}.json`), 'utf8')));
const kalkanView = csr => { const path = join(folder, 'view.csr'); writeFileSync(path, csr); return run('IssuanceInterop', 'attrs', path).trim().split('\n'); };
try {
  execFileSync(javac, ['-cp', jars, '-d', folder, resolve('tests/interop/IssuanceInterop.java'), resolve('tests/interop/Pkcs12Interop.java'), resolve('tests/interop/Verify.java')], { stdio: 'pipe' });
  const dnPath = join(folder, 'dn.tsv');
  writeFileSync(dnPath, Object.entries(dn).map(([id, value]) => `${id}\t${value}`).join('\n') + '\n');
  // Subject encoding: same bytes as Kalkan's X509Name for the portal's OID/value lists.
  const kalkanName = run('IssuanceInterop', 'name', dnPath).match(/KALKAN NAME ([0-9a-f]+)/)[1];
  assert.equal(hex(der(encodeName(Object.entries(dn)))), kalkanName);
  console.log('PASS subject DER equals Kalkan X509Name for the same OID/value list (UTF8String, PrintableString, IA5String)');

  for (const [family, algorithm, length, profile = family, subject = dn, email = ''] of families) {
    const request = normalizeIssuance({ module: 'kz.gov.pki.knca.basics', method: 'generateCsr', class: 'PKIEssentials',
      args: { dn: subject, email, subjectAltNames: '', params: [{ algorithm, length }], locale: 'ru', omittedKeyIds: [''] } });
    writeFileSync(dnPath, request.dn.map(([id, value]) => `${id}\t${value}`).join('\n') + '\n');
    const generated = await generateRequest(request, PASSWORD, family);
    const csr = pemBody(generated.pems[0]);
    const csrPath = join(folder, 'tegin.csr');
    writeFileSync(csrPath, csr);
    assert.match(run('IssuanceInterop', 'csr', csrPath), /KALKAN CSR VALID/);
    if (email) assert.deepEqual(kalkanView(csr).filter(line => /^(ATTRIBUTE|EXTENSION 2\.5\.29\.17|SAN)/.test(line)), ['ATTRIBUTE 1.2.840.113549.1.9.14', 'EXTENSION 2.5.29.17 critical=false', `SAN 1 ${email}`]);
    // Structure next to a request Kalkan generates itself from the same subject.
    const kalkanPath = join(folder, 'kalkan.csr');
    run('IssuanceInterop', 'request', profile, dnPath, kalkanPath);
    const ours = parse(csr), theirs = parse(new Uint8Array(readFileSync(kalkanPath)));
    assert.equal(der(ours.value[0].value[1]), der(theirs.value[0].value[1]), 'subject');
    assert.equal(der(ours.value[0].value[2].value[0]), der(theirs.value[0].value[2].value[0]), 'public key algorithm');
    assert.equal(der(ours.value[1]), der(theirs.value[1]), 'signature algorithm');
    assert.equal(der(ours.value[0].value[0]), der(theirs.value[0].value[0]), 'version');
    console.log(`PASS ${family}: Kalkan verifies the Tegin request; subject, key and signature AlgorithmIdentifier equal a Kalkan-generated request`);

    let certificates, anchors;
    if (family === 'RSA') {
      // RSA certificates come from an RSA CA; OpenSSL plays it here, as in tests/issuance.test.js.
      const sh = (...args) => execFileSync('openssl', args, { cwd: folder, stdio: 'pipe' });
      sh('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-out', 'root.pem', '-days', '2', '-subj', '/CN=Tegin synthetic RSA root/C=KZ', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
      writeFileSync(join(folder, 'leaf.ext'), 'keyUsage=critical,digitalSignature,nonRepudiation\n');
      sh('x509', '-req', '-inform', 'DER', '-in', 'tegin.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-days', '2', '-sha256', '-extfile', 'leaf.ext', '-outform', 'DER', '-out', 'leaf.der');
      sh('x509', '-in', 'root.pem', '-outform', 'DER', '-out', 'root.der');
    } else {
      assert.match(run('IssuanceInterop', 'issue', csrPath, folder), /KALKAN ISSUE OK/);
    }
    certificates = [new Uint8Array(readFileSync(join(folder, 'leaf.der')))];
    anchors = { anchors: [new Uint8Array(readFileSync(join(folder, 'root.der')))] };
    const [file] = await installCertificates(certificates, [{ id: family, identities: generated.identities, sealed: generated.sealed }], PASSWORD, anchors);
    const p12 = join(folder, 'tegin.p12');
    writeFileSync(p12, file.container);
    assert.match(run('Pkcs12Interop', 'open', p12), /KALKAN OPEN OK/);
    assert.match(run('Pkcs12Interop', 'resave', p12, join(folder, 'resaved.p12')), /KALKAN RESAVE OK/);
    const signer = await openContainer(file.container.slice(), PASSWORD);
    try {
      const document = new TextEncoder().encode('Kalkan issuance interop: Сәлем, ұлттық куәландырушы орталық');
      writeFileSync(join(folder, 'document.bin'), document);
      writeFileSync(join(folder, 'changed.bin'), new TextEncoder().encode('changed'));
      writeFileSync(join(folder, 'signature.p7s'), await signCms(signer, document, { encapsulate: false, cades: true }));
      assert.match(run('Verify', 'cms', join(folder, 'signature.p7s'), join(folder, 'document.bin')), /KALKAN CMS VALID/);
      assert.throws(() => run('Verify', 'cms', join(folder, 'signature.p7s'), join(folder, 'changed.bin')));
    } finally { signer.destroy(); }
    // Kalkan reopens its own re-save of the Tegin container: the key survived both ways.
    const resaved = await openContainer(new Uint8Array(readFileSync(join(folder, 'resaved.p12'))), PASSWORD);
    resaved.destroy();
    console.log(`PASS ${family}: ${family === 'RSA' ? 'OpenSSL' : 'Kalkan'} issued from the request; Tegin .p12 opened and re-saved by Kalkan; Tegin CAdES verified by Kalkan, changed document rejected`);
  }

  // Reference: NCALayer 1.4 PKIEssentials.generateCsr on the same synthetic fields (file storage chosen in its dialog).
  for (const [index, { request: call, response }] of exchanges.entries()) {
    assert.deepEqual(Object.keys(response).sort(), ['body', 'status']);
    assert.deepEqual(Object.keys(response.body), ['pems']);
    const official = response.body.pems[0];
    const generated = await generateRequest(normalizeIssuance(call), PASSWORD, `reference-${index}`);
    const ours = generated.pems[0];
    // PEM layout: header, 64-column base64, footer, trailing newline.
    for (const pem of [official, ours]) assert.match(pem, /^-----BEGIN CERTIFICATE REQUEST-----\n([A-Za-z0-9+/]{64}\n)*[A-Za-z0-9+/=]{1,64}\n-----END CERTIFICATE REQUEST-----\n$/);
    const [theirInfo, theirAlgorithm] = parse(pemBody(official)).value, [ourInfo, ourAlgorithm] = parse(pemBody(ours)).value;
    assert.equal(hex(der(ourInfo.value[1])), hex(der(theirInfo.value[1])), 'subject: order and string types');
    assert.equal(der(ourInfo.value[2].value[0]), der(theirInfo.value[2].value[0]), 'public key algorithm');
    assert.equal(der(ourAlgorithm), der(theirAlgorithm), 'signature algorithm');
    const theirView = kalkanView(pemBody(official)), ourView = kalkanView(pemBody(ours));
    assert.equal(ourView[0], theirView[0]);
    assert.deepEqual(ourView.filter(line => line.startsWith('SAN')), theirView.filter(line => line.startsWith('SAN')));
    const theirExtensions = theirView.filter(line => line.startsWith('EXTENSION')), ourExtensions = ourView.filter(line => line.startsWith('EXTENSION'));
    assert.deepEqual(ourExtensions, theirExtensions.filter(line => !line.startsWith('EXTENSION 1.2.398.3.3.5 ')));
    console.log(`PASS NCALayer reference ${index + 1}: Kalkan reads the same subject${call.args.email ? ', SAN rfc822Name' : ''} and algorithms in the Tegin request; PEM layout matches; NCALayer adds only its storage extension 1.2.398.3.3.5`);
  }
} finally { rmSync(folder, { recursive: true, force: true }); }
