import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { normalizeIssuance, issuanceOrigin, issuanceResult, issuanceError, isIssuanceRequest, PASSWORD_RULE } from '../extension/signing/issuance-protocol.js';
import { generateRequest, verifyCsr, inspectCertificates, installCertificates, unsealKeys, keyIdentity, encodeName } from '../extension/crypto/issuance.js';
import { openContainer } from '../extension/crypto/signer.js';
import { signCms } from '../extension/crypto/cms.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';
import { verifyChain } from '../extension/crypto/chain.js';
import { unbase64, der, binary, parse, forge } from '../extension/crypto/encoding.js';
import { gostHierarchy, issueFromCsr } from './helpers/gost-ca.js';

const PASSWORD = 'Tegin-Test-2026';
const DN = { '2.5.4.3': 'ТЕСТОВ ТЕСТ', '2.5.4.4': 'ТЕСТОВ', '2.5.4.5': 'IIN000000000000', '2.5.4.6': 'KZ', '2.5.4.42': 'ТЕСТОВИЧ', '2.5.4.10': 'ТОО «Синтетика»', '2.5.4.11': 'BIN000000000000' };
// Exactly what /js/pkiorder-basics.js builds from the page's hidden fields.
const generateCall = (args = {}) => ({ module: 'kz.gov.pki.knca.basics', method: 'generateCsr', class: 'PKIEssentials',
  args: { allowedStorages: ['PKCS12', 'AKKaztokenStore', 'AKKZIDCardStore'], defaultPassword: 'portal-default', dn: DN, email: '', subjectAltNames: '',
    params: [{ algorithm: 'ECGOST3410-2015', length: 512 }], locale: 'ru', omittedKeyIds: [''], ...args } });
// Exactly what /js/status-basics.js builds.
const importCall = pems => ({ module: 'kz.gov.pki.knca.basics', method: 'importCertificate', class: 'PKIEssentials',
  args: { allowedStorage: 'PKCS12', defaultPassword: 'portal-default', keystorePath: '', certificates: pems, locale: 'ru' } });
const pemBody = pem => unbase64(pem.split('\n').filter(line => line && !line.startsWith('-----')).join(''));
const code = error => error?.code;

test('generateCsr and importCertificate are normalized in the shape the NUC portal sends', () => {
  assert.ok(isIssuanceRequest(generateCall()));
  const generate = normalizeIssuance(generateCall());
  // NCALayer order, not page order: givenName (2.5.4.42) after OU (2.5.4.11).
  const ordered = ['2.5.4.3', '2.5.4.4', '2.5.4.5', '2.5.4.6', '2.5.4.10', '2.5.4.11', '2.5.4.42'].map(id => [id, DN[id]]);
  assert.deepEqual(generate, { operation: 'issue-generate', issuance: true, dn: ordered, email: undefined, keys: [{ algorithm: 'ECGOST3410-2015', length: 512 }] });
  assert.equal(JSON.stringify(generate).includes('portal-default'), false);
  // Empty hidden fields arrive as [""]; email in SAN; several keys.
  assert.equal(normalizeIssuance(generateCall({ allowedStorages: [''] })).operation, 'issue-generate');
  assert.equal(normalizeIssuance(generateCall({ email: 'test@example.kz' })).email, 'test@example.kz');
  assert.equal(normalizeIssuance(generateCall({ params: [{ algorithm: 'ECGOST3410-2015', length: 512 }, { algorithm: 'RSA', length: 2048 }] })).keys.length, 2);
  const fails = (call, expected) => assert.throws(() => normalizeIssuance(call), error => error.code === expected);
  fails(generateCall({ allowedStorages: ['AKKaztokenStore'] }), 'STORAGE_NOT_SUPPORTED');
  fails(generateCall({ params: [{ algorithm: 'ECGOST34310', length: 256 }] }), 'GENKEY_UNKNOWN_ALG');
  fails(generateCall({ params: [{ algorithm: 'ECGOST3410-2015', length: null }] }), 'GENKEY_UNKNOWN_ALG');
  // Observed on the live step-3 page: the GOST 34.10-2015 512-bit OID instead of the profile name.
  const GOST512_OID = '1.2.398.3.10.1.1.2.3.2';
  assert.deepEqual(normalizeIssuance(generateCall({ params: [{ algorithm: GOST512_OID, length: 512 }] })).keys, [{ algorithm: 'ECGOST3410-2015', length: 512 }]);
  for (const length of [256, 1024, '512', null]) fails(generateCall({ params: [{ algorithm: GOST512_OID, length }] }), 'GENKEY_UNKNOWN_ALG');
  for (const algorithm of ['1.2.398.3.10.1.1.2.3.1', '1.2.398.3.10.1.1.2.2', '1.2.398.3.10.1.1.2.3.2.1', '1.2.398.3.10.1.1.2.3.20']) fails(generateCall({ params: [{ algorithm, length: 512 }] }), 'GENKEY_UNKNOWN_ALG');
  fails(generateCall({ dn: {} }), 'GENKEY_EMPTY_DN');
  fails(generateCall({ dn: { ...DN, '2.5.4.6': 'Kazakhstan' } }), 'GENKEY_INCORRECT_DN_VALUE');
  fails(generateCall({ dn: { ...DN, '2.5.4.5': 'ИИН000000000000' } }), 'GENKEY_INCORRECT_DN_VALUE');
  fails(generateCall({ dn: { ...DN, '2.5.4.3': '#3003' } }), 'GENKEY_INCORRECT_DN_VALUE');
  fails(generateCall({ subjectAltNames: ['dNSName=example.kz'] }), 'GENKEY_INCORRECT_DN_VALUE');
  fails(generateCall({ email: 'not-an-address' }), 'GENKEY_INCORRECT_DN_VALUE');
  fails(generateCall({ keystore: 'x' }), 'COMMON');
  fails({ ...generateCall(), method: 'signCsr' }, 'COMMON');

  const pem = '-----BEGIN CERTIFICATE-----\nMIIBAA==\n-----END CERTIFICATE-----';
  assert.deepEqual(normalizeIssuance(importCall([pem, pem.replaceAll('\n', '<br>'), pem.replaceAll('\n', '\r\n')])).certificates, ['MIIBAA==', 'MIIBAA==', 'MIIBAA==']);
  fails(importCall([]), 'COMMON');
  fails(importCall(['-----BEGIN CERTIFICATE-----\n<script>\n-----END CERTIFICATE-----']), 'COMMON');
});

test('key issuance is limited to the NUC request portal in the top-level frame', () => {
  for (const url of ['https://did.pki.gov.kz/service/pkiorder/create.xhtml', 'https://nca.pki.gov.kz/ua/cabinet.xhtml'])
    assert.equal(issuanceOrigin({ url, frameId: 0 }), new URL(url).origin);
  for (const sender of [{ url: 'https://nca.pki.gov.kz.example.kz/x', frameId: 0 }, { url: 'http://did.pki.gov.kz/x', frameId: 0 }, { url: 'https://pki.gov.kz/x', frameId: 0 },
    { url: 'https://egov.kz/x', frameId: 0 }, { url: 'http://127.0.0.1:8080/x', frameId: 0 }, { url: 'https://did.pki.gov.kz/x', frameId: 3 }, { url: 'https://user:pw@did.pki.gov.kz/x', frameId: 0 }, { frameId: 0 }])
    assert.throws(() => issuanceOrigin(sender), error => error.code === 'ORIGIN_NOT_ALLOWED');
});

test('the page receives only request PEMs or the installation flag', () => {
  const generate = normalizeIssuance(generateCall());
  const pem = '-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n';
  assert.deepEqual(issuanceResult(generate, { pems: [pem], sealed: { data: 'x' }, identities: ['a'] }), { pems: [pem] });
  assert.throws(() => issuanceResult(generate, { pems: [pem, pem] }));
  assert.throws(() => issuanceResult(generate, { pems: ['-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n'] }));
  const install = normalizeIssuance(importCall(['MIIBAA==']));
  assert.deepEqual(issuanceResult(install, { installed: true, container: new Uint8Array(4) }), { result: true });
  assert.throws(() => issuanceResult(install, {}));
  assert.deepEqual(issuanceError('GENKEY_CANCEL', 'x'), { status: false, code: 'GENKEY_CANCEL', message: 'x' });
  assert.equal(issuanceError('lower <b>', 'x').code, 'COMMON');
});

test('container password policy matches the NUC application', () => {
  for (const value of ['Tegin-Test-2026', 'Aa345678', 'Pass#$^+=!*()@%&_?-.1']) assert.ok(PASSWORD_RULE.test(value), value);
  for (const value of ['short1A', 'alllower123', 'ALLUPPER123', 'NoDigitsHere', 'Пароль123Aa', 'With space1A', 'a'.repeat(62) + 'A1x']) assert.ok(!PASSWORD_RULE.test(value), value);
});

test('subject names use the Kalkan/Bouncy Castle string types in the portal order', () => {
  const name = encodeName([['2.5.4.3', 'ҰЛТТЫҚ'], ['2.5.4.5', 'IIN000000000000'], ['2.5.4.6', 'KZ'], ['1.2.840.113549.1.9.1', 'a@b.kz'], ['2.5.4.11', 'BIN000000000000']]);
  const types = name.value.map(rdn => rdn.value[0].value[1].type);
  assert.deepEqual(types, [12, 19, 19, 22, 12]);
  assert.equal(name.value[0].value[0].value[1].value, Buffer.from('ҰЛТТЫҚ').toString('binary'));
});

const { root, ca } = gostHierarchy();
const other = gostHierarchy('Tegin foreign');
const anchors = { anchors: [root.der] };
function opensslIssue(csrPem) {
  const folder = mkdtempSync(join(tmpdir(), 'tegin-csr-'));
  const run = (...args) => execFileSync('openssl', args, { cwd: folder, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    writeFileSync(join(folder, 'request.csr'), csrPem);
    writeFileSync(join(folder, 'leaf.ext'), 'keyUsage=critical,digitalSignature,nonRepudiation\nextendedKeyUsage=emailProtection\n');
    const text = run('req', '-in', 'request.csr', '-verify', '-noout', '-text');
    run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-out', 'root.pem', '-days', '2', '-subj', '/CN=Tegin synthetic RSA root/C=KZ',
      '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
    run('x509', '-req', '-in', 'request.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-days', '2', '-sha256', '-extfile', 'leaf.ext', '-outform', 'DER', '-out', 'leaf.der');
    run('x509', '-in', 'root.pem', '-outform', 'DER', '-out', 'root.der');
    const read = name => new Uint8Array(readFileSync(join(folder, name)));
    return { text, leaf: read('leaf.der'), root: read('root.der') };
  } finally { rmSync(folder, { recursive: true, force: true }); }
}

// The NCALayer storage extension 1.2.398.3.3.5 = SEQUENCE { 1.2.398.3.3.5.1.1 (file), UTF8String folder }.
function storageNode(attributes) {
  const [request] = attributes.value;
  assert.equal(forge.asn1.derToOid(request.value[0].value), '1.2.840.113549.1.9.14');
  const extensions = request.value[1].value[0].value;
  const storage = extensions.filter(item => forge.asn1.derToOid(item.value[0].value) === '1.2.398.3.3.5');
  assert.equal(storage.length, 1);
  assert.equal(storage[0], extensions.at(-1), 'storage extension comes last');
  assert.equal(storage[0].value.length, 2, 'non-critical: no BOOLEAN');
  const inner = parse(storage[0].value[1].value);
  assert.equal(inner.value.length, 2);
  assert.equal(forge.asn1.derToOid(inner.value[0].value), '1.2.398.3.3.5.1.1');
  assert.equal(inner.value[1].type, forge.asn1.Type.UTF8);
  return { extension: storage[0], inner };
}
const storagePath = attributes => forge.util.decodeUtf8(storageNode(attributes).inner.value[1].value);
function withStoragePath(attributes, path) {
  const copy = parse(der(attributes));
  const { extension, inner } = storageNode(copy);
  inner.value[1].value = forge.util.encodeUtf8(path);
  extension.value[1].value = der(inner);
  return der(copy);
}

test('requests match NCALayer 1.4 generateCsr on the same synthetic fields: subject order and types, SAN, algorithms, PEM', async () => {
  for (const n of [1, 2, 3]) {
    const { request: call, response } = JSON.parse(readFileSync(new URL(`fixtures/ncalayer-generate/exchange-${n}.json`, import.meta.url), 'utf8'));
    const official = pemBody(response.body.pems[0]);
    await verifyCsr(official);
    const generated = await generateRequest(normalizeIssuance(call), PASSWORD, `reference-${n}`);
    assert.deepEqual(Object.keys(response.body), Object.keys({ pems: generated.pems }));
    const ours = pemBody(generated.pems[0]);
    const [theirInfo, theirAlgorithm] = parse(official).value, [ourInfo, ourAlgorithm] = parse(ours).value;
    assert.equal(der(ourInfo.value[1]), der(theirInfo.value[1]), `subject ${n}`);
    assert.equal(der(ourInfo.value[2].value[0]), der(theirInfo.value[2].value[0]));
    assert.equal(der(ourAlgorithm), der(theirAlgorithm));
    // extensionRequest: SAN (when e-mail is outside the DN), then the storage extension; only the folder differs.
    assert.equal(der(ourInfo.value[3]), withStoragePath(theirInfo.value[3], ''), `attributes ${n}`);
    assert.equal(storagePath(ourInfo.value[3]), '');
    assert.match(storagePath(theirInfo.value[3]), /^\/tmp\/ncl\/out2?$/);
    for (const pem of [generated.pems[0], response.body.pems[0]]) assert.match(pem, /^-----BEGIN CERTIFICATE REQUEST-----\n([A-Za-z0-9+/]{64}\n)*[A-Za-z0-9+/=]{1,64}\n-----END CERTIFICATE REQUEST-----\n$/);
  }
});

test('the portal GOST-512 OID pair yields the same GOST 34.10-2015 512-bit request as the profile name', async () => {
  const request = normalizeIssuance(generateCall({ params: [{ algorithm: '1.2.398.3.10.1.1.2.3.2', length: 512 }] }));
  const generated = await generateRequest(request, PASSWORD, 'oid-512');
  const csr = pemBody(generated.pems[0]);
  await verifyCsr(csr);
  const oid = node => forge.asn1.derToOid(node.value);
  const [info, signatureAlgorithm] = parse(csr).value;
  const [keyAlgorithm] = info.value[2].value;
  assert.equal(oid(keyAlgorithm.value[0]), '1.2.398.3.10.1.1.2.2');
  assert.equal(oid(keyAlgorithm.value[1].value[0]), '1.2.398.3.10.1.1.2.2.1');
  assert.equal(oid(signatureAlgorithm.value[0]), '1.2.398.3.10.1.1.2.3.2');
  assert.equal(info.value[2].value[1].value[0].value.length, 128, 'public point is a 128-byte OCTET STRING');
  assert.deepEqual(generated.algorithms, (await generateRequest(normalizeIssuance(generateCall()), PASSWORD, 'name-512')).algorithms);
});

for (const params of [{ algorithm: 'ECGOST3410-2015', length: 512 }, { algorithm: 'ECGOST3410-2015', length: 256 }, { algorithm: 'RSA', length: 2048 }]) {
  test(`${params.algorithm} ${params.length}: request, issuance from it, installation, signing with the saved .p12`, async () => {
    const request = normalizeIssuance(generateCall({ params: [params], email: 'test@example.kz' }));
    const generated = await generateRequest(request, PASSWORD, 'record-1');
    assert.equal(generated.pems.length, 1);
    assert.equal(JSON.stringify(generated).includes(PASSWORD), false);
    const csr = pemBody(generated.pems[0]);
    const verified = await verifyCsr(csr);
    assert.equal(der(verified.subject), der(encodeName(request.dn)));
    // A changed request no longer verifies.
    const tampered = csr.slice(); tampered[tampered.length - 5] ^= 1;
    await assert.rejects(verifyCsr(tampered), error => code(error) === 'GENKEY_EMPTY_PKCS10');

    // GOST keys: the synthetic GOST CA. RSA keys: OpenSSL verifies the request and issues from it as an RSA CA.
    let leaf, certificates, anchors = { anchors: [root.der] };
    if (params.algorithm === 'RSA') {
      const rsa = opensslIssue(generated.pems[0]);
      assert.match(rsa.text, /email:test@example\.kz/);
      leaf = { der: rsa.leaf }; certificates = [rsa.leaf]; anchors = { anchors: [rsa.root] };
    } else {
      leaf = issueFromCsr(ca, csr); certificates = [leaf.der, ca.der];
    }
    const record = { id: 'record-1', identities: generated.identities, sealed: generated.sealed };
    const inspected = await inspectCertificates(certificates, [record], anchors);
    assert.equal(inspected.leaves.length, 1);
    assert.equal(inspected.leaves[0].recordId, 'record-1');
    assert.equal(inspected.leaves[0].trust.trusted, true);

    const [file] = await installCertificates(certificates, [record], PASSWORD, anchors);
    assert.equal(file.recordId, 'record-1');
    // Container profile: PBES2 AES-256-CBC with PBKDF2-HMAC-SHA256 and an HMAC-SHA256 MAC, 100000 iterations.
    const refused = await openContainer(file.container.slice(), PASSWORD + 'x').then(() => null, error => error);
    assert.equal(refused?.code, 'PASSWORD_OR_DAMAGED');
    const profile = refused.diagnostic.container;
    assert.deepEqual(profile.integrity, { algorithm: '2.16.840.1.101.3.4.2.1', iterations: 100000 });
    assert.deepEqual(profile.encryption, [{ scheme: '1.2.840.113549.1.5.13', kdf: '1.2.840.113549.1.5.12', prf: '1.2.840.113549.2.9', cipher: '2.16.840.1.101.3.4.1.42', iterations: 100000 }]);

    const signer = await openContainer(file.container.slice(), PASSWORD);
    try {
      assert.equal(signer.info.raw, binary(leaf.der));
      const document = new TextEncoder().encode('Тестовый документ Tegin: ұлттық куәландырушы орталық');
      // The saved file carries the verified intermediate CA: its chain reaches the root on its own.
      assert.equal(signer.certificates.length, certificates.length);
      assert.equal((await verifyChain(signer.info, signer.certificates, anchors)).trusted, true);
      // CMS carries only the signer certificate, as NCALayer does; the verifier knows the CA.
      const signature = await signCms(signer, document, { encapsulate: false, cades: true });
      const known = { anchors: [...anchors.anchors, ...certificates.slice(1)] };
      const result = await verifyCms(signature, { detached: document, ...known });
      assert.equal(result.signers.length, 1);
      assert.equal(result.signers[0].trust.trusted, true);
      await assert.rejects(verifyCms(signature, { detached: new TextEncoder().encode('changed'), ...known }));
    } finally { signer.destroy(); }
  });
}

test('installation refuses certificates for other keys, untrusted or expired chains, wrong passwords and altered records', async () => {
  const request = normalizeIssuance(generateCall({ params: [{ algorithm: 'ECGOST3410-2015', length: 256 }] }));
  const mine = await generateRequest(request, PASSWORD, 'mine');
  const foreign = await generateRequest(request, PASSWORD, 'foreign');
  const record = { id: 'mine', identities: mine.identities, sealed: mine.sealed };
  const csr = pemBody(mine.pems[0]);
  const reject = async (certificates, expected, pending = [record], password = PASSWORD, options = anchors) =>
    assert.rejects(installCertificates(certificates, pending, password, options), error => code(error) === expected);

  // Certificate for a key this browser did not create, even with our subject.
  const wrongKey = issueFromCsr(ca, csr, { spki: parse(pemBody(foreign.pems[0])).value[0].value[2] });
  const inspected = await inspectCertificates([wrongKey.der, ca.der], [record], anchors);
  assert.equal(inspected.leaves[0].recordId, null);
  await reject([wrongKey.der, ca.der], 'CERTIFICATE_KEY_MISMATCH');

  const good = issueFromCsr(ca, csr);
  await reject([good.der, ca.der], 'CERTIFICATE_UNTRUSTED', [record], PASSWORD, {});
  await reject([good.der, ca.der], 'CERTIFICATE_UNTRUSTED', [record], PASSWORD, { anchors: [other.root.der] });
  await reject([issueFromCsr(other.ca, csr).der, other.ca.der], 'CERTIFICATE_UNTRUSTED');
  await reject([issueFromCsr(ca, csr, { notBefore: Date.now() - 3 * 86400000, notAfter: Date.now() - 86400000 }).der, ca.der], 'CERTIFICATE_UNTRUSTED');
  await reject([issueFromCsr(ca, csr, { keyUsage: '\x02\x04' }).der, ca.der], 'CERTIFICATE_NO_DIGITAL_SIGNATURE');
  await reject([ca.der], 'NO_END_ENTITY_CERTIFICATE');
  await reject([new Uint8Array([48, 3, 2, 1, 0])], 'CERTIFICATE_MALFORMED');
  await reject([good.der, ca.der], 'PASSWORD_OR_DAMAGED', [record], 'Wrong-Pass-2026');
  // Identities and record id are authenticated with the sealed key.
  await reject([good.der, ca.der], 'PASSWORD_OR_DAMAGED', [{ ...record, id: 'other' }]);
  await reject([good.der, ca.der], 'PASSWORD_OR_DAMAGED', [{ ...record, identities: [...record.identities, foreign.identities[0]] }]);
  await reject([good.der, ca.der], 'PENDING_DAMAGED', [{ ...record, sealed: { ...record.sealed, iterations: 1000 } }]);
  // Another record's sealed key under this record's identities.
  await reject([good.der, ca.der], 'PASSWORD_OR_DAMAGED', [{ ...record, sealed: foreign.sealed }]);
  const [file] = await installCertificates([good.der, ca.der], [{ id: 'foreign', identities: foreign.identities, sealed: foreign.sealed }, record], PASSWORD, anchors);
  assert.equal(file.recordId, 'mine');
});

test('sealed application keys round-trip and are bound to their record', async () => {
  const request = normalizeIssuance(generateCall({ params: [{ algorithm: 'ECGOST3410-2015', length: 512 }, { algorithm: 'ECGOST3410-2015', length: 256 }] }));
  const generated = await generateRequest(request, PASSWORD, 'pair');
  assert.equal(generated.pems.length, 2);
  assert.equal(generated.sealed.iterations, 600000);
  assert.equal(generated.sealed.cipher, 'AES-256-GCM');
  const keys = await unsealKeys(generated.sealed, PASSWORD, `pair|${generated.identities.join(',')}`);
  assert.deepEqual(await Promise.all(keys.map(key => keyIdentity(key.spki))), generated.identities);
  await assert.rejects(unsealKeys(generated.sealed, PASSWORD, `pair|${[...generated.identities].reverse().join(',')}`), error => code(error) === 'PASSWORD_OR_DAMAGED');
  await assert.rejects(generateRequest(request, 'weak', 'x'), error => code(error) === 'PASSWORD_POLICY');
});
