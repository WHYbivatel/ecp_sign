import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { forge, A, O, seq, set, oid, octet, context, integer, algorithm, bytes, binary, der } from '../../extension/crypto/encoding.js';
import { nca256 } from '../../extension/crypto/nca-curves.js';
import GostSign from '../../extension/vendor/gost/sign.cjs';
import GostDigest from '../../extension/vendor/gost/digest.cjs';

export const PASSWORD = 'public-test-password';
// OpenSSL pkcs12 -export options for each protection profile under test.
export const OPENSSL_PROFILES = {
  default: [],
  legacy: ['-legacy'],
  'pbes2-key-pbe-certs': ['-keypbe', 'AES-256-CBC', '-certpbe', 'PBE-SHA1-3DES'],
  'pbe-3des-sha1-mac': ['-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES', '-macalg', 'sha1'],
  nomac: ['-nomac']
};
// Passwords travel to OpenSSL through the environment to keep spaces and Unicode exact.
export const opensslPassword = password => ({ stdio: 'pipe', env: { ...process.env, TEGIN_TEST_P12_PASSWORD: password } });

export function rsaFixture({ purpose, password = PASSWORD, profile = 'default', subject = '/CN=Tegin disposable test', keySpec = 'rsa:2048', validity } = {}) {
  if (purpose && !['clientAuth', 'emailProtection'].includes(purpose)) throw new Error('Unsupported fixture purpose');
  if (!OPENSSL_PROFILES[profile]) throw new Error('Unsupported fixture profile');
  if (validity && keySpec.startsWith('ec:')) throw new Error('Custom validity is supported for RSA fixtures only');
  const folder = mkdtempSync(join(tmpdir(), 'ncabrowser-rsa-'));
  try {
    const keyArgs = keySpec.startsWith('ec:') ? ['-newkey', 'ec', '-pkeyopt', `ec_paramgen_curve:${keySpec.slice(3)}`] : ['-newkey', keySpec];
    execFileSync('openssl', ['req', '-x509', ...keyArgs, '-nodes', '-keyout', join(folder, 'key.pem'), '-utf8',
      '-out', join(folder, 'cert.pem'), '-days', '2', '-subj', subject, ...(purpose ? ['-addext', 'extendedKeyUsage=' + purpose] : [])], { stdio: 'ignore' });
    // OpenSSL 3.0 cannot backdate `req -x509`; re-sign the same self-signed certificate with the requested dates.
    if (validity) {
      const certificate = forge.pki.certificateFromPem(readFileSync(join(folder, 'cert.pem'), 'utf8'));
      certificate.validity.notBefore = validity.notBefore; certificate.validity.notAfter = validity.notAfter;
      certificate.sign(forge.pki.privateKeyFromPem(readFileSync(join(folder, 'key.pem'), 'utf8')), forge.md.sha256.create());
      writeFileSync(join(folder, 'cert.pem'), forge.pki.certificateToPem(certificate));
    }
    execFileSync('openssl', ['pkcs12', '-export', ...OPENSSL_PROFILES[profile], '-inkey', join(folder, 'key.pem'), '-in', join(folder, 'cert.pem'),
      '-out', join(folder, 'key.p12'), '-passout', 'env:TEGIN_TEST_P12_PASSWORD'], opensslPassword(password));
    return { container: new Uint8Array(readFileSync(join(folder, 'key.p12'))),
      certificate: readFileSync(join(folder, 'cert.pem'), 'utf8'), publicKey: readFileSync(join(folder, 'key.pem'), 'utf8') };
  } finally { rmSync(folder, { recursive: true, force: true }); }
}

// Assembles a PFX from prepared SafeBags. The MAC key uses the RFC 7292 BMPString
// password, independently of how the bags were encrypted.
export function pkcs12Container(safeBags, password = PASSWORD, options = {}) {
  return pkcs12FromContents([seq(oid(O.data), context(0, [octet(der(seq(...safeBags)))]))], password, options);
}
// EncryptedData ContentInfo (RFC 7292 5.1) holding SafeBags under pbeWithSHAAnd3-KeyTripleDES-CBC.
export function encryptedSafe(safeBags, password = PASSWORD, { iterations = 2048 } = {}) {
  const salt = forge.random.getBytesSync(8);
  const key = forge.pkcs12.generateKey(password, forge.util.createBuffer(salt), 1, iterations, 24).getBytes();
  const iv = forge.pkcs12.generateKey(password, forge.util.createBuffer(salt), 2, iterations, 8).getBytes();
  const cipher = forge.des.startEncrypting(key, iv);
  cipher.update(forge.util.createBuffer(der(seq(...safeBags))));
  cipher.finish();
  const scheme = seq(oid(forge.pki.oids['pbeWithSHAAnd3-KeyTripleDES-CBC']), seq(octet(salt), A.create(0, A.Type.INTEGER, false, integerBytes(iterations))));
  return seq(oid(forge.pki.oids.encryptedData), context(0, [seq(integer(0),
    seq(oid(O.data), scheme, A.create(A.Class.CONTEXT_SPECIFIC, 0, false, cipher.output.getBytes())))]));
}
export function pkcs12FromContents(contentInfos, password = PASSWORD, { macIterations = 2048 } = {}) {
  const authSafe = der(seq(...contentInfos));
  const salt = forge.random.getBytesSync(16);
  const key = forge.pkcs12.generateKey(password, forge.util.createBuffer(salt), 3, macIterations, 20).getBytes();
  const mac = forge.hmac.create(); mac.start('sha1', key); mac.update(authSafe);
  const macData = seq(seq(algorithm(forge.pki.oids.sha1), octet(mac.digest().getBytes())), octet(salt), A.create(0, A.Type.INTEGER, false, integerBytes(macIterations)));
  return bytes(der(seq(integer(3), seq(oid(O.data), context(0, [octet(authSafe)])), macData)));
}
export function integerBytes(value) {
  let hex = value.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  if (parseInt(hex.slice(0, 2), 16) & 128) hex = '00' + hex;
  return forge.util.hexToBytes(hex);
}
export const shroudedKeyBag = encrypted => seq(oid(forge.pki.oids.pkcs8ShroudedKeyBag), context(0, [encrypted]));
export const certificateBag = certificateDer => seq(oid(forge.pki.oids.certBag), context(0, [seq(oid(forge.pki.oids.x509Certificate), context(0, [octet(certificateDer)]))]));

export function gostFixture(family = '512', { eku = [], keyUsage = false, password = PASSWORD, keyEncryption = '3des' } = {}) {
  const scheme = family === '2004' ? { version: 2001, length: 256, namedCurve: 'S-256-A', oid: O.gost2004, curveOid: '1.2.398.3.10.1.1.1.1.1', hash: O.hash2004, sig: O.sig2004 } : family === '256' ? { version: 2012, length: 256, curve: nca256, oid: O.gost256, curveOid: '1.2.398.3.10.1.1.2.1.1', hash: O.hash256, sig: O.sig256 } : { version: 2012, length: 512, namedCurve: 'T-512-A', oid: O.gost512, curveOid: '1.2.398.3.10.1.1.2.2.1', hash: O.hash512, sig: O.sig512 };
  const engine = new GostSign(scheme);
  const pair = engine.generateKey();
  const name = seq(set(seq(oid('2.5.4.3'), A.create(0, A.Type.UTF8, false, 'Tegin GOST disposable test'))));
  const pkcs8 = seq(integer(0), seq(oid(scheme.oid), seq(oid(scheme.curveOid), oid(scheme.hash))), octet(new Uint8Array(pair.privateKey)));
  const spki = seq(pkcs8.value[1], A.create(0, A.Type.BITSTRING, false, '\0' + der(octet(new Uint8Array(pair.publicKey)))));
  const date = value => A.create(0, A.Type.GENERALIZEDTIME, false, A.dateToGeneralizedTime(value));
  const tbs = seq(context(0, [integer(2)]), integer(1), algorithm(scheme.sig), name,
    seq(date(new Date(Date.now() - 86400000)), date(new Date(Date.now() + 86400000))), name, spki, ...(eku.length || keyUsage ? [context(3, [seq(
      ...(eku.length ? [seq(oid('2.5.29.37'), octet(der(seq(...eku.map(oid)))))] : []),
      ...(keyUsage ? [seq(oid('2.5.29.15'), octet(der(A.create(0, A.Type.BITSTRING, false, '\x06\xc0'))))] : [])
    )])] : []));
  const hash = new GostDigest({ version: scheme.version === 2001 ? 1994 : 2012, length: scheme.length, sBox: 'D-TEST' }).digest(bytes(der(tbs)));
  const signature = new Uint8Array(engine.sign(pair.privateKey, hash));
  const cert = seq(tbs, algorithm(scheme.sig), A.create(0, A.Type.BITSTRING, false, '\0' + binary(signature)));
  // PKCS#12 3DES PBE takes the BMPString password; PBES2 takes UTF-8 octets (RFC 8018, OpenSSL, Java).
  const encrypted = keyEncryption === 'pbes2'
    ? forge.pki.encryptPrivateKeyInfo(pkcs8, forge.util.encodeUtf8(password), { algorithm: 'aes256', prfAlgorithm: 'sha256', count: 2048 })
    : forge.pki.encryptPrivateKeyInfo(pkcs8, password, { algorithm: '3des', count: 2048 });
  const container = pkcs12Container([shroudedKeyBag(encrypted), certificateBag(der(cert))], password);
  new Uint8Array(pair.privateKey).fill(0);
  return { container, certificate: forge.util.encode64(der(cert)), publicKey: new Uint8Array(pair.publicKey) };
}
