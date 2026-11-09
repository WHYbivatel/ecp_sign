import { generateKeyPairSync } from 'node:crypto';
import { forge, A, seq, oid, octet, context, integer, algorithm, der, bytes, binary } from '../../extension/crypto/encoding.js';
import { certificateInfo } from '../../extension/crypto/signer.js';
import { certificateParts } from '../../extension/crypto/ocsp.js';
import { root, children, content, whole, oid as oidOf, integerBytes } from '../../extension/crypto/der.js';

// Disposable synthetic PKI for revocation tests: RSA keys from node:crypto, certificates and
// OCSP/CRL structures assembled field by field so every evidence check can be broken on purpose.
const SHA256_RSA = '1.2.840.113549.1.1.11';
const OCSP_SIGNING = '1.3.6.1.5.5.7.3.9', NOCHECK = '1.3.6.1.5.5.7.48.1.5', NONCE = '1.3.6.1.5.5.7.48.1.2', EXTENDED_REVOKE = '1.3.6.1.5.5.7.48.1.9';
const DAY = 86400000;
let serials = 0x1000;

function keyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { privateKey: forge.pki.privateKeyFromPem(privateKey.export({ type: 'pkcs8', format: 'pem' })), publicKey: forge.pki.publicKeyFromPem(publicKey.export({ type: 'spki', format: 'pem' })) };
}
const sign = (key, data) => key.sign(forge.md.sha256.create().update(data));
const time = value => A.create(0, A.Type.GENERALIZEDTIME, false, A.dateToGeneralizedTime(new Date(value)));
const utc = value => A.create(0, A.Type.UTCTIME, false, A.dateToUtcTime(new Date(value)));
const raw = value => A.fromDer(typeof value === 'string' ? value : binary(value));
const enumerated = value => A.create(0, A.Type.ENUMERATED, false, String.fromCharCode(value));
const extension = (id, value, critical = false) => seq(oid(id), ...(critical ? [A.create(0, A.Type.BOOLEAN, false, '\xff')] : []), octet(value));
function bigInteger(value) {
  let hex = BigInt(value).toString(16);
  if (hex.length % 2) hex = '0' + hex;
  if (parseInt(hex.slice(0, 2), 16) & 0x80) hex = '00' + hex;
  return A.create(0, A.Type.INTEGER, false, forge.util.hexToBytes(hex));
}

export function issue({ name, issuer, ca = false, eku, keyUsage, nocheck = false, notBefore = Date.now() - DAY, notAfter = Date.now() + 30 * DAY, unknownCritical = false, serial }) {
  const keys = keyPair();
  const certificate = forge.pki.createCertificate();
  certificate.serialNumber = (serial ?? ++serials).toString(16).padStart(4, '0');
  certificate.publicKey = keys.publicKey;
  certificate.validity.notBefore = new Date(notBefore); certificate.validity.notAfter = new Date(notAfter);
  certificate.setSubject([{ name: 'commonName', value: name }, { name: 'countryName', value: 'KZ' }]);
  certificate.setIssuer(issuer ? issuer.certificate.subject.attributes : certificate.subject.attributes);
  const extensions = [{ name: 'subjectKeyIdentifier' }];
  if (issuer) extensions.push({ name: 'authorityKeyIdentifier', keyIdentifier: issuer.certificate.generateSubjectKeyIdentifier().getBytes() });
  if (ca) extensions.push({ name: 'basicConstraints', cA: true, critical: true }, { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true });
  else if (keyUsage !== false) extensions.push({ name: 'keyUsage', digitalSignature: true, critical: true, ...keyUsage });
  if (eku) extensions.push({ name: 'extKeyUsage', ...Object.fromEntries(eku.map(id => [id, true])) });
  if (nocheck) extensions.push({ id: NOCHECK, value: der(A.create(0, A.Type.NULL, false, '')) });
  if (unknownCritical) extensions.push({ id: '1.2.3.4.5.6.7', critical: true, value: der(A.create(0, A.Type.NULL, false, '')) });
  certificate.setExtensions(extensions);
  certificate.sign(issuer ? issuer.privateKey : keys.privateKey, forge.md.sha256.create());
  const derBytes = bytes(forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes());
  return { name, certificate, privateKey: keys.privateKey, der: derBytes, pem: forge.pki.certificateToPem(certificate), info: certificateInfo(derBytes) };
}

export function syntheticPki() {
  const rootCa = issue({ name: 'Tegin synthetic root', ca: true });
  const ca = issue({ name: 'Tegin synthetic CA', issuer: rootCa, ca: true });
  const leaf = issue({ name: 'Tegin synthetic leaf', issuer: ca, eku: ['clientAuth'] });
  const responder = issue({ name: 'Tegin synthetic OCSP', issuer: ca, eku: [OCSP_SIGNING], nocheck: true });
  return { root: rootCa, ca, leaf, responder };
}

// OCSPRequest fields needed to answer it (RFC 6960 4.1.1).
export function parseOcspRequest(body) {
  const tbs = children(children(root(body))[0]);
  const certIdNode = children(children(tbs[0])[0])[0];
  const certId = children(certIdNode);
  const extensions = tbs.find(node => node.tag === 0xa2);
  let nonce = null;
  if (extensions) for (const item of children(children(extensions)[0])) {
    const [id, value] = children(item);
    if (oidOf(id) === NONCE) nonce = content(root(content(value)));
  }
  return { certId: { hashOid: oidOf(children(certId[0])[0]), nameHash: content(certId[1]), keyHash: content(certId[2]), serial: integerBytes(certId[3]) }, certIdDer: whole(certIdNode), nonce };
}

// BasicOCSPResponse; options break individual fields.
export function ocspResponse(request, { signer, status = 'good', revocationTime, reason, thisUpdate = Date.now(), nextUpdate, producedAt = thisUpdate, nonce = request.nonce,
  certIdDer = request.certIdDer, byKey = false, certificates = [signer], responseStatus = 0, tamper = false, criticalExtension = false, extendedRevoke = false, nonceRaw = false } = {}) {
  if (responseStatus) return bytes(der(seq(enumerated(responseStatus))));
  const certStatus = status === 'good' ? A.create(A.Class.CONTEXT_SPECIFIC, 0, false, '') : status === 'unknown' ? A.create(A.Class.CONTEXT_SPECIFIC, 2, false, '')
    : A.create(A.Class.CONTEXT_SPECIFIC, 1, true, [time(revocationTime), ...(reason === undefined ? [] : [context(0, [enumerated(reason)])])]);
  const single = seq(raw(certIdDer), certStatus, time(thisUpdate), ...(nextUpdate ? [context(0, [time(nextUpdate)])] : []));
  const responderId = byKey ? context(2, [octet(forge.md.sha1.create().update(binary(certificateParts(signer.der).keyBits)).digest().getBytes())]) : context(1, [raw(certificateParts(signer.der).subject)]);
  const extensions = [...(nonce ? [extension(NONCE, nonceRaw ? binary(nonce) : der(octet(nonce)))] : []), ...(extendedRevoke ? [extension(EXTENDED_REVOKE, der(A.create(0, A.Type.NULL, false, '')))] : []),
    ...(criticalExtension ? [extension('1.2.3.4.5.6.8', der(A.create(0, A.Type.NULL, false, '')), true)] : [])];
  const tbs = seq(responderId, time(producedAt), seq(single), ...(extensions.length ? [context(1, [seq(...extensions)])] : []));
  let signature = sign(signer.privateKey, der(tbs));
  if (tamper) signature = signature.slice(0, -1) + String.fromCharCode(signature.charCodeAt(signature.length - 1) ^ 1);
  const basic = seq(tbs, algorithm(SHA256_RSA), A.create(0, A.Type.BITSTRING, false, '\0' + signature), ...(certificates.length ? [context(0, [seq(...certificates.map(item => raw(item.der)))])] : []));
  return bytes(der(seq(enumerated(0), context(0, [seq(oid('1.3.6.1.5.5.7.48.1.1'), octet(der(basic)))]))));
}

// CertificateList v2; entries: [{ serial (hex), time, reason }].
export function crl(issuer, { signer = issuer, entries = [], thisUpdate = Date.now() - 3600000, nextUpdate = Date.now() + DAY, number = 1, deltaBase, scoped = false, criticalExtension = false,
  indirectEntry = false, criticalEntryExtension = false, tamper = false, version = 1 } = {}) {
  const extensions = [extension('2.5.29.35', der(seq(A.create(A.Class.CONTEXT_SPECIFIC, 0, false, issuer.certificate.generateSubjectKeyIdentifier().getBytes())))),
    ...(number === null ? [] : [extension('2.5.29.20', der(bigInteger(number)))]), ...(deltaBase === undefined ? [] : [extension('2.5.29.27', der(bigInteger(deltaBase)), true)]),
    ...(scoped ? [extension('2.5.29.28', der(seq(context(1, [A.create(A.Class.CONTEXT_SPECIFIC, 1, false, '\xff')]))), true)] : []),
    ...(criticalExtension ? [extension('1.2.3.4.5.6.9', der(A.create(0, A.Type.NULL, false, '')), true)] : [])];
  const revoked = entries.map(entry => seq(bigInteger(BigInt('0x' + entry.serial)), utc(entry.time ?? Date.now() - DAY),
    ...(entry.reason !== undefined || indirectEntry || criticalEntryExtension ? [seq(...(entry.reason !== undefined ? [extension('2.5.29.21', der(enumerated(entry.reason)))] : []),
      ...(indirectEntry ? [extension('2.5.29.29', der(seq(context(4, [raw(certificateParts(issuer.der).subject)]))), true)] : []),
      ...(criticalEntryExtension ? [extension('1.2.3.4.5.6.10', der(A.create(0, A.Type.NULL, false, '')), true)] : []))] : [])));
  const tbs = seq(...(version === null ? [] : [integer(version)]), algorithm(SHA256_RSA), raw(certificateParts(issuer.der).subject), utc(thisUpdate), ...(nextUpdate === null ? [] : [utc(nextUpdate)]),
    ...(revoked.length ? [seq(...revoked)] : []), context(0, [seq(...extensions)]));
  let signature = sign(signer.privateKey, der(tbs));
  if (tamper) signature = signature.slice(0, -1) + String.fromCharCode(signature.charCodeAt(signature.length - 1) ^ 1);
  return bytes(der(seq(tbs, algorithm(SHA256_RSA), A.create(0, A.Type.BITSTRING, false, '\0' + signature))));
}

export const serialHex = item => item.certificate.serialNumber;
export { OCSP_SIGNING };
export const fingerprintOf = async item => Buffer.from(await crypto.subtle.digest('SHA-256', item.der)).toString('hex');
