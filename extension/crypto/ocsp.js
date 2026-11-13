import { A, seq, oid, octet, context, algorithm, der, bytes, binary } from './encoding.js';
import { read, root, children, content, whole, expect, oid as oidOf, smallInteger, integerBytes, bitStringBytes, time, extensions, equal, TAG, DerError } from './der.js';
import { certificateInfo } from './signer.js';
import { verifySignedBytes } from './verification.js';

export class RevocationError extends Error {
  constructor(code, message) { super(message || code); this.code = code; }
}

const OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1', OCSP_NONCE = '1.3.6.1.5.5.7.48.1.2', OCSP_EXTENDED_REVOKE = '1.3.6.1.5.5.7.48.1.9';
const OCSP_NOCHECK = '1.3.6.1.5.5.7.48.1.5', OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';
const SHA1 = '1.3.14.3.2.26', SHA256 = '2.16.840.1.101.3.4.2.1';
const KNOWN_SINGLE_EXTENSIONS = new Set(['2.5.29.24', '2.5.29.21', '1.3.6.1.5.5.7.48.1.3', '1.3.6.1.5.5.7.48.1.6']);
export const REASONS = ['unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'certificateHold', undefined, 'removeFromCRL', 'privilegeWithdrawn', 'aACompromise'];

export const OCSP_LIMITS = Object.freeze({ skew: 5 * 60 * 1000, maxAge: 5 * 60 * 1000 });

const sha = async (name, data) => new Uint8Array(await crypto.subtle.digest(name, data));
const hex = value => [...value].map(byte => byte.toString(16).padStart(2, '0')).join('');

// Exact DER parts of an X.509 certificate.
export function certificateParts(raw) {
  const buffer = raw instanceof Uint8Array ? raw : bytes(raw);
  const certificate = root(buffer);
  const [tbs, outerAlgorithm, signature] = children(expect(certificate, TAG.SEQUENCE));
  const fields = children(expect(tbs, TAG.SEQUENCE));
  const offset = fields[0].tag === 0xa0 ? 1 : 0;
  const spki = children(expect(fields[offset + 5], TAG.SEQUENCE));
  return {
    serial: integerBytes(fields[offset]), issuer: whole(fields[offset + 2]), subject: whole(fields[offset + 4]),
    keyBits: bitStringBytes(spki[1]), tbs: whole(tbs), innerAlgorithm: whole(fields[offset + 1]), outerAlgorithm: whole(outerAlgorithm),
    signatureOid: oidOf(children(outerAlgorithm)[0]), signature: bitStringBytes(signature)
  };
}

// CertID with SHA-256 (accepted by ocsp.pki.gov.kz for RSA and GOST on 2026-11-09) and a 16-byte nonce.
// SHA-1 CertIDs are built only to match responses already embedded in a signature.
export async function buildOcspRequest(certificate, issuer, { nonce = crypto.getRandomValues(new Uint8Array(16)), hash = 'SHA-256' } = {}) {
  const cert = certificateParts(certificate.raw), ca = certificateParts(issuer.raw);
  if (!equal(cert.issuer, ca.subject)) throw new RevocationError('OCSP_ISSUER', 'Издатель сертификата не совпадает с УЦ.');
  const hashOid = { 'SHA-256': SHA256, 'SHA-1': SHA1 }[hash];
  const certId = { hashOid, nameHash: await sha(hash, ca.subject), keyHash: await sha(hash, ca.keyBits), serial: cert.serial };
  const certIdNode = seq(algorithm(hashOid), octet(certId.nameHash), octet(certId.keyHash), A.create(0, A.Type.INTEGER, false, binary(cert.serial)));
  const nonceExtension = seq(oid(OCSP_NONCE), octet(der(octet(nonce))));
  const tbsRequest = seq(seq(seq(certIdNode)), context(2, [seq(nonceExtension)]));
  return { body: bytes(der(seq(tbsRequest))), certId, nonce: nonce.slice(), key: `${hex(certId.keyHash)}:${hex(cert.serial)}` };
}

function parseCertId(node) {
  const [hashAlgorithm, nameHash, keyHash, serial] = children(expect(node, TAG.SEQUENCE));
  return { hashOid: oidOf(children(expect(hashAlgorithm, TAG.SEQUENCE))[0]), nameHash: content(expect(nameHash, TAG.OCTET_STRING)),
    keyHash: content(expect(keyHash, TAG.OCTET_STRING)), serial: integerBytes(serial) };
}
const sameCertId = (left, right) => left.hashOid === right.hashOid && equal(left.nameHash, right.nameHash) && equal(left.keyHash, right.keyHash) && equal(left.serial, right.serial);

async function signerVerified(info, tbs, signature, signatureOid) {
  try { return await verifySignedBytes(info, tbs, signature, signatureOid); } catch { return false; }
}

// RFC 6960 4.2.2.2 and Rules 500/НҚ p.19: a delegated responder certificate issued by the
// same CA with id-kp-OCSPSigning, or the CA itself only if it carries OCSPSigning.
async function responderFor(responderId, certificates, issuer, now) {
  const ca = certificateParts(issuer.raw);
  const matches = async (info, parts) => responderId.byName ? equal(responderId.byName, parts.subject) : equal(responderId.byKey, await sha('SHA-1', parts.keyBits));
  if (await matches(issuer, ca)) {
    if (!issuer.eku.includes(OCSP_SIGNING)) throw new RevocationError('OCSP_RESPONDER', 'Ответ OCSP подписан УЦ без назначения OCSPSigning.');
    return issuer;
  }
  for (const raw of certificates) {
    const parts = certificateParts(raw);
    let info;
    try { info = certificateInfo(raw); } catch { continue; }
    if (!await matches(info, parts)) continue;
    if (!equal(parts.issuer, ca.subject) || !equal(parts.innerAlgorithm, parts.outerAlgorithm)) throw new RevocationError('OCSP_RESPONDER', 'Сертификат службы OCSP выдан другим УЦ.');
    if (info.authorityKeyId && issuer.subjectKeyId && info.authorityKeyId !== issuer.subjectKeyId) throw new RevocationError('OCSP_RESPONDER', 'Сертификат службы OCSP выдан другим ключом УЦ.');
    if (!await signerVerified(issuer, parts.tbs, parts.signature, parts.signatureOid)) throw new RevocationError('OCSP_RESPONDER', 'Сертификат службы OCSP не подписан УЦ.');
    if (!info.eku.includes(OCSP_SIGNING)) throw new RevocationError('OCSP_RESPONDER', 'У сертификата службы OCSP нет назначения OCSPSigning.');
    if (info.keyUsage !== null && !(info.keyUsage & 0x80)) throw new RevocationError('OCSP_RESPONDER', 'Ключ службы OCSP не предназначен для подписи.');
    if (info.unknownCritical.length) throw new RevocationError('OCSP_RESPONDER', 'В сертификате службы OCSP есть неизвестное критическое расширение.');
    if (now < Date.parse(info.summary.notBefore) || now > Date.parse(info.summary.notAfter)) throw new RevocationError('OCSP_RESPONDER', 'Срок сертификата службы OCSP истёк или не наступил.');
    // The responder's own status is not checked; RFC 6960 4.2.2.2.1 requires id-pkix-ocsp-nocheck for that.
    if (!certificateExtensionIds(parts).has(OCSP_NOCHECK)) throw new RevocationError('OCSP_RESPONDER', 'Сертификат службы OCSP без id-pkix-ocsp-nocheck не поддерживается.');
    return info;
  }
  throw new RevocationError('OCSP_RESPONDER', 'Сертификат службы OCSP не найден в ответе.');
}
function certificateExtensionIds(parts) {
  const tbs = read(parts.tbs, 0);
  const node = children(tbs).find(child => child.tag === 0xa3);
  return new Set(node ? extensions(children(node)[0]).map(entry => entry.id) : []);
}

// Returns { status: 'good' | 'revoked' | 'unknown', ... } only for a fully verified response.
// Any structural, signature, binding, nonce or freshness failure throws RevocationError.
// historical: a response embedded in a signature, judged at its own producedAt. No nonce or freshness
// against the present; the responder certificate must be valid at producedAt and its notAfter is
// returned, so the caller can require proof that the response existed before then.
export async function verifyOcspResponse(raw, request, issuer, { now = Date.now(), skew = OCSP_LIMITS.skew, maxAge = OCSP_LIMITS.maxAge, historical = false } = {}) {
  try {
    const response = root(raw);
    const [statusNode, bytesNode] = children(expect(response, TAG.SEQUENCE));
    if (statusNode.tag !== TAG.ENUMERATED) throw new DerError('status');
    const status = smallInteger(statusNode);
    if (status !== 0) throw new RevocationError('OCSP_STATUS', `Служба OCSP вернула ошибку ${status}.`);
    const [typeNode, octets] = children(expect(children(expect(bytesNode, 0xa0))[0], TAG.SEQUENCE));
    if (oidOf(typeNode) !== OCSP_BASIC) throw new RevocationError('OCSP_MALFORMED', 'Неподдерживаемый тип ответа OCSP.');
    const basic = root(content(expect(octets, TAG.OCTET_STRING)));
    const [tbs, signatureAlgorithm, signatureNode, certsNode, ...rest] = children(expect(basic, TAG.SEQUENCE));
    if (rest.length) throw new DerError('basic');
    const fields = children(expect(tbs, TAG.SEQUENCE));
    let index = 0;
    if (fields[0].tag === 0xa0) { if (smallInteger(children(fields[0])[0]) !== 0) throw new RevocationError('OCSP_MALFORMED', 'Неподдерживаемая версия ответа OCSP.'); index++; }
    const idNode = fields[index++];
    const responderId = idNode.tag === 0xa1 ? { byName: whole(children(idNode)[0]) } : idNode.tag === 0xa2 ? { byKey: content(expect(children(idNode)[0], TAG.OCTET_STRING)) } : null;
    if (!responderId) throw new DerError('responder id');
    const producedAt = time(expect(fields[index++], TAG.GENERALIZED_TIME));
    const responses = children(expect(fields[index++], TAG.SEQUENCE));
    const responseExtensions = fields[index] ? extensions(children(expect(fields[index++], 0xa1))[0]) : [];
    if (fields[index]) throw new DerError('response data');

    const certificates = certsNode ? children(expect(children(expect(certsNode, 0xa0))[0], TAG.SEQUENCE)).map(whole) : [];
    if (certificates.length > 4) throw new RevocationError('OCSP_MALFORMED', 'Слишком много сертификатов в ответе OCSP.');
    const signer = await responderFor(responderId, certificates, issuer, historical ? producedAt : now);
    if (!await signerVerified(signer, whole(tbs), bitStringBytes(signatureNode), oidOf(children(expect(signatureAlgorithm, TAG.SEQUENCE))[0])))
      throw new RevocationError('OCSP_SIGNATURE', 'Подпись ответа OCSP не прошла проверку.');

    for (const extension of responseExtensions) if (extension.critical && ![OCSP_NONCE, OCSP_EXTENDED_REVOKE].includes(extension.id)) throw new RevocationError('OCSP_CRITICAL', 'В ответе OCSP есть неизвестное критическое расширение.');
    if (!historical) {
      const nonce = responseExtensions.find(extension => extension.id === OCSP_NONCE);
      if (!nonce) throw new RevocationError('OCSP_NONCE', 'Ответ OCSP без nonce не принимается.');
      let echoed = nonce.value;
      try { const inner = root(nonce.value); if (inner.tag === TAG.OCTET_STRING) echoed = content(inner); } catch {}
      if (!equal(echoed, request.nonce)) throw new RevocationError('OCSP_NONCE', 'Ответ OCSP относится к другому запросу (nonce).');
    }

    const matching = responses.map(node => children(expect(node, TAG.SEQUENCE))).filter(parts => sameCertId(parseCertId(parts[0]), request.certId));
    if (matching.length !== 1) throw new RevocationError('OCSP_MISMATCH', 'Ответ OCSP не относится к проверяемому сертификату.');
    const [, statusChoice, thisNode, ...optional] = matching[0];
    const thisUpdate = time(expect(thisNode, TAG.GENERALIZED_TIME));
    let nextUpdate = null, singleExtensions = [];
    for (const node of optional) {
      if (node.tag === 0xa0 && nextUpdate === null && !singleExtensions.length) nextUpdate = time(expect(children(node)[0], TAG.GENERALIZED_TIME));
      else if (node.tag === 0xa1) singleExtensions = extensions(children(node)[0]);
      else throw new DerError('single response');
    }
    for (const extension of singleExtensions) if (extension.critical && !KNOWN_SINGLE_EXTENSIONS.has(extension.id)) throw new RevocationError('OCSP_CRITICAL', 'В ответе OCSP есть неизвестное критическое расширение.');

    // Rules 500/НҚ p.19(6): the status describes only the moment it was provided.
    if (historical) {
      if (thisUpdate > producedAt + skew) throw new RevocationError('OCSP_FUTURE', 'Время статуса OCSP позже времени ответа.');
      if (nextUpdate !== null && nextUpdate < thisUpdate) throw new RevocationError('OCSP_MALFORMED', 'Срок актуальности ответа OCSP раньше времени его выпуска.');
    } else {
      if (thisUpdate > now + skew || producedAt > now + skew) throw new RevocationError('OCSP_FUTURE', 'Время ответа OCSP находится в будущем.');
      if (thisUpdate < now - maxAge || producedAt < now - maxAge) throw new RevocationError('OCSP_STALE', 'Ответ OCSP устарел.');
      if (nextUpdate !== null && (nextUpdate < thisUpdate || nextUpdate < now - skew)) throw new RevocationError('OCSP_STALE', 'Срок актуальности ответа OCSP истёк.');
    }

    const result = { source: 'ocsp', thisUpdate: new Date(thisUpdate).toISOString(), nextUpdate: nextUpdate === null ? null : new Date(nextUpdate).toISOString(),
      producedAt: new Date(producedAt).toISOString(), expires: Math.min(nextUpdate ?? Infinity, thisUpdate + maxAge),
      ...(historical ? { signerNotAfter: signer.summary.notAfter } : {}) };
    if (statusChoice.tag === 0x80) {
      if (statusChoice.end !== statusChoice.start) throw new DerError('good');
      return { ...result, status: 'good' };
    }
    if (statusChoice.tag === 0xa1) {
      const [revocationNode, reasonNode] = children(statusChoice);
      const revocationTime = time(expect(revocationNode, TAG.GENERALIZED_TIME));
      const reasonCode = reasonNode ? smallInteger(expect(children(expect(reasonNode, 0xa0))[0], TAG.ENUMERATED)) : null;
      // RFC 6960 2.2: "revoked" + certificateHold at 1970-01-01 with the extended revoke extension means "not issued".
      if (reasonCode === 6 && revocationTime === 0 && responseExtensions.some(extension => extension.id === OCSP_EXTENDED_REVOKE))
        return { ...result, status: 'unknown', detail: 'not-issued' };
      return { ...result, status: 'revoked', revocationTime: new Date(revocationTime).toISOString(), reason: reasonCode === null ? null : REASONS[reasonCode] || 'unspecified' };
    }
    if (statusChoice.tag === 0x82) return { ...result, status: 'unknown' };
    throw new DerError('cert status');
  } catch (error) {
    if (error instanceof RevocationError) throw error;
    throw new RevocationError('OCSP_MALFORMED', 'Повреждённый ответ OCSP.');
  }
}
