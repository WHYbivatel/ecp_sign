import { read, root, children, iterate, content, whole, expect, oid as oidOf, integerBytes, smallInteger, bitStringBytes, time, extensions, equal, TAG } from './der.js';
import { RevocationError, REASONS, certificateParts } from './ocsp.js';
import { verifySignedBytes } from './verification.js';

const AKI = '2.5.29.35', CRL_NUMBER = '2.5.29.20', DELTA_INDICATOR = '2.5.29.27', ISSUING_DP = '2.5.29.28', FRESHEST = '2.5.29.46', AIA = '1.3.6.1.5.5.7.1.1';
const REASON_CODE = '2.5.29.21', INVALIDITY_DATE = '2.5.29.24', CERTIFICATE_ISSUER = '2.5.29.29';
export const CRL_SKEW = 5 * 60 * 1000;

const strip = value => { let index = 0; while (index < value.length - 1 && value[index] === 0) index++; return value.subarray(index); };
export function compareNumbers(left, right) {
  const a = strip(left), b = strip(right);
  if (a.length !== b.length) return a.length - b.length;
  for (let index = 0; index < a.length; index++) if (a[index] !== b[index]) return a[index] - b[index];
  return 0;
}

// Structure and extensions of a CertificateList; entries stay as a node for a single later pass.
export function parseCrl(raw) {
  try {
    const list = root(raw);
    const [tbs, outerAlgorithm, signatureNode, ...rest] = children(expect(list, TAG.SEQUENCE));
    if (rest.length) throw new Error();
    const fields = children(expect(tbs, TAG.SEQUENCE));
    let index = 0, version = 0;
    if (fields[0].tag === TAG.INTEGER) version = smallInteger(fields[index++]);
    if (version !== 1) throw new RevocationError('CRL_UNSUPPORTED', 'Поддерживаются только CRL версии 2.');
    const innerAlgorithm = fields[index++];
    if (!equal(whole(innerAlgorithm), whole(outerAlgorithm))) throw new RevocationError('CRL_MALFORMED', 'Алгоритмы подписи CRL не совпадают.');
    const issuer = whole(expect(fields[index++], TAG.SEQUENCE));
    const thisUpdate = time(fields[index++]);
    let nextUpdate = null, entries = null, crlExtensions = [];
    if (fields[index] && (fields[index].tag === TAG.UTC_TIME || fields[index].tag === TAG.GENERALIZED_TIME)) nextUpdate = time(fields[index++]);
    if (fields[index]?.tag === TAG.SEQUENCE) entries = fields[index++];
    if (fields[index]?.tag === 0xa0) crlExtensions = extensions(children(fields[index++])[0]);
    if (fields[index]) throw new Error();
    const crl = { tbs: whole(tbs), signatureOid: oidOf(children(expect(outerAlgorithm, TAG.SEQUENCE))[0]), signature: bitStringBytes(signatureNode),
      issuer, thisUpdate, nextUpdate, entries, number: null, deltaBase: null, authorityKeyId: null, scoped: false, unknownCritical: [] };
    for (const extension of crlExtensions) {
      if (extension.id === CRL_NUMBER) crl.number = integerBytes(root(extension.value));
      else if (extension.id === DELTA_INDICATOR) crl.deltaBase = integerBytes(root(extension.value));
      else if (extension.id === AKI) crl.authorityKeyId = children(expect(root(extension.value), TAG.SEQUENCE)).find(node => node.tag === 0x80);
      else if (extension.id === ISSUING_DP) crl.scoped = true;
      else if (extension.critical && ![FRESHEST, AIA].includes(extension.id)) crl.unknownCritical.push(extension.id);
    }
    if (crl.authorityKeyId) crl.authorityKeyId = content(crl.authorityKeyId);
    return crl;
  } catch (error) {
    if (error instanceof RevocationError) throw error;
    throw new RevocationError('CRL_MALFORMED', 'Повреждённый список отозванных сертификатов.');
  }
}

// Signature, issuer, scope and freshness (RFC 5280 6.3.3, Rules 500/НҚ p.18).
export async function verifyCrl(crl, issuer, { now = Date.now(), kind = 'full', skew = CRL_SKEW } = {}) {
  const ca = certificateParts(issuer.raw);
  if (!equal(crl.issuer, ca.subject)) throw new RevocationError('CRL_ISSUER', 'CRL выпущен другим УЦ.');
  if (crl.authorityKeyId && issuer.subjectKeyId && !equal(crl.authorityKeyId, Uint8Array.from(issuer.subjectKeyId, char => char.charCodeAt(0)))) throw new RevocationError('CRL_ISSUER', 'CRL подписан другим ключом УЦ.');
  if (issuer.keyUsage !== null && !(issuer.keyUsage & 0x02)) throw new RevocationError('CRL_ISSUER', 'Ключ УЦ не предназначен для подписи CRL.');
  if (crl.scoped) throw new RevocationError('CRL_UNSUPPORTED', 'CRL с ограниченной областью действия (IDP, indirect) не поддерживается.');
  if (crl.unknownCritical.length) throw new RevocationError('CRL_UNSUPPORTED', 'В CRL есть неизвестное критическое расширение.');
  if (!crl.number) throw new RevocationError('CRL_UNSUPPORTED', 'CRL без номера не поддерживается.');
  if (kind === 'full' && crl.deltaBase) throw new RevocationError('CRL_UNSUPPORTED', 'Вместо полного CRL получен delta CRL.');
  if (kind === 'delta' && !crl.deltaBase) throw new RevocationError('CRL_UNSUPPORTED', 'Вместо delta CRL получен полный CRL.');
  let valid = false;
  try { valid = await verifySignedBytes(issuer, crl.tbs, crl.signature, crl.signatureOid); } catch {}
  if (!valid) throw new RevocationError('CRL_SIGNATURE', 'Подпись CRL не прошла проверку.');
  if (crl.thisUpdate > now + skew) throw new RevocationError('CRL_FUTURE', 'Время выпуска CRL находится в будущем.');
  if (crl.nextUpdate === null) throw new RevocationError('CRL_UNSUPPORTED', 'CRL без срока следующего обновления не поддерживается.');
  if (crl.nextUpdate < now) throw new RevocationError('CRL_STALE', 'Срок действия CRL истёк.');
  return crl;
}

// One pass over all entries: rejects indirect entries and unknown critical entry extensions anywhere
// in the list (RFC 5280 5.3), and returns the entry for the serial, if any.
export function findEntry(crl, serial) {
  if (!crl.entries) return null;
  let found = null;
  try {
    for (const entry of iterate(crl.entries)) {
      const fields = children(expect(entry, TAG.SEQUENCE));
      const serialNode = expect(fields[0], TAG.INTEGER);
      let extensionList = [];
      if (fields[2]) extensionList = extensions(fields[2]);
      else if (fields.length < 2) throw new Error();
      for (const extension of extensionList) {
        if (extension.id === CERTIFICATE_ISSUER) throw new RevocationError('CRL_UNSUPPORTED', 'Indirect CRL не поддерживается.');
        if (extension.critical && ![REASON_CODE, INVALIDITY_DATE].includes(extension.id)) throw new RevocationError('CRL_UNSUPPORTED', 'В записи CRL есть неизвестное критическое расширение.');
      }
      if (serialNode.end - serialNode.start !== serial.length || !equal(content(serialNode), serial)) continue;
      if (found) throw new RevocationError('CRL_MALFORMED', 'Сертификат повторяется в CRL.');
      const reasonExtension = extensionList.find(extension => extension.id === REASON_CODE);
      const reasonCode = reasonExtension ? smallInteger(expect(root(reasonExtension.value), TAG.ENUMERATED)) : null;
      found = { revocationTime: time(fields[1]), reasonCode, reason: reasonCode === null ? null : REASONS[reasonCode] || 'unspecified' };
    }
  } catch (error) {
    if (error instanceof RevocationError) throw error;
    throw new RevocationError('CRL_MALFORMED', 'Повреждённый список отозванных сертификатов.');
  }
  return found;
}

// How a delta CRL relates to a complete CRL of the same scope (scoped CRLs are rejected earlier):
// 'compatible', 'older' (the complete CRL already supersedes it), 'newer' (needs a later complete
// CRL) or 'conflict'.
// - 'rfc5280': RFC 5280 5.2.4 (a)-(d); complete and delta CRLs share one number sequence (5.2.3).
// - 'nca': NCA numbers complete and delta CRLs in separate sequences (complete 1468, delta 63642
//   with BaseCRLNumber 1468 on 2026-11-09), so condition (d) cannot order them. Its CPS v3 2.3
//   publishes each delta as the revocations since the latest complete CRL: BaseCRLNumber must equal
//   the complete CRL's number, and issue times order the lists. Anything else is a conflict.
export function deltaRelation(full, delta, numbering = 'rfc5280') {
  if (!equal(delta.issuer, full.issuer) || !equal(delta.authorityKeyId || new Uint8Array(), full.authorityKeyId || new Uint8Array())) return 'conflict';
  const base = compareNumbers(full.number, delta.deltaBase);
  if (numbering === 'nca') {
    if (base === 0) return delta.thisUpdate >= full.thisUpdate ? 'compatible' : 'conflict';
    if (base > 0) return delta.thisUpdate <= full.thisUpdate ? 'older' : 'conflict';
    return delta.thisUpdate >= full.thisUpdate ? 'newer' : 'conflict';
  }
  if (base < 0) return 'newer';
  return compareNumbers(full.number, delta.number) < 0 ? 'compatible' : 'older';
}

const later = (a, b, numbering) => numbering === 'nca' ? (a.thisUpdate - b.thisUpdate || compareNumbers(a.number, b.number)) : compareNumbers(a.number, b.number);

// Newest complete CRL among copies (mirrors, cache) and the newest delta that refines it. A delta
// that needs a later complete CRL or contradicts it wins over compatible ones: it proves that the
// chosen pair is not the latest data, so statusFromCrls refuses a permissive answer.
export function selectCrls(fulls, deltas, numbering = 'rfc5280') {
  const full = fulls.reduce((best, item) => compareNumbers(item.number, best.number) > 0 ? item : best);
  let compatible = null, blocking = null;
  for (const delta of deltas) {
    const relation = deltaRelation(full, delta, numbering);
    if (relation === 'newer' || relation === 'conflict') blocking ||= delta;
    else if (relation === 'compatible' && (!compatible || later(delta, compatible, numbering) > 0)) compatible = delta;
  }
  return { full, delta: blocking || compatible, settled: !blocking };
}

// Complete CRL plus an optional delta CRL that refines it (Rules 500/НҚ p.4(3)).
export function statusFromCrls(full, delta, serial, numbering = 'rfc5280') {
  const relation = delta ? deltaRelation(full, delta, numbering) : null;
  const base = findEntry(full, serial);
  if (base?.reasonCode === 8) throw new RevocationError('CRL_MALFORMED', 'Полный CRL содержит запись removeFromCRL.');
  const merged = relation === 'compatible' ? delta : null;
  let entry = base;
  if (relation === 'newer' || relation === 'conflict') {
    // Later lists can only lift certificateHold (RFC 5280 5.3.1); any other listed revocation stands.
    if (!base || base.reasonCode === 6) throw new RevocationError('CRL_DELTA_MISMATCH', relation === 'newer' ? 'Delta CRL требует более нового полного CRL.' : 'Полный CRL и delta CRL несовместимы.');
  } else if (merged) {
    const update = findEntry(merged, serial);
    if (update) entry = update.reasonCode === 8 ? (base?.reasonCode === 6 ? null : base) : update;
  }
  const nextUpdate = Math.min(full.nextUpdate, merged?.nextUpdate ?? Infinity);
  const result = { source: merged ? 'crl+delta' : 'crl', thisUpdate: new Date(Math.max(full.thisUpdate, merged?.thisUpdate ?? 0)).toISOString(),
    nextUpdate: new Date(nextUpdate).toISOString() };
  if (!entry) return { ...result, status: 'good' };
  return { ...result, status: 'revoked', revocationTime: new Date(entry.revocationTime).toISOString(), reason: entry.reason };
}
