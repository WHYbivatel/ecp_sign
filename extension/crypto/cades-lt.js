import { O, oid, der, bytes, parse } from './encoding.js';
import { root, children, whole, content, oid as oidOf, equal, TAG, DerError } from './der.js';
import { signCms } from './cms.js';
import { digestForOid } from './verification.js';
import { verifyEmbeddedTimestamp } from './timestamp.js';

// CAdES baseline B-LT and B-LTA (ETSI EN 319 122-1 V1.1.1, 5.5.3 and 6.3; RFC 5940 for OCSP in
// SignedData.crls). Built from raw TLVs: the SignerInfo, certificates, CRLs and OCSP responses keep
// their received bytes, only the containers around them are re-encoded.
export const LT_OIDS = Object.freeze({
  signatureTimestamp: '1.2.840.113549.1.9.16.2.14',
  archiveTimestampV3: '0.4.0.1733.2.4',
  atsHashIndexV3: '0.4.0.19122.1.5',
  ocspResponse: '1.3.6.1.5.5.7.16.2'
});
export const LONG_TERM_MESSAGE = 'CAdES-LT и CAdES-LTA пока доступны только для ключей RSA с цепочкой НУЦ: для ГОСТ нет независимого валидатора с казахстанскими OID.';
const MAX_ARCHIVE_TIMESTAMPS = 16;

const fail = message => { throw Object.assign(new Error(message), { code: 'CADES_LT' }); };
const malformed = () => fail('Некорректная структура CMS для долгосрочной подписи.');
// DER errors from nested structures surface as one message, other errors pass through.
const guarded = fn => async (...args) => { try { return await fn(...args); } catch (error) { if (error instanceof DerError) malformed(); throw error; } };

function header(tag, length) {
  if (length < 0x80) return [tag, length];
  const octets = [];
  for (let rest = length; rest; rest = Math.floor(rest / 256)) octets.unshift(rest & 255);
  return [tag, 0x80 | octets.length, ...octets];
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
const tlv = (tag, ...parts) => { const body = concat(...parts); return concat(Uint8Array.from(header(tag, body.length)), body); };
const oidTlv = value => bytes(der(oid(value)));
const attribute = (type, ...values) => tlv(TAG.SEQUENCE, oidTlv(type), tlv(TAG.SET, ...values));
const octets = value => tlv(TAG.OCTET_STRING, value);

function signedDataOf(cms) {
  let info;
  try { info = root(cms); } catch { malformed(); }
  const [type, wrapper, ...extra] = info.tag === TAG.SEQUENCE ? children(info) : [];
  if (!type || extra.length || type.tag !== TAG.OID || oidOf(type) !== O.signedData || wrapper?.tag !== 0xa0) malformed();
  const [signedData, ...more] = children(wrapper);
  if (more.length || signedData.tag !== TAG.SEQUENCE) malformed();
  const fields = children(signedData);
  const [version, digestAlgorithms, encapsulated] = fields;
  const middle = fields.slice(3, -1), signerInfos = fields.at(-1);
  if (fields.length < 4 || version.tag !== TAG.INTEGER || digestAlgorithms.tag !== TAG.SET || encapsulated.tag !== TAG.SEQUENCE || signerInfos.tag !== TAG.SET ||
    middle.some((node, index) => ![0xa0, 0xa1].includes(node.tag) || (index && node.tag <= middle[index - 1].tag))) malformed();
  const certificates = middle.find(node => node.tag === 0xa0), crls = middle.find(node => node.tag === 0xa1);
  return { version, digestAlgorithms, encapsulated, certificates: certificates ? children(certificates) : [], crls: crls ? children(crls) : [], signerInfos: children(signerInfos) };
}
function rebuild({ version, digestAlgorithms, encapsulated, certificates, crls, signerInfos }) {
  const signedData = tlv(TAG.SEQUENCE, version, digestAlgorithms, encapsulated,
    ...(certificates.length ? [tlv(0xa0, ...certificates)] : []), ...(crls.length ? [tlv(0xa1, ...crls)] : []), tlv(TAG.SET, ...signerInfos));
  return tlv(TAG.SEQUENCE, oidTlv(O.signedData), tlv(0xa0, signedData));
}
const raw = sd => ({ version: whole(sd.version), digestAlgorithms: whole(sd.digestAlgorithms), encapsulated: whole(sd.encapsulated),
  certificates: sd.certificates.map(whole), crls: sd.crls.map(whole), signerInfos: sd.signerInfos.map(whole) });

// SignerInfo without and with its [1] unsignedAttrs.
function signerParts(node) {
  const fields = children(node);
  const hasUnsigned = fields.at(-1).tag === 0xa1;
  const unsigned = hasUnsigned ? children(fields.at(-1)) : [];
  const attributes = unsigned.map(item => {
    const [type, values, ...extra] = item.tag === TAG.SEQUENCE ? children(item) : [];
    if (!type || type.tag !== TAG.OID || values?.tag !== TAG.SET || extra.length) malformed();
    return { node: item, type: oidOf(type), typeTlv: whole(type), values: children(values) };
  });
  return { signed: (hasUnsigned ? fields.slice(0, -1) : fields).map(whole), attributes };
}
const withUnsigned = (node, attributes) => tlv(TAG.SEQUENCE, ...signerParts(node).signed, ...(attributes.length ? [tlv(0xa1, ...attributes)] : []));
const onlySigner = sd => { if (sd.signerInfos.length !== 1) fail('Долгосрочная подпись поддерживается только для CMS с одним подписантом.'); return sd.signerInfos[0]; };

function signedContent(sd, detached) {
  const [, wrapper] = children(sd.encapsulated);
  if (!wrapper) { if (!detached) fail('Для архивной метки отдельной подписи нужен исходный документ.'); return detached; }
  const [value] = children(wrapper);
  if (value?.tag !== TAG.OCTET_STRING) malformed();
  const attached = content(value);
  if (detached && !equal(attached, detached)) fail('Документ не совпадает с вложенными данными CMS.');
  return attached;
}

// B-LT: certificates, CRLs and OCSP responses (RFC 5940 id-ri-ocsp-response) go into the root
// SignedData (EN 319 122-1 5.5.3, no ATSv2 present). Items already present are not repeated.
function addValidationDataRaw(cms, { certificates = [], crls = [], ocsp = [] } = {}) {
  const sd = signedDataOf(cms);
  const parts = raw(sd);
  const add = (list, item) => { if (!list.some(existing => equal(existing, item))) list.push(item); };
  const sequence = item => { try { if (root(item).tag !== TAG.SEQUENCE) malformed(); } catch { malformed(); } return item; };
  for (const item of certificates) add(parts.certificates, sequence(item));
  for (const item of crls) add(parts.crls, sequence(item));
  for (const item of ocsp) add(parts.crls, tlv(0xa1, oidTlv(LT_OIDS.ocspResponse), sequence(item)));
  // RFC 5652 5.1: an "other" RevocationInfoChoice requires SignedData version 5.
  if (parts.crls.some(item => item[0] === 0xa1)) parts.version = tlv(TAG.INTEGER, Uint8Array.of(Math.max(5, content(sd.version).at(-1))));
  return rebuild(parts);
}

// ATSHashIndexV3 (EN 319 122-1 5.5.2): hashes of every SignedData certificate, every
// RevocationInfoChoice and of attrType || attrValue for every unsigned attribute value.
async function hashIndex(sd, signer, hashOid) {
  const hash = data => digestForOid(hashOid, data);
  const list = async items => tlv(TAG.SEQUENCE, ...(await Promise.all(items.map(hash))).map(octets));
  const values = signerParts(signer).attributes.flatMap(item => item.values.map(value => concat(item.typeTlv, whole(value))));
  // hashIndAlgorithm is DEFAULT sha256, but validators (DSS) always rebuild the index with it
  // present before hashing, so it is written explicitly.
  return tlv(TAG.SEQUENCE, tlv(TAG.SEQUENCE, oidTlv(hashOid)),
    await list(sd.certificates.map(whole)), await list(sd.crls.map(whole)), await list(values));
}
// Message imprint input (EN 319 122-1 5.5.3): eContentType, hash of the signed content, the
// SignerInfo fields before unsignedAttrs, then the ATSHashIndexV3.
async function archiveInput(sd, signer, signed, hashOid, index) {
  return concat(whole(children(sd.encapsulated)[0]), await digestForOid(hashOid, signed), ...signerParts(signer).signed, index);
}

function addTokenAttribute(token, extra) {
  const sd = signedDataOf(token);
  const signer = onlySigner(sd);
  const parts = raw(sd);
  parts.signerInfos = [withUnsigned(signer, [...signerParts(signer).attributes.map(item => whole(item.node)), extra])];
  return rebuild(parts);
}

// B-LTA: archive-time-stamp-v3 over the current signature; requester(data) returns a verified token.
async function addArchiveTimestampRaw(cms, { detached, requester, hashOid = O.sha256 }) {
  const sd = signedDataOf(cms);
  const signer = onlySigner(sd);
  const { attributes } = signerParts(signer);
  if (!attributes.some(item => item.type === LT_OIDS.signatureTimestamp)) fail('Архивная метка добавляется только к подписи с меткой времени (CAdES-T).');
  if (attributes.filter(item => item.type === LT_OIDS.archiveTimestampV3).length >= MAX_ARCHIVE_TIMESTAMPS) fail('Слишком много архивных меток времени.');
  const index = await hashIndex(sd, signer, hashOid);
  const stamp = await requester(await archiveInput(sd, signer, signedContent(sd, detached), hashOid, index));
  const token = addTokenAttribute(bytes(der(stamp.token)), attribute(LT_OIDS.atsHashIndexV3, index));
  const parts = raw(sd);
  parts.signerInfos = [withUnsigned(signer, [...attributes.map(item => whole(item.node)), attribute(LT_OIDS.archiveTimestampV3, token)])];
  return { cms: rebuild(parts), stamp };
}

// TSTInfo.messageImprint.hashAlgorithm of a time-stamp token (RFC 3161 2.4.2).
function imprintAlgorithm(token) {
  const [, wrapper] = children(signedDataOf(token).encapsulated);
  const [value] = wrapper ? children(wrapper) : [];
  if (value?.tag !== TAG.OCTET_STRING) malformed();
  const imprint = children(root(content(value)))[2];
  if (imprint?.tag !== TAG.SEQUENCE) malformed();
  return oidOf(children(children(imprint)[0])[0]);
}

function hashesOf(node) {
  if (node?.tag !== TAG.SEQUENCE) malformed();
  return children(node).map(item => { if (item.tag !== TAG.OCTET_STRING) malformed(); return content(item); });
}
// Every hash listed by an archive time-stamp must still match an item of the signature; items added
// later (newer validation data, newer time-stamps) are allowed.
// Returns the positions in `present` of the items the stamp lists.
function covers(listed, present, label) {
  const used = new Set();
  return listed.map(hash => {
    const index = present.findIndex((item, position) => !used.has(position) && equal(item, hash));
    if (index < 0) fail(`Архивная метка времени не соответствует подписи: изменены или удалены ${label}.`);
    used.add(index);
    return index;
  });
}

// Re-reads a long-term signature: every archive-time-stamp-v3 is verified against its ATSHashIndexV3
// and the current content, certificates, revocation data and unsigned attributes.
async function verifyLongTermRaw(cms, { detached, anchors } = {}) {
  const sd = signedDataOf(cms);
  const signer = onlySigner(sd);
  const { attributes } = signerParts(signer);
  const signed = signedContent(sd, detached);
  const archives = [];
  for (const [position, item] of attributes.entries()) {
    if (item.type !== LT_OIDS.archiveTimestampV3) continue;
    if (item.values.length !== 1 || archives.length >= MAX_ARCHIVE_TIMESTAMPS) fail('Неоднозначная архивная метка времени.');
    const token = whole(item.values[0]);
    const tokenSigner = onlySigner(signedDataOf(token));
    const indexes = signerParts(tokenSigner).attributes.filter(entry => entry.type === LT_OIDS.atsHashIndexV3);
    if (indexes.length !== 1 || indexes[0].values.length !== 1) fail('В архивной метке времени нет однозначного ats-hash-index-v3.');
    const index = indexes[0].values[0];
    const fields = children(index);
    const custom = fields.length === 4;
    if (fields.length !== 3 && !custom) malformed();
    const hashOid = custom ? oidOf(children(fields[0])[0]) : O.sha256;
    const [certificates, crls, values] = fields.slice(custom ? 1 : 0).map(hashesOf);
    const hash = data => digestForOid(hashOid, data);
    covers(certificates, await Promise.all(sd.certificates.map(node => hash(whole(node)))), 'сертификаты');
    const revocationItems = covers(crls, await Promise.all(sd.crls.map(node => hash(whole(node)))), 'данные об отзыве');
    const earlier = attributes.filter((entry, index) => index !== position).flatMap(entry => entry.values.map(value => concat(entry.typeTlv, whole(value))));
    covers(values, await Promise.all(earlier.map(hash)), 'неподписанные атрибуты');
    // The time-stamp's own imprint algorithm hashes the content, as EN 319 122-1 and EU DSS do.
    const verified = await verifyEmbeddedTimestamp(parse(token), await archiveInput(sd, signer, signed, imprintAlgorithm(token), whole(index)), { anchors });
    archives.push({ time: verified.time, authority: verified.authority, certificates: verified.certificates, hashAlgorithm: hashOid,
      covers: { certificates: certificates.length, revocation: crls.length, attributes: values.length }, revocationItems });
  }
  return { ...countEvidence(sd), archives };
}
function countEvidence(sd) {
  const ocsp = sd.crls.filter(node => node.tag === 0xa1).length;
  return { certificates: sd.certificates.length, crls: sd.crls.length - ocsp, ocsp };
}
// Raw OCSP responses and CRLs of SignedData.crls with their positions (as in archive revocationItems).
export function embeddedRevocation(cms) {
  try {
    return signedDataOf(cms).crls.map((node, index) => {
      if (node.tag === TAG.SEQUENCE) return { kind: 'crl', raw: whole(node), index };
      const [format, value] = children(node);
      return format?.tag === TAG.OID && oidOf(format) === LT_OIDS.ocspResponse && value ? { kind: 'ocsp', raw: whole(value), index } : { kind: 'other', index };
    });
  } catch (error) { if (error instanceof DerError) malformed(); throw error; }
}
// Validation data embedded in SignedData, counted without verifying anything.
export function embeddedValidationData(cms) {
  try { return countEvidence(signedDataOf(cms)); } catch (error) { if (error instanceof DerError) malformed(); throw error; }
}

// What a long-term verification established, for the verify screen. historical: the status at the
// signature time-stamp derived from embedded evidence (historical.js), or why it was not computed.
export function longTermReport(verified, { signatureTimestamp, archiveRevocations = [], historical = { computed: false }, renewal = false }) {
  const level = verified.archives.length ? 'LTA' : signatureTimestamp && verified.crls + verified.ocsp > 0 ? 'LT' : null;
  return {
    level,
    embedded: { certificates: verified.certificates, crls: verified.crls, ocsp: verified.ocsp },
    archives: verified.archives.map((archive, index) => ({ index: index + 1, time: archive.time, authority: archive.authority,
      hashAlgorithm: archive.hashAlgorithm, covers: { ...archive.covers }, revocation: archiveRevocations[index] })),
    historical,
    renewal
  };
}

export function addValidationData(...args) {
  try { return addValidationDataRaw(...args); } catch (error) { if (error instanceof DerError) malformed(); throw error; }
}
export const addArchiveTimestamp = guarded(addArchiveTimestampRaw);
export const verifyLongTerm = guarded(verifyLongTermRaw);

export function checkLongTermKey(signer) {
  if (signer.info.keyOid !== O.rsa) fail(LONG_TERM_MESSAGE);
}

// CAdES-T, then validation data obtained after the signature time-stamp for the signer path and the
// TSA path, then (B-LTA) an archive time-stamp. evidence(path, role) returns a "good" revocation
// summary with its raw evidence or throws; requester(data) returns a verified time-stamp token.
export async function signLongTerm(signer, data, { level, encapsulate = true, signerPath, evidence, requester }) {
  checkLongTermKey(signer);
  if (!['lt', 'lta'].includes(level)) fail('Неизвестный уровень долгосрочной подписи.');
  const stamps = [];
  let cms = await signCms(signer, data, { encapsulate, cades: true, timestamp: true, timestampRequester: requester, signingTime: new Date(), onTimestamp: stamp => stamps.push(stamp) });
  const [stamp] = stamps;
  const signerStatus = await evidence(signerPath, 'signer');
  const stampStatus = await evidence(stamp.certificates, 'timestamp');
  cms = addValidationData(cms, {
    certificates: [...signerPath, ...stamp.certificates].map(item => bytes(item.raw)),
    crls: [...signerStatus.evidence.crls, ...stampStatus.evidence.crls],
    ocsp: [...signerStatus.evidence.ocsp, ...stampStatus.evidence.ocsp]
  });
  let archive = null;
  if (level === 'lta') ({ cms, stamp: archive } = await addArchiveTimestamp(cms, { detached: encapsulate ? undefined : data, requester }));
  return { cms, stamp, archive, signerStatus, stampStatus };
}
