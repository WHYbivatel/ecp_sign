import { A, O, bytes, binary, der, oidValue, parse, set } from './encoding.js';
import { certificateInfo } from './signer.js';
import { digestForOid, equalBytes, verifySignedBytes } from './verification.js';
import { verifyChain } from './chain.js';

const CONTENT_TYPE = '1.2.840.113549.1.9.3', MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
// eContent OCTET STRING; BER may split it into nested parts, each of them universal too.
function octets(node, depth = 0) {
  if (depth > 24 || node?.tagClass !== A.Class.UNIVERSAL || node.type !== A.Type.OCTETSTRING) throw new Error('Некорректные данные CMS.');
  return typeof node.value === 'string' ? node.value : node.value.map(child => octets(child, depth + 1)).join('');
}
const universal = (node, type) => node?.tagClass === A.Class.UNIVERSAL && node.type === type;
const explicit = (node, tag) => node?.tagClass === A.Class.CONTEXT_SPECIFIC && node.type === tag && node.constructed && node.value.length === 1;
// RFC 5652 5.1 shape. Fields outside the signature must not vary either, so a structure
// other verifiers reject is not reported as a valid signature here.
function checkShape(root) {
  if (!universal(root, A.Type.SEQUENCE) || root.value.length !== 2 || !universal(root.value[0], A.Type.OID)) throw new Error('Ожидается CMS SignedData.');
  if (oidValue(root.value[0]) !== O.signedData || !explicit(root.value[1], 0) || !universal(root.value[1].value[0], A.Type.SEQUENCE)) throw new Error('Ожидается CMS SignedData.');
  const fields = root.value[1].value[0].value;
  const [version, digestAlgorithms, encapsulated] = fields;
  const optional = fields.slice(3, -1);
  if (!universal(version, A.Type.INTEGER) || !universal(digestAlgorithms, A.Type.SET) || digestAlgorithms.value.some(node => !universal(node, A.Type.SEQUENCE) || !universal(node.value[0], A.Type.OID)) ||
    !universal(encapsulated, A.Type.SEQUENCE) || !universal(encapsulated.value[0], A.Type.OID) || encapsulated.value.length > 2 || (encapsulated.value[1] && !explicit(encapsulated.value[1], 0)) ||
    optional.length > 2 || optional.some((node, index) => node.tagClass !== A.Class.CONTEXT_SPECIFIC || !node.constructed || node.type > 1 || (index && node.type <= optional[index - 1].type))) throw new Error('Некорректная структура CMS.');
  // CertificateChoices and RevocationInfoChoice: X.509 SEQUENCE or one of their context tags.
  for (const node of optional) if (node.value.some(item => !universal(item, A.Type.SEQUENCE) && !(item.tagClass === A.Class.CONTEXT_SPECIFIC && item.constructed && (node.type === 0 ? item.type >= 1 && item.type <= 3 : item.type === 1)))) throw new Error('Некорректная структура CMS.');
  const infos = fields.at(-1);
  if (!universal(infos, A.Type.SET) || !infos.constructed || !infos.value.length || infos.value.length > 10) throw new Error('Неверный список подписантов CMS.');
  infos.value.forEach(checkSignerInfo);
}
const algorithmIdentifier = node => universal(node, A.Type.SEQUENCE) && node.value.length >= 1 && node.value.length <= 2 && universal(node.value[0], A.Type.OID);
const attributeSet = (node, tag) => node?.tagClass === A.Class.CONTEXT_SPECIFIC && node.type === tag && node.constructed && node.value.length > 0 &&
  node.value.every(item => universal(item, A.Type.SEQUENCE) && item.value.length === 2 && universal(item.value[0], A.Type.OID) && universal(item.value[1], A.Type.SET));
// RFC 5652 5.3: version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature, [1] unsignedAttrs.
function checkSignerInfo(info) {
  const fail = () => { throw new Error('Некорректная структура подписанта CMS.'); };
  if (!universal(info, A.Type.SEQUENCE)) fail();
  const [version, sid, digestAlgorithm, ...rest] = info.value;
  const byKey = sid?.tagClass === A.Class.CONTEXT_SPECIFIC && sid.type === 0 && !sid.constructed;
  const byIssuer = universal(sid, A.Type.SEQUENCE) && sid.value.length === 2 && universal(sid.value[0], A.Type.SEQUENCE) && universal(sid.value[1], A.Type.INTEGER);
  if (!universal(version, A.Type.INTEGER) || version.value !== (byKey ? '\x03' : '\x01') || !(byKey || byIssuer) || !algorithmIdentifier(digestAlgorithm)) fail();
  let index = 0;
  if (rest[index]?.tagClass === A.Class.CONTEXT_SPECIFIC && rest[index].type === 0 && !attributeSet(rest[index++], 0)) fail();
  if (!algorithmIdentifier(rest[index++])) fail();
  const signature = rest[index++];
  if (!universal(signature, A.Type.OCTETSTRING) || signature.constructed) fail();
  if (rest[index] && !attributeSet(rest[index++], 1)) fail();
  if (index !== rest.length) fail();
}
export function readCms(raw, detached, { allowMissingDocument = false } = {}) {
  if (raw.length > 8 * 1024 * 1024) throw new Error('Подпись превышает 8 МБ.');
  const root = parse(raw);
  checkShape(root);
  const signedData = root.value[1].value[0];
  const encapsulated = signedData.value[2];
  const contentType = oidValue(encapsulated.value[0]);
  const attached = encapsulated.value[1] ? bytes(octets(encapsulated.value[1].value[0])) : null;
  if (attached && detached && !equalBytes(attached, detached)) throw new Error('Документ не совпадает с вложенными данными CMS.');
  const content = attached || detached;
  if (!content && !allowMissingDocument) throw new Error('Для отдельной подписи нужен исходный документ.');
  const certificateSet = signedData.value.find((node, index) => index > 2 && node.tagClass === A.Class.CONTEXT_SPECIFIC && node.type === 0);
  const certificates = (certificateSet?.value || []).filter(node => node.tagClass === 0 && node.type === A.Type.SEQUENCE).map(certificateInfo);
  const infos = signedData.value.at(-1);
  return { root, signedData, infos: infos.value, certificates, content, contentType, attached: Boolean(attached) };
}

// Envelope metadata only. This does not establish signature validity or trust.
export function describeCms(raw) {
  const cms = readCms(raw, undefined, { allowMissingDocument: true });
  return { attached: cms.attached, contentLength: cms.content?.length ?? null, signerCount: cms.infos.length };
}

async function checkCertificateBinding(attributes, certificate, required) {
  let checked = false;
  for (const id of ['1.2.840.113549.1.9.16.2.12', '1.2.840.113549.1.9.16.2.47']) {
    const attribute = attributes.find(node => oidValue(node.value[0]) === id);
    if (!attribute) continue;
    const first = attribute.value[1].value[0].value[0].value[0];
    let hashOid = id.endsWith('.12') ? '1.3.14.3.2.26' : O.sha256;
    let index = 0;
    if (first.value[0].type === A.Type.SEQUENCE) { hashOid = oidValue(first.value[0].value[0]); index++; }
    if (first.value[index].type !== A.Type.OCTETSTRING || !equalBytes(bytes(first.value[index].value), await digestForOid(hashOid, bytes(certificate.raw)))) throw new Error('Подпись содержит неверный отпечаток сертификата.');
    checked = true;
  }
  if (required && !checked) throw new Error('Метка времени не связывает подпись с сертификатом TSA.');
  return checked;
}

export async function verifyCms(raw, { detached, requireBinding = false, anchors, now } = {}) {
  const cms = readCms(raw, detached);
  const signers = [];
  for (const info of cms.infos) {
    const fields = info.value;
    const sid = fields[1];
    const matches = cms.certificates.filter(cert => sid.tagClass === A.Class.CONTEXT_SPECIFIC
      ? cert.subjectKeyId === sid.value
      : der(cert.issuer) === der(sid.value[0]) && cert.serial.value === sid.value[1].value);
    if (matches.length !== 1) throw new Error('Не удалось однозначно определить сертификат подписанта.');
    const certificate = matches[0];
    const hashOid = oidValue(fields[2].value[0]);
    let index = 3, data = cms.content, attributes = [], cades = false;
    if (fields[index]?.tagClass === A.Class.CONTEXT_SPECIFIC && fields[index].type === 0) {
      attributes = fields[index++].value;
      const ids = attributes.map(node => oidValue(node.value[0]));
      if (new Set(ids).size !== ids.length) throw new Error('В подписи повторяются подписанные атрибуты.');
      const contentType = attributes.find(node => oidValue(node.value[0]) === CONTENT_TYPE);
      const digest = attributes.find(node => oidValue(node.value[0]) === MESSAGE_DIGEST);
      if (contentType?.value[1].value.length !== 1 || oidValue(contentType.value[1].value[0]) !== cms.contentType || digest?.value[1].value.length !== 1 || digest.value[1].value[0].type !== A.Type.OCTETSTRING) throw new Error('Некорректные подписанные атрибуты CMS.');
      if (!equalBytes(bytes(digest.value[1].value[0].value), await digestForOid(hashOid, cms.content))) throw new Error('Документ изменён после подписания.');
      data = bytes(der(set(...attributes)));
      cades = await checkCertificateBinding(attributes, certificate, requireBinding);
    } else if (requireBinding) throw new Error('В подписи отсутствуют обязательные атрибуты TSA.');
    const signatureOid = oidValue(fields[index++].value[0]);
    if (fields[index]?.type !== A.Type.OCTETSTRING) throw new Error('Неверное значение подписи CMS.');
    const signature = bytes(fields[index].value);
    if (!await verifySignedBytes(certificate, data, signature, signatureOid, hashOid)) throw new Error('Криптографическая подпись не прошла проверку.');
    const trust = await verifyChain(certificate, cms.certificates, { anchors, now });
    signers.push({ certificate, trust, signature, cades, info });
  }
  return { ...cms, signers, valid: true };
}
