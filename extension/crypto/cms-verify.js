import { A, O, bytes, binary, der, oidValue, parse, set } from './encoding.js';
import { certificateInfo } from './signer.js';
import { digestForOid, equalBytes, verifySignedBytes } from './verification.js';
import { verifyChain } from './chain.js';

const CONTENT_TYPE = '1.2.840.113549.1.9.3', MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
function octets(node, depth = 0) {
  if (depth > 24 || node?.type !== A.Type.OCTETSTRING) throw new Error('Некорректные данные CMS.');
  return typeof node.value === 'string' ? node.value : node.value.map(child => octets(child, depth + 1)).join('');
}
export function readCms(raw, detached) {
  if (raw.length > 8 * 1024 * 1024) throw new Error('Подпись превышает 8 МБ.');
  const root = parse(raw);
  if (oidValue(root.value[0]) !== O.signedData) throw new Error('Ожидается CMS SignedData.');
  const signedData = root.value[1].value[0];
  const encapsulated = signedData.value[2];
  const contentType = oidValue(encapsulated.value[0]);
  const attached = encapsulated.value[1] ? bytes(octets(encapsulated.value[1].value[0])) : null;
  if (attached && detached && !equalBytes(attached, detached)) throw new Error('Документ не совпадает с вложенными данными CMS.');
  const content = attached || detached;
  if (!content) throw new Error('Для отдельной подписи нужен исходный документ.');
  const certificateSet = signedData.value.find((node, index) => index > 2 && node.tagClass === A.Class.CONTEXT_SPECIFIC && node.type === 0);
  const certificates = (certificateSet?.value || []).filter(node => node.tagClass === 0 && node.type === A.Type.SEQUENCE).map(certificateInfo);
  const infos = signedData.value.at(-1);
  if (infos.type !== A.Type.SET || !infos.value.length || infos.value.length > 10) throw new Error('Неверный список подписантов CMS.');
  return { root, signedData, infos: infos.value, certificates, content, contentType, attached: Boolean(attached) };
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
