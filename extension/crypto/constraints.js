import { O } from './encoding.js';

export const CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
const SHA256_RSA = '1.2.840.113549.1.1.11';
const KEY_TYPE_LABELS = { SIGNATURE: 'для подписи', AUTHENTICATION: 'для аутентификации' };

// Key types by which NCALayer Common Utils filters keys (knca_provider_util 0.8.8, see docs/ncalayer-reference.md).
export function kncaKeyTypes(info) {
  const usage = info.keyUsage ?? 0, types = new Set();
  const digitalSignature = (usage & 0x80) !== 0, nonRepudiation = (usage & 0x40) !== 0, keyEncipherment = (usage & 0x20) !== 0, keyAgreement = (usage & 0x08) !== 0;
  if (digitalSignature && nonRepudiation) {
    types.add('SIGNATURE');
    if (info.signatureOid === O.sig512 || (info.signatureOid === SHA256_RSA && keyAgreement)) types.add('AUTHENTICATION');
  }
  if (digitalSignature && keyEncipherment && info.eku.includes(CLIENT_AUTH)) types.add('AUTHENTICATION');
  return types;
}

// NUC's unified GOST-2015 subscriber certificates serve signing and authentication:
// https://pki.gov.kz/ru/2024/04/26/Технические-работы-34/
// The issuer policy applies only after an independent path to our pinned NUC roots.
// A site's own trust anchor or a familiar issuer name cannot activate it.
export function isUnifiedNcaCertificate(info, trust) {
  if (trust?.ncaTrusted !== true || info.ca || ![O.gost512, O.gost256].includes(info.keyOid)) return false;
  if (!info.eku.includes('1.3.6.1.5.5.7.3.4') || info.keyUsage === null || !(info.keyUsage & 192)) return false;
  const issued = Date.parse(info.summary.notBefore);
  const individual = info.eku.includes('1.2.398.3.3.4.1.1');
  const organization = info.eku.includes('1.2.398.3.3.4.1.2');
  return (individual && issued >= Date.parse('2022-11-26T00:00:00+06:00')) ||
    (organization && issued >= Date.parse('2024-04-28T00:00:00+05:00'));
}

export function checkSignerConstraints(info, request, trust) {
  const constraints = request.signerParams || {};
  for (const field of ['iin', 'bin', 'serialNumber']) {
    const normalize = value => field === 'serialNumber' ? String(value || '').toLowerCase().replace(/^0+/, '') : value;
    if (constraints[field] && normalize(constraints[field]) !== normalize(info.summary[field])) throw new Error('Сертификат не соответствует требованиям сайта.');
  }
  // null: no keyType from the site, which NCALayer treats as signature or authentication keys only.
  if (constraints.kncaType !== undefined) {
    const types = kncaKeyTypes(info), wanted = constraints.kncaType ? [constraints.kncaType] : ['SIGNATURE', 'AUTHENTICATION'];
    if (!wanted.some(type => types.has(type))) throw new Error(`Сайт запросил ключ ${wanted.map(type => KEY_TYPE_LABELS[type]).join(' или ')}. Этот сертификат к такому типу не относится.`);
  }
  const unified = isUnifiedNcaCertificate(info, trust);
  const missing = (constraints.extKeyUsageOids || []).filter(oid => !info.eku.includes(oid) && !(oid === CLIENT_AUTH && unified));
  if (missing.length) {
    if (missing.includes(CLIENT_AUTH)) throw new Error('Для входа нужен сертификат аутентификации или единый ГОСТ-ключ НУЦ РК с подтверждённой цепочкой. Выбранный сертификат не соответствует этим требованиям.');
    throw new Error('Назначение сертификата не соответствует требованиям сайта. Требуемые назначения (OID): ' + missing.join(', '));
  }
  if (request.trustRequired && !trust?.trusted) throw new Error('Сайт требует доверенную цепочку сертификата. ' + (trust?.reason || 'Цепочка не проверена.'));
}
