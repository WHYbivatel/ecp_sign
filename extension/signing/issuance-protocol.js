// NCALayer PKIEssentials calls of the NUC request portal: key generation for an online
// application (generateCsr) and installation of the issued certificates (importCertificate).
// Shapes follow the portal scripts /js/pkiorder-basics.js and /js/status-basics.js.
export const BASICS = 'kz.gov.pki.knca.basics';
export const PKI_CLASS = 'PKIEssentials';
// Both hosts serve the same request application and byte-identical scripts; the personal
// cabinet (/ua/) on nca.pki.gov.kz loads the same two scripts.
export const ISSUANCE_ORIGINS = Object.freeze(['https://did.pki.gov.kz', 'https://nca.pki.gov.kz']);
export const ALGORITHMS = Object.freeze({ 'ECGOST3410-2015': [256, 512], RSA: [2048, 3072, 4096] });
// The live step-3 page sends the GOST 34.10-2015 512-bit signature OID instead of a profile name.
// Only the exact OID/length pair maps; the profile itself (key OID, curve T-512-A, hash) is unchanged.
export const ALGORITHM_OIDS = Object.freeze({ '1.2.398.3.10.1.1.2.3.2': Object.freeze({ algorithm: 'ECGOST3410-2015', length: 512 }) });
// The NUC application and its help pages ask for this password policy; ASCII only, so every
// PKCS#12 reader derives the same key bytes from it.
export const PASSWORD_RULE = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)[A-Za-z\d#$^+=!*()@%&_?.-]{8,64}$/;
export const PASSWORD_HINT = 'От 8 до 64 символов: заглавная и строчная латинская буква и цифра. Можно использовать #$^+=!*()@%&_?-.';
const OID = /^[0-2](\.(0|[1-9]\d{0,8})){1,20}$/;
const PRINTABLE_OIDS = new Set(['2.5.4.6', '2.5.4.5', '2.5.4.46', '2.5.4.20']);
const IA5_OIDS = new Set(['1.2.840.113549.1.9.1', '0.9.2342.19200300.100.1.25']);
const EMAIL = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

export class IssuanceRequestError extends Error {
  constructor(code, message) { super(message); this.name = 'IssuanceRequestError'; this.code = code; }
}
const fail = (code, message) => { throw new IssuanceRequestError(code, message); };
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const strings = (value, max, length) => Array.isArray(value) && value.length <= max && value.every(item => typeof item === 'string' && item.length <= length);

export const isIssuanceRequest = input => object(input) && input.module === BASICS && input.class === PKI_CLASS;

// Only the request portal itself, as the top-level document, may generate or install keys.
export function issuanceOrigin(sender) {
  let url;
  try { url = new URL(sender?.url); } catch { fail('ORIGIN_NOT_ALLOWED', 'Выпуск ключей доступен только на сайте НУЦ РК.'); }
  if (!ISSUANCE_ORIGINS.includes(url.origin) || url.username || url.password) fail('ORIGIN_NOT_ALLOWED', 'Выпуск ключей доступен только на сайте НУЦ РК.');
  if (sender.frameId !== 0) fail('ORIGIN_NOT_ALLOWED', 'Выпуск ключей доступен только на основной странице НУЦ РК.');
  return url.origin;
}

function storages(value) {
  if (value === undefined) return;
  if (!strings(value, 16, 64)) fail('COMMON', 'Некорректный список хранилищ.');
  // An empty hidden field reaches NCALayer as [""]: no restriction.
  const listed = value.filter(Boolean);
  if (listed.length && !listed.includes('PKCS12')) fail('STORAGE_NOT_SUPPORTED', 'Для этого шаблона НУЦ разрешает только защищённый носитель. Tegin создаёт ключ в файле PKCS#12, поэтому здесь нужен NCALayer и носитель.');
}
function distinguishedName(dn) {
  if (!object(dn)) fail('GENKEY_EMPTY_DN', 'Нет данных владельца ключа.');
  const entries = Object.entries(dn);
  if (!entries.length || entries.length > 24) fail('GENKEY_EMPTY_DN', 'Нет данных владельца ключа.');
  for (const [id, value] of entries) {
    if (!OID.test(id)) fail('GENKEY_INCORRECT_DN_VALUE', 'Некорректный идентификатор поля заявки.');
    if (typeof value !== 'string' || !value.trim()) fail('GENKEY_EMPTY_DN', 'Пустое поле в данных владельца ключа.');
    if (value.length > 512 || /[\u0000-\u001f\u007f\u2028\u2029]/.test(value) || value.startsWith('#')) fail('GENKEY_INCORRECT_DN_VALUE', 'Недопустимое значение поля заявки.');
    if (PRINTABLE_OIDS.has(id) && !/^[A-Za-z0-9 '()+,\-./:=?]+$/.test(value)) fail('GENKEY_INCORRECT_DN_VALUE', 'Недопустимые символы в поле заявки.');
    if (id === '2.5.4.6' && !/^[A-Z]{2}$/.test(value)) fail('GENKEY_INCORRECT_DN_VALUE', 'Некорректный код страны.');
    if (IA5_OIDS.has(id) && !/^[\x20-\x7e]+$/.test(value)) fail('GENKEY_INCORRECT_DN_VALUE', 'Недопустимые символы в поле заявки.');
  }
  return entries;
}
function keyParams(params) {
  if (!Array.isArray(params) || !params.length || params.length > 4) fail('GENKEY_UNKNOWN_ALG', 'Не указаны параметры ключа.');
  return params.map(item => {
    if (!object(item) || Object.keys(item).some(key => !['algorithm', 'length'].includes(key))) fail('GENKEY_UNKNOWN_ALG', 'Некорректные параметры ключа.');
    const profile = typeof item.algorithm === 'string' && Object.hasOwn(ALGORITHM_OIDS, item.algorithm) ? ALGORITHM_OIDS[item.algorithm] : null;
    if (profile && profile.length === item.length) return { algorithm: profile.algorithm, length: profile.length };
    const lengths = typeof item.algorithm === 'string' && Object.hasOwn(ALGORITHMS, item.algorithm) ? ALGORITHMS[item.algorithm] : null;
    if (!lengths || !lengths.includes(item.length)) {
      const name = typeof item.algorithm === 'string' && /^[\w.-]{1,40}$/.test(item.algorithm) ? item.algorithm : 'неизвестный';
      fail('GENKEY_UNKNOWN_ALG', `Алгоритм ключа ${name} длиной ${Number.isInteger(item.length) ? item.length : '?'} бит не поддерживается.`);
    }
    return { algorithm: item.algorithm, length: item.length };
  });
}
function locale(value) {
  if (value !== undefined && !['ru', 'kk', 'en'].includes(value)) fail('COMMON', 'Неизвестный язык.');
}
function fields(args, allowed) {
  if (!object(args)) fail('COMMON', 'Некорректные параметры запроса.');
  if (Object.keys(args).some(key => !allowed.includes(key))) fail('COMMON', 'Этот параметр запроса НУЦ не поддерживается. Ключ не создан.');
}
function certificate(input) {
  if (typeof input !== 'string' || input.length > 16384) fail('COMMON', 'Некорректный сертификат.');
  // The status page reads each PEM from an element's innerHTML.
  const value = input.replace(/<br\s*\/?>/gi, '\n');
  const body = value.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
  const framed = /-----BEGIN CERTIFICATE-----/.test(value);
  if ((framed && !/^\s*-----BEGIN CERTIFICATE-----[\sA-Za-z0-9+/=]+-----END CERTIFICATE-----\s*$/.test(value)) || !body || body.length % 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(body)) fail('COMMON', 'Некорректный сертификат.');
  return body;
}

export function normalizeIssuance(input) {
  if (!isIssuanceRequest(input)) fail('COMMON', 'Некорректный запрос.');
  if (Object.keys(input).some(key => !['module', 'method', 'class', 'args'].includes(key))) fail('COMMON', 'Некорректный запрос.');
  const { args } = input;
  if (input.method === 'generateCsr') {
    fields(args, ['allowedStorages', 'defaultPassword', 'dn', 'email', 'subjectAltNames', 'params', 'locale', 'omittedKeyIds']);
    storages(args.allowedStorages);
    // The portal's temporary container password is not a secret: Tegin protects the key with
    // a password chosen in the extension, so this value is checked and dropped.
    if (args.defaultPassword !== undefined && (typeof args.defaultPassword !== 'string' || args.defaultPassword.length > 256)) fail('COMMON', 'Некорректный пароль хранилища.');
    // Without an e-mail field the page still sends its empty text.
    if (args.email !== undefined && (typeof args.email !== 'string' || args.email.length > 254 || (args.email !== '' && !EMAIL.test(args.email)))) fail('GENKEY_INCORRECT_DN_VALUE', 'Некорректный адрес электронной почты.');
    // The portal sends "" when the template has no alternative names.
    if (args.subjectAltNames !== undefined && args.subjectAltNames !== '' && !(Array.isArray(args.subjectAltNames) && !args.subjectAltNames.length)) fail('GENKEY_INCORRECT_DN_VALUE', 'Дополнительные имена субъекта пока не поддерживаются. Ключ не создан.');
    if (args.omittedKeyIds !== undefined && !strings(args.omittedKeyIds, 8, 128)) fail('COMMON', 'Некорректный список ключей.');
    locale(args.locale);
    return { operation: 'issue-generate', issuance: true, dn: distinguishedName(args.dn), email: args.email || undefined, keys: keyParams(args.params) };
  }
  if (input.method === 'importCertificate') {
    fields(args, ['allowedStorage', 'defaultPassword', 'keystorePath', 'certificates', 'locale']);
    // Storage type and path describe where NCALayer kept the key; Tegin finds its key by the
    // public key in the certificate instead.
    for (const field of ['allowedStorage', 'defaultPassword']) if (args[field] !== undefined && (typeof args[field] !== 'string' || args[field].length > 256)) fail('COMMON', 'Некорректные параметры установки.');
    if (args.keystorePath !== undefined && (typeof args.keystorePath !== 'string' || args.keystorePath.length > 4096)) fail('COMMON', 'Некорректные параметры установки.');
    if (!Array.isArray(args.certificates) || !args.certificates.length || args.certificates.length > 8) fail('COMMON', 'Нет сертификатов для установки.');
    locale(args.locale);
    return { operation: 'issue-install', issuance: true, certificates: args.certificates.map(certificate) };
  }
  fail('COMMON', 'Этот метод PKIEssentials не поддерживается.');
}

const CSR_PEM = /^-----BEGIN CERTIFICATE REQUEST-----\n(?:[A-Za-z0-9+/=]{1,64}\n)+-----END CERTIFICATE REQUEST-----\n?$/;
// The page receives only what the protocol needs: request PEMs, or the installation flag.
export function issuanceResult(normalized, result) {
  if (normalized.operation === 'issue-generate') {
    if (!object(result) || !Array.isArray(result.pems) || result.pems.length !== normalized.keys.length || result.pems.some(pem => typeof pem !== 'string' || pem.length > 16384 || !CSR_PEM.test(pem))) throw new Error('Некорректный запрос на сертификат.');
    return { pems: [...result.pems] };
  }
  if (normalized.operation === 'issue-install') {
    if (!object(result) || result.installed !== true) throw new Error('Сертификаты не установлены.');
    return { result: true };
  }
  throw new Error('Неизвестная операция.');
}
export const issuanceError = (code, message) => ({ status: false, code: typeof code === 'string' && /^[A-Z_]{1,40}$/.test(code) ? code : 'COMMON', message });
