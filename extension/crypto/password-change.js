// Password change for a PKCS#12 file key, the local counterpart of NCALayer's changePassword.
// Runs in the crypto worker. The page receives only the new container; the selected file is
// never written, so the user keeps the original until the new one is checked.
import { der } from './encoding.js';
import { openContainer } from './signer.js';
import { writePkcs12 } from './issuance.js';
import { ContainerError } from '../lib/pkcs12.js';
import { CHANGE_PASSWORD_RULE, CHANGE_PASSWORD_HINT } from '../lib/password-rule.js';

export { CHANGE_PASSWORD_RULE };

export class PasswordChangeError extends Error {
  constructor(code, message) { super(message); this.name = 'PasswordChangeError'; this.code = code; }
}
const fail = (code, message) => { throw new PasswordChangeError(code, message); };

const MAC_NAMES = { '1.3.14.3.2.26': 'HMAC-SHA-1', '2.16.840.1.101.3.4.2.1': 'HMAC-SHA-256', '2.16.840.1.101.3.4.2.2': 'HMAC-SHA-384',
  '2.16.840.1.101.3.4.2.3': 'HMAC-SHA-512', '1.2.840.113549.2.5': 'HMAC-MD5' };
const PBE_NAMES = { '1.2.840.113549.1.12.1.3': 'PBE-SHA1-3DES', '1.2.840.113549.1.12.1.6': 'PBE-SHA1-RC2-40' };
const CIPHER_NAMES = { '2.16.840.1.101.3.4.1.2': 'AES-128-CBC', '2.16.840.1.101.3.4.1.22': 'AES-192-CBC', '2.16.840.1.101.3.4.1.42': 'AES-256-CBC',
  '1.2.840.113549.3.7': '3DES-CBC', '1.3.14.3.2.7': 'DES-CBC' };
const PRF_NAMES = { '1.2.840.113549.2.7': 'SHA-1', '1.2.840.113549.2.9': 'SHA-256', '1.2.840.113549.2.10': 'SHA-384', '1.2.840.113549.2.11': 'SHA-512' };
const count = value => Number.isSafeInteger(value) ? String(value).replace(/\B(?=(\d{3})+$)/g, '\u00a0') : '?';
export function describeProtection({ integrity, encryption = [] } = {}) {
  const ciphers = encryption.map(entry => PBE_NAMES[entry.scheme] ? `${PBE_NAMES[entry.scheme]}, ${count(entry.iterations)} итераций`
    : `PBES2 ${CIPHER_NAMES[entry.cipher] || entry.cipher}, PBKDF2-HMAC-${PRF_NAMES[entry.prf] || 'SHA-1'}, ${count(entry.iterations)} итераций`);
  return { integrity: integrity ? `${MAC_NAMES[integrity.algorithm] || integrity.algorithm}, ${count(integrity.iterations)} итераций` : '—', encryption: [...new Set(ciphers)] };
}

const sortedDer = certificates => certificates.map(der).sort();

export async function changeContainerPassword(container, oldPassword, newPassword, options = {}) {
  try { return await changePassword(container, oldPassword, newPassword, options); }
  catch (error) {
    if (error instanceof PasswordChangeError || error instanceof ContainerError) throw error;
    fail('CHANGEPASS_COMMON', 'Не удалось сменить пароль ключа.');
  }
}

async function changePassword(container, oldPassword, newPassword, options) {
  if (typeof newPassword !== 'string' || !CHANGE_PASSWORD_RULE.test(newPassword)) fail('CHANGEPASS_INCORRECT_NEWPASS_PATTERN', CHANGE_PASSWORD_HINT);
  if (newPassword === oldPassword) fail('CHANGEPASS_SAME_PASSWORD', 'Новый пароль совпадает со старым.');
  const opened = await openContainer(container, oldPassword, { ...options, exportKey: true });
  let reopened;
  try {
    // NCALayer refuses keys without a certificate; Tegin also keeps the file to one key and its
    // certificates so that nothing in the original is silently dropped.
    if (opened.contents.keys !== 1 || opened.contents.other) fail('CHANGE_PASSWORD_CONSTRAINT', 'Смена пароля поддерживается для контейнера с одним ключом и его сертификатами.');
    const privateInfo = opened.privateKeyInfo();
    const leaf = opened.info.raw;
    const certificates = [leaf, ...opened.certificates.map(der).filter(raw => raw !== leaf)];
    const result = writePkcs12(privateInfo, certificates, newPassword, { friendlyName: opened.alias });

    reopened = await openContainer(result, newPassword, { ...options, exportKey: true });
    const same = der(reopened.privateKeyInfo()) === der(privateInfo) && reopened.info.raw === leaf
      && JSON.stringify(sortedDer(reopened.certificates)) === JSON.stringify(sortedDer(opened.certificates));
    if (!same) fail('CHANGEPASS_SELF_CHECK', 'Новый контейнер не прошёл самопроверку: ключ или сертификаты отличаются.');
    try { (await openContainer(result, oldPassword, options)).destroy(); fail('CHANGEPASS_SELF_CHECK', 'Новый контейнер открывается старым паролем.'); }
    catch (error) { if (!(error instanceof ContainerError && error.code === 'PASSWORD_OR_DAMAGED')) throw error; }

    return { container: result, certificate: opened.info.summary, alias: opened.alias,
      protection: { before: describeProtection(opened.protection), after: describeProtection(reopened.protection) } };
  } finally { opened.destroy(); reopened?.destroy(); }
}
