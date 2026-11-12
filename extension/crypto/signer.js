import { nca256 } from './nca-curves.js';
import GostSign from '../vendor/gost/sign.cjs';
import GostDigest from '../vendor/gost/digest.cjs';
import { A, O, forge, parse, binary, bytes, der, oidValue, base64, utf8, seq, set } from './encoding.js';
import { inspectPkcs12, ContainerError } from '../lib/pkcs12.js';

export const schemes = {
  [O.gost512]: { label: 'ГОСТ 34.10-2015 · 512 бит', kncaName: 'ECGOST3410-2015', version: 2012, length: 512, namedCurve: 'T-512-A', curveOid: '1.2.398.3.10.1.1.2.2.1', hash: O.hash512, signature: O.sig512 },
  [O.gost256]: { label: 'ГОСТ 34.10-2015 · 256 бит', kncaName: 'ECGOST3410-2015', version: 2012, length: 256, curve: nca256, curveOid: '1.2.398.3.10.1.1.2.1.1', hash: O.hash256, signature: O.sig256 },
  [O.gost2004]: { label: 'ГОСТ 34.310-2004', kncaName: 'ECGOST34310', version: 2001, length: 256, namedCurve: 'S-256-A', curveOid: '1.2.398.3.10.1.1.1.1.1', hash: O.hash2004, signature: O.sig2004 }
};
export function gostEngine(scheme) {
  // The input to this engine is already a digest; do not enable its internal hash.
  return new GostSign({ version: scheme.version, length: scheme.length, namedCurve: scheme.namedCurve, curve: scheme.curve });
}

function nameValue(node, field) {
  for (const rdn of node.value) for (const entry of rdn.value) {
    if (oidValue(entry.value[0]) !== field) continue;
    const value = entry.value[1];
    if (value.type === A.Type.UTF8) return forge.util.decodeUtf8(value.value);
    // forge already decodes BMPSTRING from UTF-16BE into the JavaScript string.
    return value.value;
  }
  return '';
}

function distinguishedName(node) {
  const aliases = { '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'SERIALNUMBER', '2.5.4.4': 'SURNAME', '2.5.4.42': 'GIVENNAME', '1.2.840.113549.1.9.1': 'E' };
  return [...node.value].reverse().map(rdn => rdn.value.map(entry => {
    const id = oidValue(entry.value[0]);
    const value = nameValue(seq(set(entry)), id);
    const escaped = value.replace(/[\\,+=<>;"#]/g, '\\$&').replace(/^ | $/g, '\\$&');
    return `${aliases[id] || id}=${escaped}`;
  }).join('+')).join(',');
}

// Forward RDN order with Kalkan's X509Name symbols and escaping, as NCALayer getKeyInfo prints it.
const KNCA_SYMBOLS = { '2.5.4.6': 'C', '2.5.4.8': 'S', '2.5.4.7': 'L', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.12': 'T', '2.5.4.15': 'BusinessCategory',
  '1.2.840.113549.1.9.1': 'E', '2.5.4.3': 'CN', '2.5.4.4': 'SURNAME', '2.5.4.42': 'G', '2.5.4.5': 'SERIALNUMBER', '0.9.2342.19200300.100.1.25': 'DC',
  '0.9.2342.19200300.100.1.1': 'UID', '2.5.4.9': 'STREET', '2.5.4.46': 'DN', '2.5.4.17': 'PostalCode' };
function kncaDistinguishedName(node) {
  return node.value.map(rdn => rdn.value.map(entry => {
    const id = oidValue(entry.value[0]);
    return `${KNCA_SYMBOLS[id] || id}=${nameValue(seq(set(entry)), id).replace(/ +$/, '').replace(/[\\,+=<>;"]/g, '\\$&')}`;
  }).join('+')).join(',');
}

function dateValue(node) {
  if (node.type === A.Type.UTCTIME) return A.utcTimeToDate(node.value);
  if (node.type === A.Type.GENERALIZEDTIME) return A.generalizedTimeToDate(node.value);
  throw new Error('Неизвестный формат срока сертификата.');
}

export function certificateInfo(raw) {
  const certificate = typeof raw === 'string' || raw instanceof Uint8Array ? parse(raw) : raw;
  const tbs = certificate.value[0].value;
  const offset = tbs[0].tagClass === A.Class.CONTEXT_SPECIFIC ? 1 : 0;
  if (oidValue(certificate.value[1].value[0]) !== oidValue(tbs[offset + 1].value[0])) throw new Error('Алгоритмы подписи сертификата не совпадают.');
  const spki = tbs[offset + 5];
  const keyOid = oidValue(spki.value[0].value[0]);
  const subject = tbs[offset + 4];
  const validity = tbs[offset + 3].value;
  const serial = tbs[offset];
  const ext = tbs.find(node => node.tagClass === A.Class.CONTEXT_SPECIFIC && node.type === 3);
  let eku = [], ekuCritical = false, keyUsage = null, ca = false, pathLength = null, subjectKeyId = null, authorityKeyId = null;
  const unknownCritical = [];
  const extensionIds = new Set();
  for (const entry of ext?.value?.[0]?.value || []) {
    const id = oidValue(entry.value[0]);
    if (extensionIds.has(id)) throw new Error('В сертификате повторяются расширения.');
    extensionIds.add(id);
    if (id === '2.5.29.37') eku = parse(entry.value.at(-1).value).value.map(oidValue);
    if (id === '2.5.29.15') {
      const usage = parse(entry.value.at(-1).value);
      keyUsage = (usage.bitStringContents || usage.value).charCodeAt(1);
    }
    if (id === '2.5.29.19') {
      const constraints = parse(entry.value.at(-1).value).value;
      ca = constraints[0]?.type === A.Type.BOOLEAN && constraints[0].value.charCodeAt(0) !== 0;
      const limit = constraints.find(node => node.type === A.Type.INTEGER);
      if (limit) pathLength = [...limit.value].reduce((value, char) => value * 256 + char.charCodeAt(0), 0);
    }
    if (id === '2.5.29.14') subjectKeyId = parse(entry.value.at(-1).value).value;
    if (id === '2.5.29.35') authorityKeyId = parse(entry.value.at(-1).value).value.find(node => node.tagClass === A.Class.CONTEXT_SPECIFIC && node.type === 0)?.value;
    const critical = entry.value[1]?.type === A.Type.BOOLEAN && entry.value[1].value.charCodeAt(0) !== 0;
    if (id === '2.5.29.37') ekuCritical = critical;
    if (critical && !['2.5.29.15', '2.5.29.19', '2.5.29.37'].includes(id)) unknownCritical.push(id);
  }
  const algorithm = keyOid === O.rsa ? { label: 'RSA · SHA-256', kncaName: 'RSA', hash: O.sha256, signature: O.rsa } : schemes[keyOid];
  if (!algorithm) {
    const error = new Error(`Алгоритм ключа ${keyOid} пока не поддерживается.`);
    error.code = 'UNSUPPORTED_CERTIFICATE_ALGORITHM';
    error.oid = keyOid;
    throw error;
  }
  if (keyOid !== O.rsa) {
    const params = spki.value[0].value[1];
    if (!params || params.type !== A.Type.SEQUENCE || oidValue(params.value[0]) !== algorithm.curveOid) {
      const error = new Error('Параметры ГОСТ не поддерживаются.');
      error.code = 'UNSUPPORTED_CERTIFICATE_ALGORITHM';
      error.oid = keyOid;
      throw error;
    }
  }
  return { certificate, spki, serial, issuer: tbs[offset + 2], subject,
    raw: der(certificate), signatureOid: oidValue(certificate.value[1].value[0]), keyOid, algorithm, eku, ekuCritical, keyUsage, ca, pathLength, subjectKeyId, authorityKeyId, unknownCritical,
    summary: {
      name: nameValue(subject, '2.5.4.3'), iin: /^IIN(\d{12})$/.exec(nameValue(subject, '2.5.4.5'))?.[1] || '',
      organization: nameValue(subject, '2.5.4.10'), issuer: nameValue(tbs[offset + 2], '2.5.4.3'),
      bin: /^BIN(\d{12})$/.exec(nameValue(subject, '2.5.4.11'))?.[1] || '',
      subjectDn: distinguishedName(subject), issuerDn: distinguishedName(tbs[offset + 2]),
      notBefore: dateValue(validity[0]).toISOString(), notAfter: dateValue(validity[1]).toISOString(),
      serialNumber: forge.util.bytesToHex(serial.value), algorithm: algorithm.label, extendedKeyUsageOids: [...eku],
      certificate: forge.util.encode64(der(certificate)),
      knca: { keyId: subjectKeyId && forge.util.bytesToHex(subjectKeyId), authorityKeyIdentifier: subjectKeyId && authorityKeyId ? forge.util.bytesToHex(authorityKeyId) : null,
        subjectCn: nameValue(subject, '2.5.4.3').replace(/ +$/, ''), subjectDn: kncaDistinguishedName(subject),
        issuerCn: nameValue(tbs[offset + 2], '2.5.4.3').replace(/ +$/, ''), issuerDn: kncaDistinguishedName(tbs[offset + 2]), algorithm: algorithm.kncaName }
    }
  };
}

const MAX_ITERATIONS = 1000000;
// A key safe and a certificate safe at the per-step limit, tried with each of the three PBES2 password encodings.
const MAX_KDF_WORK = 6 * MAX_ITERATIONS;
const PBES2 = '1.2.840.113549.1.5.13', PBKDF2 = '1.2.840.113549.1.5.12';
const PKCS12_PBE = new Set(['1.2.840.113549.1.12.1.3', '1.2.840.113549.1.12.1.6']);
const PBES2_CIPHERS = new Set(['2.16.840.1.101.3.4.1.2', '2.16.840.1.101.3.4.1.22', '2.16.840.1.101.3.4.1.42', '1.2.840.113549.3.7', '1.3.14.3.2.7']);
// forge derives hmacWithSHA224 (1.2.840.113549.2.8) with SHA-512/224, so it is not accepted.
const PBES2_PRFS = new Set(['1.2.840.113549.2.7', '1.2.840.113549.2.9', '1.2.840.113549.2.10', '1.2.840.113549.2.11']);
const MAC_DIGESTS = { '1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512', '1.2.840.113549.2.5': 'md5' };
const MAC_KEY_BYTES = { sha1: 20, sha256: 32, sha384: 48, sha512: 64, md5: 16 };

function checkKdfLimits(node, depth = 0) {
  if (depth > 32) throw new ContainerError('Слишком сложная структура контейнера.', 'CONTAINER_LIMITS');
  if (!Array.isArray(node.value)) return;
  if (node.type === A.Type.SEQUENCE && node.value[0]?.type === A.Type.OID) {
    const id = oidValue(node.value[0]);
    if (id.startsWith('1.2.840.113549.1.12.1.') || id === PBKDF2) {
      const iterations = node.value[1]?.value?.[1];
      if (iterations?.type === A.Type.INTEGER) validateIterations(iterations.value);
    }
  }
  for (const child of node.value) checkKdfLimits(child, depth + 1);
}
function integerValue(value) {
  if (typeof value !== 'string' || !value.length || value.charCodeAt(0) & 128) return -1;
  let count = 0;
  for (const char of value) count = count * 256 + char.charCodeAt(0);
  return count;
}
function validateIterations(value) {
  const count = integerValue(value);
  if (count < 1 || count > MAX_ITERATIONS) throw new ContainerError('Число итераций защиты контейнера не поддерживается.', 'CONTAINER_LIMITS');
  return count;
}

// Diagnostics carry only algorithm OIDs and bounded counters: no names, IIN, file names, DER or key bytes.
const safeOid = value => typeof value === 'string' && /^\d{1,9}(\.\d{1,9}){1,24}$/.test(value) ? value : undefined;
const safeCount = value => Number.isSafeInteger(value) && value >= 0 ? Math.min(value, MAX_ITERATIONS + 1) : undefined;
function describeEncryption(algorithm) { return describeParameters(oidValue(algorithm.value[0]), algorithm.value[1]); }
function describeParameters(scheme, params) {
  if (scheme === PBES2) {
    const [kdf, cipher] = params.value;
    const kdfParams = kdf.value[1].value;
    const prf = kdfParams.find(node => node.type === A.Type.SEQUENCE);
    return { scheme, kdf: oidValue(kdf.value[0]), prf: prf ? oidValue(prf.value[0]) : undefined,
      cipher: oidValue(cipher.value[0]), iterations: integerValue(kdfParams[1]?.value) };
  }
  return { scheme, iterations: integerValue(params?.value?.[1]?.value) };
}
function safeEncryption(entry) {
  return { scheme: safeOid(entry.scheme), kdf: safeOid(entry.kdf), prf: safeOid(entry.prf), cipher: safeOid(entry.cipher), iterations: safeCount(entry.iterations) };
}
function supportedEncryption(entry) {
  if (PKCS12_PBE.has(entry.scheme)) return true;
  return entry.scheme === PBES2 && entry.kdf === PBKDF2 && PBES2_CIPHERS.has(entry.cipher) && (entry.prf === undefined || PBES2_PRFS.has(entry.prf));
}
function visibleEncryption(authSafe) {
  const found = [];
  for (const content of authSafe.value) {
    const value = content.value[1].value[0];
    if (oidValue(content.value[0]) === O.data) {
      for (const bag of parse(value.value).value) {
        if (oidValue(bag.value[0]) === forge.pki.oids.pkcs8ShroudedKeyBag) found.push(describeEncryption(bag.value[1].value[0].value[0]));
      }
    } else found.push(describeEncryption(value.value[1].value[1]));
  }
  return found;
}

function verifyMac(pfx, authSafeBytes, password, profile) {
  let algorithm, expected, salt, iterations;
  try {
    const [digestInfo, macSalt, macIterations] = pfx.value[2].value;
    algorithm = oidValue(digestInfo.value[0].value[0]);
    expected = digestInfo.value[1].value; salt = macSalt.value;
    iterations = macIterations ? integerValue(macIterations.value) : 1;
    if (typeof expected !== 'string' || typeof salt !== 'string') throw new Error();
  } catch { throw new ContainerError(undefined, 'CONTAINER_MALFORMED'); }
  profile.integrity = { algorithm: safeOid(algorithm), iterations: safeCount(iterations) };
  if (iterations < 1 || iterations > MAX_ITERATIONS) throw new ContainerError('Число итераций защиты контейнера не поддерживается.', 'CONTAINER_LIMITS');
  const name = MAC_DIGESTS[algorithm];
  if (!name) throw new ContainerError(undefined, 'UNSUPPORTED_INTEGRITY_ALGORITHM');
  const md = forge.md[name].create();
  // RFC 7292 B.1: the MAC key is derived from the BMPString (UTF-16BE) password.
  const key = forge.pkcs12.generateKey(password, forge.util.createBuffer(salt), 3, iterations, MAC_KEY_BYTES[name], md);
  const mac = forge.hmac.create();
  mac.start(md, key);
  mac.update(authSafeBytes);
  const actual = mac.digest().getBytes();
  if (actual.length !== expected.length) throw new ContainerError(undefined, 'PASSWORD_OR_DAMAGED');
  let difference = 0;
  for (let i = 0; i < actual.length; i++) difference |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  if (difference) throw new ContainerError(undefined, 'PASSWORD_OR_DAMAGED');
}

function decryptSafeContents(pfx, password) {
  // PKCS#12 PBE derives keys from the BMPString password. For PBES2 (RFC 8018) the
  // password octets differ by producer: OpenSSL and current Java use UTF-8, Kalkan
  // uses the low byte of each UTF-16 unit, and node-forge writers pass the JavaScript
  // string to PBKDF2 unconverted. Non-ASCII passwords try them in that order. The full
  // password is already authenticated by the MAC and the key is later matched
  // against its certificate.
  const encodings = [forge.util.encodeUtf8(password)];
  if (/[^\x00-\x7f]/.test(password)) encodings.push(password.replace(/[^]/g, char => String.fromCharCode(char.charCodeAt(0) & 255)), password);
  const pbe = forge.pki.pbe, pbes2 = pbe.getCipherForPBES2, pkcs12Pbe = pbe.getCipherForPKCS12PBE;
  const authenticated = A.create(A.Class.UNIVERSAL, A.Type.SEQUENCE, true, pfx.value.slice(0, 2));
  // Key bags inside EncryptedData are only visible after decryption, so every parameter
  // set forge asks a cipher for is held to the same algorithms and limits, and the total
  // derivation work of one open is bounded.
  let work = 0, failure;
  const guarded = cipher => (scheme, params, secret) => {
    const entry = describeParameters(scheme, params);
    if (!supportedEncryption(entry)) throw new ContainerError(undefined, 'UNSUPPORTED_ENCRYPTION_ALGORITHM');
    if (entry.iterations < 1 || entry.iterations > MAX_ITERATIONS || (work += entry.iterations) > MAX_KDF_WORK) throw new ContainerError('Число итераций защиты контейнера не поддерживается.', 'CONTAINER_LIMITS', 'decryption');
    return cipher(scheme, params, secret);
  };
  for (const encoded of encodings) {
    pbe.getCipherForPBES2 = guarded((oid, params) => pbes2(oid, params, encoded));
    pbe.getCipherForPKCS12PBE = guarded(pkcs12Pbe);
    // MAC is verified by verifyMac; forge only decrypts the authenticated contents.
    try { return forge.pkcs12.pkcs12FromAsn1(authenticated, true, password); }
    catch (error) { if (error instanceof ContainerError) throw error; failure = error; if (error?.oid) break; }
    finally { pbe.getCipherForPBES2 = pbes2; pbe.getCipherForPKCS12PBE = pkcs12Pbe; }
  }
  throw new ContainerError(undefined, failure?.oid ? 'UNSUPPORTED_ENCRYPTION_ALGORITHM' : 'DECRYPTION_FAILED');
}

function containerDiagnostic(error, profile = {}) {
  return { stage: error.stage || undefined, code: error.code, container: {
    size: safeCount(profile.size), encoding: ['DER', 'BER'].includes(profile.encoding) ? profile.encoding : undefined,
    integrity: profile.integrity, encryption: profile.encryption, bags: profile.bags,
    keyAlgorithms: profile.keyAlgorithms?.map(safeOid).filter(Boolean)
  } };
}

function fixedScalar(raw, size) {
  let scalar = bytes(raw);
  try {
    const inner = parse(raw);
    if ([A.Type.OCTETSTRING, A.Type.INTEGER].includes(inner.type) && typeof inner.value === 'string') scalar = bytes(inner.value);
  } catch { /* Common PKCS#8 representations include a bare scalar. */ }
  if (scalar.length === size + 1 && scalar[0] === 0) scalar = scalar.subarray(1);
  if (scalar.length !== size) throw new ContainerError('Неподдерживаемое представление закрытого ключа ГОСТ.', 'UNSUPPORTED_KEY_ALGORITHM');
  return scalar.slice();
}

export async function openContainer(container, password, options = {}) {
  const state = { stage: 'structure', profile: {} };
  try { return await openAuthenticatedContainer(container, password, options, state); }
  catch (error) {
    const failure = error instanceof ContainerError ? error : new ContainerError(undefined, 'INTERNAL', state.stage);
    if (error?.certificate) failure.certificate = error.certificate;
    failure.diagnostic = containerDiagnostic(failure, state.profile);
    throw failure;
  }
}

// exportKey is for the password change only: the signer then also returns the PKCS#8 and the
// container layout, and stays inside the worker like every other opened key.
async function openAuthenticatedContainer(container, password, { now = Date.now(), exportKey = false } = {}, state) {
  const { profile } = state;
  inspectPkcs12(container);
  profile.size = container.length;
  let pfx, authSafeBytes, authSafe;
  try {
    pfx = parse(container);
    profile.encoding = der(pfx) === binary(container) ? 'DER' : 'BER';
    authSafeBytes = pfx.value[1].value[1].value[0].value;
    authSafe = parse(authSafeBytes);
  } catch { throw new ContainerError(undefined, 'CONTAINER_MALFORMED'); }
  if (pfx.value.length !== 3) throw new ContainerError(undefined, 'CONTAINER_NO_INTEGRITY');
  state.stage = 'limits';
  checkKdfLimits(pfx);
  for (const content of authSafe.value) {
    checkKdfLimits(content);
    if (oidValue(content.value[0]) === O.data) checkKdfLimits(parse(content.value[1].value[0].value));
  }
  let encryption = [];
  try { encryption = visibleEncryption(authSafe); } catch { /* Reported by decryption if unreadable. */ }
  profile.encryption = encryption.map(safeEncryption);
  state.stage = 'password';
  if (typeof password !== 'string' || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(password)) throw new ContainerError(undefined, 'PASSWORD_ENCODING');
  state.stage = 'integrity';
  verifyMac(pfx, authSafeBytes, password, profile);
  state.stage = 'decryption';
  if (!encryption.every(supportedEncryption)) throw new ContainerError(undefined, 'UNSUPPORTED_ENCRYPTION_ALGORITHM');
  const store = decryptSafeContents(pfx, password);
  state.stage = 'key-pair';
  const bags = store.safeContents.flatMap(safe => safe.safeBags);
  const certBags = bags.filter(bag => bag.type === forge.pki.oids.certBag);
  const keyBags = bags.filter(bag => bag.type === forge.pki.oids.pkcs8ShroudedKeyBag || bag.type === forge.pki.oids.keyBag);
  profile.bags = { keys: keyBags.length, certificates: certBags.length, other: bags.length - keyBags.length - certBags.length };
  const unsupportedKeys = new Set(), supportedKeys = new Set();
  profile.keyAlgorithms = [];
  for (const keyBag of keyBags) {
    for (const certBag of certBags) {
      state.stage = 'key-pair';
      let info;
      try { info = certificateInfo(certBag.cert ? forge.pki.certificateToAsn1(certBag.cert) : certBag.asn1); }
      catch (error) {
        if (error?.code === 'UNSUPPORTED_CERTIFICATE_ALGORITHM') unsupportedKeys.add(error.oid);
        if (error?.oid && !profile.keyAlgorithms.includes(error.oid)) profile.keyAlgorithms.push(error.oid);
        continue;
      }
      supportedKeys.add(info.keyOid);
      if (!profile.keyAlgorithms.includes(info.keyOid)) profile.keyAlgorithms.push(info.keyOid);
      let key, publicKey;
      if (info.keyOid === O.rsa && keyBag.key) {
        if (keyBag.key.n.toString(16) !== certBag.cert?.publicKey.n.toString(16) || keyBag.key.e.toString(16) !== certBag.cert?.publicKey.e.toString(16)) continue;
        if (keyBag.key.n.bitLength() < 2048) throw new ContainerError(undefined, 'KEY_TOO_WEAK');
        const privateInfo = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(keyBag.key));
        key = await crypto.subtle.importKey('pkcs8', bytes(der(privateInfo)), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
        publicKey = await crypto.subtle.importKey('spki', bytes(der(info.spki)), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
      } else if (info.keyOid !== O.rsa && keyBag.asn1) {
        if (oidValue(keyBag.asn1.value[1].value[0]) !== info.keyOid) continue;
        key = fixedScalar(keyBag.asn1.value[2].value, info.algorithm.length / 8);
        const pubBitString = info.spki.value[1].bitStringContents || info.spki.value[1].value;
        const point = parse(pubBitString.slice(1));
        publicKey = bytes(point.value);
        const derivedPublic = scalar => new Uint8Array(new GostSign({ version: info.algorithm.version,
          length: info.algorithm.length, namedCurve: info.algorithm.namedCurve, curve: info.algorithm.curve, ukm: scalar }).generateKey().publicKey);
        const matches = scalar => scalar.some(value => value !== 0) && binary(derivedPublic(scalar)) === binary(publicKey);
        if (!matches(key)) {
          key.reverse();
          if (!matches(key)) { key.fill(0); continue; }
        }
      } else continue;
      state.stage = 'certificate';
      if (now < Date.parse(info.summary.notBefore) || now > Date.parse(info.summary.notAfter)) {
        if (key instanceof Uint8Array) key.fill(0);
        const error = new ContainerError(undefined, 'CERTIFICATE_NOT_VALID_NOW');
        error.certificate = { ...info.summary };
        throw error;
      }
      if (info.keyUsage !== null && !(info.keyUsage & 192)) {
        if (key instanceof Uint8Array) key.fill(0);
        throw new ContainerError(undefined, 'CERTIFICATE_NO_DIGITAL_SIGNATURE');
      }
      // The browser worker owns all decrypted data and is terminated after each operation.
      let rsaKey = info.keyOid === O.rsa ? keyBag.key : null;
      let exportable = exportKey ? keyBag : null;
      const exported = exportKey ? {
        contents: { ...profile.bags }, protection: { integrity: profile.integrity, encryption: profile.encryption },
        alias: typeof keyBag.attributes?.friendlyName?.[0] === 'string' ? keyBag.attributes.friendlyName[0] : undefined,
        privateKeyInfo() {
          if (!exportable) throw new Error('Ключ уже закрыт.');
          return exportable.key ? forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(exportable.key)) : exportable.asn1;
        }
      } : {};
      return {
        ...exported,
        info, certificates: certBags.map(bag => bag.cert ? forge.pki.certificateToAsn1(bag.cert) : bag.asn1),
        async digest(data) {
          if (info.keyOid === O.rsa) return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
          return new Uint8Array(new GostDigest({ version: info.algorithm.version === 2001 ? 1994 : 2012,
            length: info.algorithm.length, sBox: 'D-TEST' }).digest(data));
        },
        async sign(data) {
          if (info.keyOid === O.rsa) {
            const result = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, data));
            if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, result, data)) throw new Error('Самопроверка подписи не пройдена.');
            return result;
          }
          return this.signDigest(await this.digest(data));
        },
        async signDigest(hash) {
          const expectedLength = info.keyOid === O.rsa ? 32 : info.algorithm.length / 8;
          if (hash.length !== expectedLength) throw new Error(`Ожидается хеш длиной ${expectedLength} байт.`);
          if (info.keyOid === O.rsa) {
            // Raw PKCS#1 v1.5 signing of an existing SHA-256 digest. Forge's
            // vulnerable generic signature verifier is deliberately not used.
            const digest = binary(hash);
            const result = rsaKey.sign({ algorithm: 'sha256', digest: () => forge.util.createBuffer(digest) });
            const publicRsa = forge.pki.setRsaPublicKey(rsaKey.n, rsaKey.e);
            const recovered = publicRsa.encrypt(result, 'RAW');
            const digestInfo = forge.util.hexToBytes('3031300d060960864801650304020105000420') + digest;
            const block = '\x00\x01' + '\xff'.repeat(Math.ceil(rsaKey.n.bitLength() / 8) - digestInfo.length - 3) + '\x00' + digestInfo;
            if (recovered !== block) throw new Error('Самопроверка подписи не пройдена.');
            return bytes(result);
          }
          const engine = gostEngine(info.algorithm);
          const signature = new Uint8Array(engine.sign(key, hash));
          if (!engine.verify(publicKey, signature, hash)) throw new Error('Самопроверка подписи не пройдена.');
          return signature; // Kalkan's Kazakhstan OIDs encode r_LE || s_LE.
        },
        destroy() { if (key instanceof Uint8Array) key.fill(0); key = null; publicKey = null; rsaKey = null; exportable = null; }
      };
    }
  }
  state.stage = 'key-pair';
  if (unsupportedKeys.size && !supportedKeys.size) throw new ContainerError(undefined, 'UNSUPPORTED_KEY_ALGORITHM');
  throw new ContainerError(undefined, 'NO_KEY_PAIR');
}

export { GostSign, GostDigest };
