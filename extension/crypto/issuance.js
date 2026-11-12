// Key generation and certificate installation for NUC online applications. Runs in the
// crypto worker: keys are created here, leave only as an encrypted container, and the page
// receives PKCS#10 requests built from the public key.
import { A, O, forge, parse, binary, bytes, der, oidValue, base64, unbase64, seq, set, oid, octet, integer, algorithm } from './encoding.js';
import { certificateInfo, gostEngine, GostDigest, GostSign, schemes } from './signer.js';
import { verifySignedBytes } from './verification.js';
import { verifyChain } from './chain.js';
import { PASSWORD_RULE, PASSWORD_HINT } from '../signing/issuance-protocol.js';

export class IssuanceError extends Error {
  constructor(code, message) { super(message); this.name = 'IssuanceError'; this.code = code; }
}
const fail = (code, message) => { throw new IssuanceError(code, message); };
const hex = value => [...value].map(byte => byte.toString(16).padStart(2, '0')).join('');
const sha256 = async data => new Uint8Array(await crypto.subtle.digest('SHA-256', data));
const RSA_SIGNATURE = '1.2.840.113549.1.1.11';
const EXTENSION_REQUEST = '1.2.840.113549.1.9.14';
const STORAGE_EXTENSION = '1.2.398.3.3.5', FILE_STORAGE = '1.2.398.3.3.5.1.1';
// Final container: PBES2 AES-256-CBC with PBKDF2-HMAC-SHA256 and an HMAC-SHA256 MAC.
// The official Kalkan provider opens this profile (tests/kalkan-issuance.mjs).
export const PKCS12_ITERATIONS = 100000;
// Pending key in extension storage, sealed with AES-256-GCM.
export const SEAL_ITERATIONS = 600000;

export function keySpec({ algorithm: name, length }) {
  if (name === 'ECGOST3410-2015' && (length === 512 || length === 256)) {
    const keyOid = length === 512 ? O.gost512 : O.gost256;
    return { kind: 'gost', algorithm: name, length, keyOid, scheme: schemes[keyOid], label: schemes[keyOid].label };
  }
  if (name === 'RSA' && [2048, 3072, 4096].includes(length)) return { kind: 'rsa', algorithm: name, length, keyOid: O.rsa, label: `RSA · ${length} бит` };
  fail('GENKEY_UNKNOWN_ALG', 'Алгоритм ключа не поддерживается.');
}

// String types as in the Kalkan/Bouncy Castle default X.509 entry converter.
const PRINTABLE = new Set(['2.5.4.6', '2.5.4.5', '2.5.4.46', '2.5.4.20']);
const IA5 = new Set(['1.2.840.113549.1.9.1', '0.9.2342.19200300.100.1.25']);
export function encodeName(entries) {
  return seq(...entries.map(([id, value]) => {
    const node = PRINTABLE.has(id) ? A.create(0, A.Type.PRINTABLESTRING, false, value)
      : IA5.has(id) ? A.create(0, A.Type.IA5STRING, false, value)
      : A.create(0, A.Type.UTF8, false, forge.util.encodeUtf8(value));
    return set(seq(oid(id), node));
  }));
}

const gostAlgorithm = spec => seq(oid(spec.keyOid), seq(oid(spec.scheme.curveOid), oid(spec.scheme.hash)));
const bitString = value => A.create(0, A.Type.BITSTRING, false, '\0' + value);
function gostPoint(spki) {
  const bits = spki.value[1].bitStringContents || spki.value[1].value;
  return bytes(parse(bits.slice(1)).value);
}

export async function generateKey(spec) {
  if (spec.kind === 'gost') {
    const pair = gostEngine(spec.scheme).generateKey();
    const scalar = new Uint8Array(pair.privateKey).slice(), point = new Uint8Array(pair.publicKey).slice();
    new Uint8Array(pair.privateKey).fill(0);
    return { spec, scalar, point, spki: seq(gostAlgorithm(spec), bitString(der(octet(point)))) };
  }
  const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: spec.length, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  return { spec, privateKey: pair.privateKey, publicKey: pair.publicKey, spki: parse(new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey))) };
}
export function destroyKey(key) { key?.scalar?.fill(0); if (key) { key.scalar = null; key.privateKey = null; } }

async function signWith(key, data) {
  if (key.spec.kind === 'gost') {
    const hash = new Uint8Array(new GostDigest({ version: 2012, length: key.spec.length, sBox: 'D-TEST' }).digest(data));
    const engine = gostEngine(key.spec.scheme);
    const signature = new Uint8Array(engine.sign(key.scalar, hash));
    if (!engine.verify(key.point, signature, hash)) fail('GENKEY_COMMON', 'Самопроверка подписи запроса не пройдена.');
    return signature;
  }
  return new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key.privateKey, data));
}

// Public key identity independent of how a CA re-encodes SubjectPublicKeyInfo.
export async function keyIdentity(spki) {
  const keyOid = oidValue(spki.value[0].value[0]);
  if (keyOid === O.rsa) return hex(await sha256(bytes(`rsa:${der(parse((spki.value[1].bitStringContents || spki.value[1].value).slice(1)))}`)));
  const scheme = schemes[keyOid];
  const params = spki.value[0].value[1];
  if (!scheme || params?.type !== A.Type.SEQUENCE || oidValue(params.value[0]) !== scheme.curveOid) fail('UNSUPPORTED_KEY_ALGORITHM', 'Алгоритм ключа не поддерживается.');
  return hex(await sha256(bytes(`${keyOid}:${scheme.curveOid}:${binary(gostPoint(spki))}`)));
}

function publicInfo(spki) {
  const keyOid = oidValue(spki.value[0].value[0]);
  if (keyOid === O.rsa) return { keyOid, spki, algorithm: { label: 'RSA' } };
  const scheme = schemes[keyOid];
  const params = spki.value[0].value[1];
  if (!scheme || params?.type !== A.Type.SEQUENCE || oidValue(params.value[0]) !== scheme.curveOid) fail('UNSUPPORTED_KEY_ALGORITHM', 'Алгоритм ключа не поддерживается.');
  return { keyOid, spki, algorithm: scheme };
}

// PKCS#10 (RFC 2986). An e-mail outside the subject goes to an rfc822Name alternative name.
export async function createCsr(key, dn, { email } = {}) {
  const extensions = [
    ...(email ? [seq(oid('2.5.29.17'), octet(der(seq(A.create(A.Class.CONTEXT_SPECIFIC, 1, false, email)))))] : []),
    // NCALayer 1.4 always adds this non-critical extension: file storage type and its folder. The
    // browser cannot know the folder, so the path is an empty UTF8String.
    seq(oid(STORAGE_EXTENSION), octet(der(seq(oid(FILE_STORAGE), A.create(0, A.Type.UTF8, false, '')))))
  ];
  const attributes = [seq(oid(EXTENSION_REQUEST), set(seq(...extensions)))];
  const info = seq(integer(0), encodeName(dn), key.spki, A.create(A.Class.CONTEXT_SPECIFIC, 0, true, attributes));
  const infoDer = bytes(der(info));
  const signature = await signWith(key, infoDer);
  const csr = bytes(der(seq(info, algorithm(key.spec.kind === 'gost' ? key.spec.scheme.signature : RSA_SIGNATURE), bitString(binary(signature)))));
  await verifyCsr(csr);
  return csr;
}

export async function verifyCsr(raw) {
  let request, info, spki, signatureOid, signature;
  try {
    request = parse(raw);
    [info] = request.value;
    if (request.value.length !== 3 || info.value.length !== 4 || info.value[0].value !== '\0' || info.value[3].tagClass !== A.Class.CONTEXT_SPECIFIC) throw new Error();
    spki = info.value[2];
    signatureOid = oidValue(request.value[1].value[0]);
    const bits = request.value[2].bitStringContents || request.value[2].value;
    if (bits.charCodeAt(0) !== 0) throw new Error();
    signature = bytes(bits.slice(1));
  } catch { fail('GENKEY_EMPTY_PKCS10', 'Некорректный запрос на сертификат.'); }
  const publicKey = publicInfo(spki);
  if (!await verifySignedBytes(publicKey, bytes(der(info)), signature, signatureOid)) fail('GENKEY_EMPTY_PKCS10', 'Подпись запроса на сертификат не прошла проверку.');
  return { subject: info.value[1], spki, keyOid: publicKey.keyOid, signatureOid };
}

export function csrPem(raw) {
  const body = base64(raw).replace(/.{1,64}/g, '$&\n');
  return `-----BEGIN CERTIFICATE REQUEST-----\n${body}-----END CERTIFICATE REQUEST-----\n`;
}

// PKCS#8 as the Kalkan provider writes it: GOST keys hold the little-endian scalar in an
// OCTET STRING inside the privateKey OCTET STRING.
async function privateKeyInfo(key) {
  if (key.spec.kind === 'gost') return seq(integer(0), gostAlgorithm(key.spec), octet(der(octet(key.scalar))));
  return parse(new Uint8Array(await crypto.subtle.exportKey('pkcs8', key.privateKey)));
}

async function aesKey(password, salt, iterations) {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
// Pending keys: PKCS#8 DER under AES-256-GCM; the record id and key identities are authenticated.
export async function sealKeys(keys, password, context) {
  if (!PASSWORD_RULE.test(password)) fail('PASSWORD_POLICY', PASSWORD_HINT);
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = bytes(der(seq(...await Promise.all(keys.map(privateKeyInfo)))));
  try {
    const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(context) }, await aesKey(password, salt, SEAL_ITERATIONS), plain));
    return { version: 1, kdf: 'PBKDF2-SHA256', iterations: SEAL_ITERATIONS, cipher: 'AES-256-GCM', salt: base64(salt), iv: base64(iv), data: base64(data) };
  } finally { plain.fill(0); }
}

export async function unsealKeys(sealed, password, context) {
  if (sealed?.version !== 1 || sealed.kdf !== 'PBKDF2-SHA256' || sealed.cipher !== 'AES-256-GCM' || !Number.isInteger(sealed.iterations) || sealed.iterations < 100000 || sealed.iterations > 2000000) fail('PENDING_DAMAGED', 'Сохранённый ключ заявки повреждён.');
  let plain;
  try {
    const salt = unbase64(sealed.salt), iv = unbase64(sealed.iv), data = unbase64(sealed.data);
    if (salt.length !== 16 || iv.length !== 12) throw new Error();
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(context) }, await aesKey(password, salt, sealed.iterations), data));
  } catch { fail('PASSWORD_OR_DAMAGED', 'Пароль не подошёл или сохранённый ключ повреждён.'); }
  try {
    const keys = [];
    for (const item of parse(plain).value) keys.push(await restoreKey(item));
    return keys;
  } catch (error) { if (error instanceof IssuanceError) throw error; fail('PENDING_DAMAGED', 'Сохранённый ключ заявки повреждён.'); }
  finally { plain.fill(0); }
}

async function restoreKey(pkcs8) {
  const keyOid = oidValue(pkcs8.value[1].value[0]);
  if (keyOid === O.rsa) {
    const privateKey = await crypto.subtle.importKey('pkcs8', bytes(der(pkcs8)), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['sign']);
    const jwk = await crypto.subtle.exportKey('jwk', privateKey);
    const publicKey = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']);
    const spki = parse(new Uint8Array(await crypto.subtle.exportKey('spki', publicKey)));
    return { spec: keySpec({ algorithm: 'RSA', length: forge.pki.publicKeyFromAsn1(spki).n.bitLength() }), privateKey, publicKey, spki };
  }
  const scheme = schemes[keyOid];
  if (!scheme || scheme.version !== 2012) fail('PENDING_DAMAGED', 'Сохранённый ключ заявки повреждён.');
  const spec = keySpec({ algorithm: 'ECGOST3410-2015', length: scheme.length });
  const scalar = bytes(parse(pkcs8.value[2].value).value);
  if (scalar.length !== scheme.length / 8) fail('PENDING_DAMAGED', 'Сохранённый ключ заявки повреждён.');
  const point = new Uint8Array(new GostSign({ version: scheme.version, length: scheme.length, namedCurve: scheme.namedCurve, curve: scheme.curve, ukm: scalar }).generateKey().publicKey);
  return { spec, scalar, point, spki: seq(gostAlgorithm(spec), bitString(der(octet(point)))) };
}

// Proof that the restored private key belongs to the certificate, not only matching identities.
async function provePossession(key, info) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const signature = await signWith(key, challenge);
  const signatureOid = key.spec.kind === 'gost' ? key.spec.scheme.signature : RSA_SIGNATURE;
  if (!await verifySignedBytes(info, challenge, signature, signatureOid)) fail('CERTIFICATE_KEY_MISMATCH', 'Сертификат не соответствует ключу заявки.');
}

const attribute = (id, value) => seq(oid(id), A.create(0, A.Type.SET, true, [value]));
function bmp(value) { let result = ''; for (const char of value) result += String.fromCharCode(char.charCodeAt(0) >> 8, char.charCodeAt(0) & 255); return result; }
function integerBytes(value) {
  let text = value.toString(16); if (text.length % 2) text = '0' + text;
  if (parseInt(text.slice(0, 2), 16) & 128) text = '00' + text;
  return forge.util.hexToBytes(text);
}
// Layout of a Kalkan-written container (shrouded key bag and certificate bags sharing
// friendlyName and localKeyId = SHA-1 of the public key bits) with modern protection.
export async function buildPkcs12(key, certificates, password) {
  if (!PASSWORD_RULE.test(password)) fail('PASSWORD_POLICY', PASSWORD_HINT);
  const leaf = certificateInfo(certificates[0]);
  const keyBits = (leaf.spki.value[1].bitStringContents || leaf.spki.value[1].value).slice(1);
  const localKeyId = forge.md.sha1.create().update(keyBits).digest().getBytes();
  const attributes = () => A.create(0, A.Type.SET, true, [attribute('1.2.840.113549.1.9.20', A.create(0, A.Type.BMPSTRING, false, bmp(forge.util.bytesToHex(localKeyId)))), attribute('1.2.840.113549.1.9.21', octet(localKeyId))]);
  const encrypted = forge.pki.encryptPrivateKeyInfo(await privateKeyInfo(key), password, { algorithm: 'aes256', prfAlgorithm: 'sha256', count: PKCS12_ITERATIONS, saltSize: 16 });
  const keyBag = seq(oid(forge.pki.oids.pkcs8ShroudedKeyBag), A.create(A.Class.CONTEXT_SPECIFIC, 0, true, [encrypted]), attributes());
  const certBags = certificates.map((raw, index) => seq(oid(forge.pki.oids.certBag), A.create(A.Class.CONTEXT_SPECIFIC, 0, true, [seq(oid(forge.pki.oids.x509Certificate), A.create(A.Class.CONTEXT_SPECIFIC, 0, true, [octet(raw)]))]), ...(index === 0 ? [attributes()] : [])));
  const data = bags => seq(oid(O.data), A.create(A.Class.CONTEXT_SPECIFIC, 0, true, [octet(der(seq(...bags)))]));
  const authSafe = der(seq(data([keyBag]), data(certBags)));
  const salt = forge.random.getBytesSync(32);
  const macKey = forge.pkcs12.generateKey(password, forge.util.createBuffer(salt), 3, PKCS12_ITERATIONS, 32, forge.md.sha256.create());
  const mac = forge.hmac.create(); mac.start(forge.md.sha256.create(), macKey); mac.update(authSafe);
  const macData = seq(seq(seq(oid('2.16.840.1.101.3.4.2.1'), A.create(0, A.Type.NULL, false, '')), octet(mac.digest().getBytes())), octet(salt), A.create(0, A.Type.INTEGER, false, integerBytes(PKCS12_ITERATIONS)));
  return bytes(der(seq(integer(3), seq(oid(O.data), A.create(A.Class.CONTEXT_SPECIFIC, 0, true, [octet(authSafe)])), macData)));
}

// Generates one key per requested parameter set and the matching PKCS#10 requests.
export async function generateRequest({ dn, email, keys: requested }, password, context) {
  if (!PASSWORD_RULE.test(password)) fail('PASSWORD_POLICY', PASSWORD_HINT);
  if (!Array.isArray(requested) || !requested.length) fail('GENKEY_UNKNOWN_ALG', 'Не указаны параметры ключа.');
  const keys = [];
  try {
    for (const params of requested) keys.push(await generateKey(keySpec(params)));
    const csrs = [];
    for (const key of keys) csrs.push(await createCsr(key, dn, { email }));
    const identities = await Promise.all(keys.map(key => keyIdentity(key.spki)));
    const sealed = await sealKeys(keys, password, `${context}|${identities.join(',')}`);
    return { pems: csrs.map(csrPem), identities, algorithms: keys.map(key => key.spec.label), sealed };
  } finally { keys.forEach(destroyKey); }
}

// Parses the certificates the portal hands over and links each end-entity certificate to
// a pending key by its public key. Nothing secret is needed for this step.
export async function inspectCertificates(certificates, pending, { anchors, now = Date.now() } = {}) {
  const parsed = certificates.map(raw => { try { return certificateInfo(raw); } catch { fail('CERTIFICATE_MALFORMED', 'Сайт передал сертификат, который не удалось разобрать.'); } });
  const authorities = parsed.filter(info => info.ca);
  const leaves = parsed.filter(info => !info.ca);
  if (!leaves.length) fail('NO_END_ENTITY_CERTIFICATE', 'Среди переданных сертификатов нет сертификата владельца ключа.');
  const result = [];
  for (const info of leaves) {
    const identity = await keyIdentity(info.spki);
    const record = pending.find(entry => entry.identities.includes(identity));
    const trust = await verifyChain(info, authorities, { now, ...(anchors ? { anchors } : {}) });
    result.push({ info, identity, recordId: record?.id ?? null, trust });
  }
  return { leaves: result, authorities };
}

export async function installCertificates(certificates, pending, password, options = {}) {
  const { leaves } = await inspectCertificates(certificates, pending, options);
  const files = [];
  for (const { info, identity, recordId, trust } of leaves) {
    if (!recordId) fail('CERTIFICATE_KEY_MISMATCH', 'Сертификат выпущен не для ключа, созданного в этом браузере. Установка остановлена.');
    if (!trust.trusted) fail('CERTIFICATE_UNTRUSTED', `Цепочка до корня НУЦ РК не подтверждена: ${trust.reason}`);
    if (info.keyUsage !== null && !(info.keyUsage & 192)) fail('CERTIFICATE_NO_DIGITAL_SIGNATURE', 'Сертификат не разрешает цифровую подпись.');
    if (info.unknownCritical.length) fail('CERTIFICATE_UNSUPPORTED', 'В сертификате есть неподдерживаемое критическое расширение.');
    // A restored backup may sit next to the original record: every record naming this key is tried.
    const failures = [];
    let file;
    for (const record of pending.filter(entry => entry.identities.includes(identity))) {
      try { file = await installFrom(record, identity, info, trust, password); break; }
      catch (error) { if (!(error instanceof IssuanceError)) throw error; failures.push(error); }
    }
    if (!file) throw failures.find(error => error.code === 'PASSWORD_OR_DAMAGED') || failures.at(-1);
    files.push(file);
  }
  return files;
}
async function installFrom(record, identity, info, trust, password) {
  const keys = await unsealKeys(record.sealed, password, `${record.id}|${record.identities.join(',')}`);
  try {
    let key;
    for (const candidate of keys) if (await keyIdentity(candidate.spki) === identity) key = candidate;
    if (!key) fail('CERTIFICATE_KEY_MISMATCH', 'Сертификат не соответствует ключу заявки.');
    await provePossession(key, info);
    // The verified intermediate CAs travel with the key; the root stays in the trust store.
    const intermediates = trust.certificates.slice(1).filter(cert => der(cert.issuer) !== der(cert.subject));
    return { recordId: record.id, slot: record.slot ?? record.id, identity, container: await buildPkcs12(key, [info, ...intermediates].map(cert => bytes(cert.raw)), password), certificate: info.summary };
  } finally { keys.forEach(destroyKey); }
}
