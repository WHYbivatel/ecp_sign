import { nca256 } from './nca-curves.js';
import GostSign from '../vendor/gost/sign.cjs';
import GostDigest from '../vendor/gost/digest.cjs';
import { A, O, forge, parse, binary, bytes, der, oidValue, base64, utf8, seq, set } from './encoding.js';
import { inspectPkcs12 } from '../lib/pkcs12.js';

const schemes = {
  [O.gost512]: { label: 'ГОСТ 34.10-2015 · 512 бит', version: 2012, length: 512, namedCurve: 'T-512-A', curveOid: '1.2.398.3.10.1.1.2.2.1', hash: O.hash512, signature: O.sig512 },
  [O.gost256]: { label: 'ГОСТ 34.10-2015 · 256 бит', version: 2012, length: 256, curve: nca256, curveOid: '1.2.398.3.10.1.1.2.1.1', hash: O.hash256, signature: O.sig256 },
  [O.gost2004]: { label: 'ГОСТ 34.310-2004', version: 2001, length: 256, namedCurve: 'S-256-A', curveOid: '1.2.398.3.10.1.1.1.1.1', hash: O.hash2004, signature: O.sig2004 }
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
    if (value.type === A.Type.BMPSTRING) {
      let result = '';
      for (let i = 0; i < value.value.length; i += 2) result += String.fromCharCode(value.value.charCodeAt(i) * 256 + value.value.charCodeAt(i + 1));
      return result;
    }
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
  const algorithm = keyOid === O.rsa ? { label: 'RSA · SHA-256', hash: O.sha256, signature: O.rsa } : schemes[keyOid];
  if (!algorithm) throw new Error(`Алгоритм ключа ${keyOid} пока не поддерживается.`);
  if (keyOid !== O.rsa) {
    const params = spki.value[0].value[1];
    if (!params || params.type !== A.Type.SEQUENCE || oidValue(params.value[0]) !== algorithm.curveOid) throw new Error('Параметры ГОСТ не поддерживаются.');
  }
  return { certificate, spki, serial, issuer: tbs[offset + 2], subject,
    raw: der(certificate), keyOid, algorithm, eku, ekuCritical, keyUsage, ca, pathLength, subjectKeyId, authorityKeyId, unknownCritical,
    summary: {
      name: nameValue(subject, '2.5.4.3'), iin: /^IIN(\d{12})$/.exec(nameValue(subject, '2.5.4.5'))?.[1] || '',
      organization: nameValue(subject, '2.5.4.10'), issuer: nameValue(tbs[offset + 2], '2.5.4.3'),
      bin: /^BIN(\d{12})$/.exec(nameValue(subject, '2.5.4.11'))?.[1] || '',
      subjectDn: distinguishedName(subject), issuerDn: distinguishedName(tbs[offset + 2]),
      notBefore: dateValue(validity[0]).toISOString(), notAfter: dateValue(validity[1]).toISOString(),
      serialNumber: forge.util.bytesToHex(serial.value), algorithm: algorithm.label,
      certificate: forge.util.encode64(der(certificate))
    }
  };
}

function checkKdfLimits(node, depth = 0) {
  if (depth > 32) throw new Error('Слишком сложная структура контейнера.');
  if (!Array.isArray(node.value)) return;
  if (node.type === A.Type.SEQUENCE && node.value[0]?.type === A.Type.OID) {
    const id = oidValue(node.value[0]);
    if (id.startsWith('1.2.840.113549.1.12.1.') || id === '1.2.840.113549.1.5.12') {
      const iterations = node.value[1]?.value?.[1];
      if (iterations?.type === A.Type.INTEGER) validateIterations(iterations.value);
    }
  }
  for (const child of node.value) checkKdfLimits(child, depth + 1);
}
function validateIterations(value) {
  let count = 0;
  for (const char of value) count = count * 256 + char.charCodeAt(0);
  if (count < 1 || count > 1000000) throw new Error('Число итераций защиты контейнера не поддерживается.');
}

function fixedScalar(raw, size) {
  let scalar = bytes(raw);
  try {
    const inner = parse(raw);
    if ([A.Type.OCTETSTRING, A.Type.INTEGER].includes(inner.type) && typeof inner.value === 'string') scalar = bytes(inner.value);
  } catch { /* Common PKCS#8 representations include a bare scalar. */ }
  if (scalar.length === size + 1 && scalar[0] === 0) scalar = scalar.subarray(1);
  if (scalar.length !== size) throw new Error('Неподдерживаемое представление закрытого ключа ГОСТ.');
  return scalar.slice();
}

export async function openContainer(container, password, { now = Date.now() } = {}) {
  inspectPkcs12(container);
  const pfx = parse(container);
  if (pfx.value.length !== 3) throw new Error('Контейнер без проверки целостности не поддерживается.');
  checkKdfLimits(pfx);
  const authSafe = parse(pfx.value[1].value[1].value[0].value);
  for (const content of authSafe.value) {
    checkKdfLimits(content);
    if (oidValue(content.value[0]) === O.data) checkKdfLimits(parse(content.value[1].value[0].value));
  }
  const macIterations = pfx.value[2].value[2];
  if (macIterations) validateIterations(macIterations.value);
  let store;
  try { store = forge.pkcs12.pkcs12FromAsn1(pfx, true, password); }
  catch { throw new Error('Не удалось открыть контейнер: проверьте пароль и формат файла.'); }
  const bags = store.safeContents.flatMap(safe => safe.safeBags);
  const certBags = bags.filter(bag => bag.type === forge.pki.oids.certBag);
  const keyBags = bags.filter(bag => bag.type === forge.pki.oids.pkcs8ShroudedKeyBag || bag.type === forge.pki.oids.keyBag);
  for (const keyBag of keyBags) {
    for (const certBag of certBags) {
      let info;
      try { info = certificateInfo(certBag.cert ? forge.pki.certificateToAsn1(certBag.cert) : certBag.asn1); }
      catch { continue; }
      let key, publicKey;
      if (info.keyOid === O.rsa && keyBag.key) {
        if (keyBag.key.n.toString(16) !== certBag.cert?.publicKey.n.toString(16) || keyBag.key.e.toString(16) !== certBag.cert?.publicKey.e.toString(16)) continue;
        if (keyBag.key.n.bitLength() < 2048) throw new Error('RSA-ключи короче 2048 бит не поддерживаются.');
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
      if (now < Date.parse(info.summary.notBefore) || now > Date.parse(info.summary.notAfter)) {
        if (key instanceof Uint8Array) key.fill(0);
        throw new Error('Срок действия сертификата ещё не наступил или уже истёк.');
      }
      if (info.keyUsage !== null && !(info.keyUsage & 192)) throw new Error('Сертификат не разрешает цифровую подпись.');
      // The browser worker owns all decrypted data and is terminated after each operation.
      let rsaKey = info.keyOid === O.rsa ? keyBag.key : null;
      return {
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
        destroy() { if (key instanceof Uint8Array) key.fill(0); key = null; publicKey = null; rsaKey = null; }
      };
    }
  }
  throw new Error('В контейнере не найдена поддерживаемая пара ключа и сертификата.');
}

export { GostSign, GostDigest };
