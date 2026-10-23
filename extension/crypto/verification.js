import { O, forge, bytes, binary, der, parse } from './encoding.js';
import { GostDigest, GostSign, gostEngine } from './signer.js';

const shaOids = { '1.3.14.3.2.26': 'SHA-1', [O.sha256]: 'SHA-256', '2.16.840.1.101.3.4.2.2': 'SHA-384', '2.16.840.1.101.3.4.2.3': 'SHA-512' };
const rsaSignatures = { '1.2.840.113549.1.1.5': '1.3.14.3.2.26', '1.2.840.113549.1.1.11': O.sha256,
  '1.2.840.113549.1.1.12': '2.16.840.1.101.3.4.2.2', '1.2.840.113549.1.1.13': '2.16.840.1.101.3.4.2.3' };
export const equalBytes = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
export async function digestForOid(id, data) {
  if (shaOids[id]) return new Uint8Array(await crypto.subtle.digest(shaOids[id], data));
  if (![O.hash2004, O.hash256, O.hash512].includes(id)) throw new Error('Алгоритм хеширования не поддерживается.');
  return new Uint8Array(new GostDigest({ version: id === O.hash2004 ? 1994 : 2012,
    length: id === O.hash512 ? 512 : 256, sBox: 'D-TEST' }).digest(data));
}

// All arithmetic below handles public points only; signing stays in the bundled engine.
function validPoint(raw, scheme) {
  const params = scheme.curve || GostSign.curveParameters(scheme.namedCurve);
  const p = BigInt(params.p), a = BigInt(params.a), b = BigInt(params.b), q = BigInt(params.q);
  const size = scheme.length / 8;
  if (raw.length !== 2 * size) return false;
  const number = data => [...data].reverse().reduce((n, value) => n * 256n + BigInt(value), 0n);
  const x = number(raw.subarray(0, size)), y = number(raw.subarray(size));
  const mod = value => ((value % p) + p) % p;
  if (x >= p || y >= p || mod(y * y) !== mod(x * x * x + a * x + b)) return false;
  const invert = value => {
    let oldR = p, r = mod(value), oldT = 0n, t = 1n;
    while (r) { const quotient = oldR / r; [oldR, r] = [r, oldR - quotient * r]; [oldT, t] = [t, oldT - quotient * t]; }
    if (oldR !== 1n) throw new Error('Invalid public point');
    return mod(oldT);
  };
  function add(left, right) {
    if (!left) return right; if (!right) return left;
    if (left.x === right.x && mod(left.y + right.y) === 0n) return null;
    const slope = left.x === right.x ? mod((3n * left.x * left.x + a) * invert(2n * left.y)) : mod((right.y - left.y) * invert(right.x - left.x));
    const rx = mod(slope * slope - left.x - right.x);
    return { x: rx, y: mod(slope * (left.x - rx) - left.y) };
  }
  let result = null, point = { x, y }, scalar = q;
  while (scalar) { if (scalar & 1n) result = add(result, point); point = add(point, point); scalar >>= 1n; }
  return result === null;
}

export async function verifySignedBytes(info, data, signature, signatureOid, hashOid) {
  if (info.keyOid === O.rsa) {
    const hash = signatureOid === O.rsa ? (hashOid || O.sha256) : rsaSignatures[signatureOid];
    if (!hash || (hashOid && hash !== hashOid) || !shaOids[hash]) return false;
    const publicKey = await crypto.subtle.importKey('spki', bytes(der(info.spki)), { name: 'RSASSA-PKCS1-v1_5', hash: shaOids[hash] }, false, ['verify']);
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signature, data);
  }
  if (signatureOid !== info.algorithm.signature || (hashOid && hashOid !== info.algorithm.hash)) return false;
  const bitString = info.spki.value[1].bitStringContents || info.spki.value[1].value;
  const point = bytes(parse(bitString.slice(1)).value);
  if (!validPoint(point, info.algorithm) || signature.length !== point.length) return false;
  return gostEngine(info.algorithm).verify(point, signature, await digestForOid(info.algorithm.hash, data));
}
