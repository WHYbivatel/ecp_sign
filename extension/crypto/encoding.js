import forge from 'node-forge';
export { binary, bytes, base64, unbase64, utf8 } from '../lib/bytes.js';
import { binary } from '../lib/bytes.js';

export { forge };
export const A = forge.asn1;
export const O = {
  data: '1.2.840.113549.1.7.1', signedData: '1.2.840.113549.1.7.2',
  rsa: '1.2.840.113549.1.1.1', sha256: '2.16.840.1.101.3.4.2.1',
  gost2004: '1.2.398.3.10.1.1.1.1', gost512: '1.2.398.3.10.1.1.2.2',
  gost256: '1.2.398.3.10.1.1.2.1', hash2004: '1.2.398.3.10.1.3.1',
  hash512: '1.2.398.3.10.1.3.3', hash256: '1.2.398.3.10.1.3.2',
  sig2004: '1.2.398.3.10.1.1.1.2', sig512: '1.2.398.3.10.1.1.2.3.2',
  sig256: '1.2.398.3.10.1.1.2.3.1'
};
export const seq = (...items) => A.create(A.Class.UNIVERSAL, A.Type.SEQUENCE, true, items);
export const set = (...items) => A.create(A.Class.UNIVERSAL, A.Type.SET, true,
  items.sort((left, right) => der(left) < der(right) ? -1 : der(left) > der(right) ? 1 : 0));
export const oid = value => A.create(0, A.Type.OID, false, A.oidToDer(value).getBytes());
export const octet = value => A.create(0, A.Type.OCTETSTRING, false, typeof value === 'string' ? value : binary(value));
export const integer = value => A.create(0, A.Type.INTEGER, false, String.fromCharCode(value));
export const context = (tag, items) => A.create(A.Class.CONTEXT_SPECIFIC, tag, true, items);
export const der = value => A.toDer(value).getBytes();
export const algorithm = value => seq(oid(value), A.create(0, A.Type.NULL, false, ''));
export const oidValue = node => A.derToOid(node.value);
export function parse(value) { return A.fromDer(typeof value === 'string' ? value : binary(value), { strict: true, parseAllBytes: true }); }
