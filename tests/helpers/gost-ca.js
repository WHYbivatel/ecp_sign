import GostSign from '../../extension/vendor/gost/sign.cjs';
import GostDigest from '../../extension/vendor/gost/digest.cjs';
import { A, O, forge, seq, set, oid, octet, integer, context, algorithm, der, parse, bytes, binary } from '../../extension/crypto/encoding.js';

// Disposable GOST 34.10-2015 (512) hierarchy shaped like the NUC one: root, issuing CA, and
// end-entity certificates issued from a PKCS#10 request with its subject and key copied verbatim.
const SCHEME = { version: 2012, length: 512, namedCurve: 'T-512-A' };
const KEY = seq(oid(O.gost512), seq(oid('1.2.398.3.10.1.1.2.2.1'), oid(O.hash512)));
const DAY = 86400000;
let serials = 0x7000;

const date = value => A.create(0, A.Type.GENERALIZEDTIME, false, A.dateToGeneralizedTime(new Date(value)));
const name = text => seq(set(seq(oid('2.5.4.3'), A.create(0, A.Type.UTF8, false, forge.util.encodeUtf8(text)))), set(seq(oid('2.5.4.6'), A.create(0, A.Type.PRINTABLESTRING, false, 'KZ'))));
const bits = value => A.create(0, A.Type.BITSTRING, false, value);
const extension = (id, value, critical) => seq(oid(id), ...(critical ? [A.create(0, A.Type.BOOLEAN, false, '\xff')] : []), octet(der(value)));
const serialNumber = () => A.create(0, A.Type.INTEGER, false, forge.util.hexToBytes((++serials).toString(16).padStart(6, '0')));

function sign(issuerKey, tbs) {
  const hash = new GostDigest({ version: 2012, length: 512, sBox: 'D-TEST' }).digest(bytes(der(tbs)));
  const signature = new Uint8Array(new GostSign(SCHEME).sign(issuerKey, hash));
  return seq(tbs, algorithm(O.sig512), bits('\0' + binary(signature)));
}
function certificate({ subject, spki, issuer, signerKey, extensions, notBefore, notAfter }) {
  const tbs = seq(context(0, [integer(2)]), serialNumber(), algorithm(O.sig512), issuer, seq(date(notBefore), date(notAfter)), subject, spki, context(3, [seq(...extensions)]));
  const cert = sign(signerKey, tbs);
  const raw = bytes(der(cert));
  return { der: raw, base64: forge.util.encode64(der(cert)), pem: `-----BEGIN CERTIFICATE-----\n${forge.util.encode64(der(cert)).replace(/.{1,64}/g, '$&\n')}-----END CERTIFICATE-----\n` };
}

export function gostAuthority(label, parent) {
  const pair = new GostSign(SCHEME).generateKey();
  const privateKey = new Uint8Array(pair.privateKey);
  const spki = seq(KEY, bits('\0' + der(octet(new Uint8Array(pair.publicKey)))));
  const subject = name(label);
  const issued = certificate({ subject, spki, issuer: parent ? parent.subject : subject, signerKey: parent ? parent.privateKey : privateKey,
    extensions: [extension('2.5.29.19', seq(A.create(0, A.Type.BOOLEAN, false, '\xff')), true), extension('2.5.29.15', bits('\x01\x06'), true)],
    notBefore: Date.now() - DAY, notAfter: Date.now() + 365 * DAY });
  return { label, subject, privateKey, ...issued };
}

export function gostHierarchy(prefix = 'Tegin synthetic NUC') {
  const root = gostAuthority(`${prefix} root`);
  const ca = gostAuthority(`${prefix} issuing CA`, root);
  return { root, ca };
}

// End-entity certificate for the request's subject and public key.
export function issueFromCsr(ca, csr, { keyUsage = '\x06\xc0', eku = ['1.3.6.1.5.5.7.3.4'], notBefore = Date.now() - DAY, notAfter = Date.now() + 365 * DAY, spki } = {}) {
  const info = parse(csr).value[0];
  const extensions = [
    ...(keyUsage ? [extension('2.5.29.15', bits(keyUsage), true)] : []),
    ...(eku.length ? [extension('2.5.29.37', seq(...eku.map(oid)))] : [])
  ];
  return certificate({ subject: info.value[1], spki: spki || info.value[2], issuer: ca.subject, signerKey: ca.privateKey, extensions, notBefore, notAfter });
}
