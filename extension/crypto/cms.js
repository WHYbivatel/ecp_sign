import { O, seq, set, oid, octet, integer, context, der, algorithm, bytes } from './encoding.js';
import { requestTimestamp } from './timestamp.js';

// RFC 5652 SignedData; requested RFC3161 timestamps are verified before inclusion.
export async function signCms(signer, data, { encapsulate = true, cades = false, digested = false, timestamp = false, timestampRequester = requestTimestamp, onTimestamp } = {}) {
  if (digested && encapsulate) throw new Error('Для готового хеша допустима только отдельная подпись.');
  const contentDigest = digested ? data : null;
  if (digested && data.length !== (signer.info.keyOid === O.rsa ? 32 : signer.info.algorithm.length / 8)) throw new Error('Длина хеша не соответствует алгоритму сертификата.');
  let attributes;
  if (cades || timestamp) {
    const certHash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(signer.info.raw)));
    attributes = set(
      seq(oid('1.2.840.113549.1.9.3'), set(oid(O.data))),
      seq(oid('1.2.840.113549.1.9.4'), set(octet(contentDigest || await signer.digest(data)))),
      // RFC 5035 SigningCertificateV2: SHA-256 is the omitted default algorithm.
      seq(oid('1.2.840.113549.1.9.16.2.47'), set(seq(seq(seq(octet(certHash))))))
    );
  }
  const signature = attributes ? await signer.sign(bytes(der(attributes))) : digested ? await signer.signDigest(data) : await signer.sign(data);
  const digestAlgorithm = algorithm(signer.info.algorithm.hash);
  const signerInfo = seq(integer(1), seq(signer.info.issuer, signer.info.serial),
    digestAlgorithm, ...(attributes ? [context(0, attributes.value)] : []),
    algorithm(signer.info.algorithm.signature), octet(signature));
  if (timestamp) {
    const stamp = await timestampRequester(signature);
    signerInfo.value.push(context(1, set(seq(oid('1.2.840.113549.1.9.16.2.14'), set(stamp.token))).value));
    onTimestamp?.({ time: stamp.time, authority: stamp.authority, revocation: stamp.revocation });
  }
  const content = seq(oid(O.data), ...(encapsulate ? [context(0, [octet(data)])] : []));
  const signedData = seq(integer(1), set(digestAlgorithm), content,
    context(0, [signer.info.certificate]), set(signerInfo));
  return bytes(der(seq(oid(O.signedData), context(0, [signedData]))));
}
