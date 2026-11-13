import { forge, bytes } from '../../extension/crypto/encoding.js';
import { openContainer } from '../../extension/crypto/signer.js';
import { verifyChain } from '../../extension/crypto/chain.js';
import { RevocationChecker, memoryStore } from '../../extension/crypto/revocation.js';
import { OCSP_URL } from '../../extension/crypto/revocation-profiles.js';
import { makeTimestampRequest, verifyTimestampResponse, TSA_PROFILES } from '../../extension/crypto/timestamp.js';
import { syntheticPki, ocspResponse, parseOcspRequest, crl, fingerprintOf } from './pki.js';
import { verifyLongTerm, embeddedRevocation, LT_OIDS } from '../../extension/crypto/cades-lt.js';
import { verifyEmbeddedTimestamp } from '../../extension/crypto/timestamp.js';
import { historicalRevocation } from '../../extension/crypto/historical.js';
import { parse } from '../../extension/crypto/encoding.js';
import { syntheticTsa } from './tsa.js';
import { PASSWORD } from './fixtures.js';

// Rewrites SignedData fields of a DER CMS for tamper tests. edit receives the forge nodes of the
// certificates [0] and crls [1] item lists and the eContent OCTET STRING (or null).
export function editSignedData(cms, edit) {
  const asn1 = forge.asn1.fromDer(forge.util.binary.raw.encode(cms));
  const signedData = asn1.value[1].value[0];
  const field = tag => signedData.value.find(item => item.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && item.type === tag);
  const encap = signedData.value[2].value[1];
  edit({ certificates: field(0).value, crls: field(1)?.value ?? [], content: encap ? encap.value[0] : null });
  return bytes(forge.asn1.toDer(asn1).getBytes());
}

// Synthetic CAdES-LT/LTA environment: RSA root, CA, signer, OCSP responder and a TSA issued by the
// same CA. The CA is mapped to the pinned NCA RSA profile, so the real RevocationChecker fetches
// OCSP and CRLs from the NCA URLs, which a fake network answers. Nothing leaves the process.
export async function longTermHarness({ ocspStatus = 'good' } = {}) {
  const pki = syntheticPki();
  const { root, ca, leaf, responder } = pki;
  const tsa = syntheticTsa({ issuer: ca });
  const testIssuers = { [await fingerprintOf(ca)]: { like: 'nca_rsa_2022' }, [await fingerprintOf(root)]: { like: 'root' } };
  const calls = [];
  const reply = (body, type) => new Response(body, { status: 200, headers: { 'content-type': type } });
  // One publication per CRL, as at a real CA between issues: two fetches within one test get the same bytes
  // even across a second boundary, so the embedded copies deduplicate.
  const published = new Map();
  const publication = (url, make) => { if (!published.has(url)) published.set(url, make()); return published.get(url); };
  const fetchImpl = async (url, init) => {
    calls.push(url);
    if (url === OCSP_URL) return reply(ocspResponse(parseOcspRequest(new Uint8Array(init.body)), { signer: responder, status: ocspStatus, revocationTime: Date.now() - 60000, reason: 1 }), 'application/ocsp-response');
    if (url === 'https://crl.root.gov.kz/rsa2020.crl') return reply(publication(url, () => crl(root, { number: 3 })), 'application/pkix-crl');
    if (url.endsWith('/nca_rsa_2022.crl')) return reply(publication(url, () => crl(ca, { number: 5 })), 'application/octet-stream');
    if (url.endsWith('/nca_d_rsa_2022.crl')) return reply(publication(url, () => crl(ca, { number: 6, deltaBase: 5 })), 'application/octet-stream');
    throw new Error('unexpected URL ' + url);
  };
  const checker = new RevocationChecker({ fetchImpl, store: memoryStore(), testIssuers });
  const anchors = [root.der];
  const p12 = forge.asn1.toDer(forge.pkcs12.toPkcs12Asn1(leaf.privateKey, [leaf.certificate, ca.certificate], PASSWORD, { algorithm: '3des' })).getBytes();
  const signer = await openContainer(bytes(p12), PASSWORD);
  const signerPath = (await verifyChain(signer.info, signer.certificates, { anchors })).certificates;
  let stamps = 0;
  const requester = async data => {
    stamps++;
    const request = await makeTimestampRequest(data, TSA_PROFILES.rsa);
    return verifyTimestampResponse(tsa.reply(request.body), request, { anchors });
  };
  const evidence = async path => {
    const result = await checker.checkPath(path, { fresh: true });
    if (result.state !== 'good' || !result.required) throw Object.assign(new Error(`revocation ${result.state}`), { revocation: result });
    return result;
  };
  return {
    pki, tsa, signer, signerPath, anchors, requester, evidence, calls, stampCount: () => stamps,
    destroy() { signer.destroy(); tsa.destroy(); }
  };
}

// The signature time-stamp of a CAdES-T/LT/LTA with its verified TSA path.
export async function signatureStamp(cms, anchors) {
  const asn1 = forge.asn1.fromDer(forge.util.binary.raw.encode(cms));
  const signerInfo = asn1.value[1].value[0].value.at(-1).value[0];
  const stamp = signerInfo.value.at(-1).value.find(item => forge.asn1.derToOid(item.value[0].value) === LT_OIDS.signatureTimestamp);
  const signature = signerInfo.value.find(item => item.type === forge.asn1.Type.OCTETSTRING && item.tagClass === 0);
  return verifyEmbeddedTimestamp(parse(forge.asn1.toDer(stamp.value[1].value[0]).getBytes()), forge.util.binary.raw.decode(signature.value), { anchors });
}
// What the extension worker computes for the verify screen (crypto/historical.js), for the harness signer.
export async function evaluateHistorical(h, cms, { detached } = {}) {
  const stamp = await signatureStamp(cms, h.anchors);
  const verified = await verifyLongTerm(cms, { detached, anchors: h.anchors });
  const signerPath = (await verifyChain(h.signer.info, h.signer.certificates, { anchors: h.anchors, now: Date.parse(stamp.time) })).certificates;
  return historicalRevocation({ paths: [{ role: 'signer', certificates: signerPath, time: stamp.time }, { role: 'timestamp', certificates: stamp.certificates, time: stamp.time }],
    evidence: embeddedRevocation(cms), archives: verified.archives });
}
