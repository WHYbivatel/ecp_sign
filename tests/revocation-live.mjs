import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { forge, binary, unbase64 } from '../extension/crypto/encoding.js';
import { certificateInfo } from '../extension/crypto/signer.js';
import { certificateParts } from '../extension/crypto/ocsp.js';
import { trustStore } from '../extension/crypto/trust-store.js';
import { RevocationChecker, memoryStore } from '../extension/crypto/revocation.js';
import { profileFor } from '../extension/crypto/revocation-profiles.js';

// Explicit live check against the NCA services, public material only: the NCA timestamp service
// certificate, placeholder certificates with random never-issued serials, and the published CRLs.
// No personal certificate is used; serial numbers of revoked certificates are never printed.
const nca = name => certificateInfo(unbase64(trustStore.find(entry => entry.name === name).certificate));
const tsa = certificateInfo(new Uint8Array(readFileSync(new URL('fixtures/revocation/nca-tsa.cer', import.meta.url))));
const fingerprint = async info => Buffer.from(await crypto.subtle.digest('SHA-256', Uint8Array.from(info.raw, char => char.charCodeAt(0)))).toString('hex');
function placeholder(issuer) {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const certificate = forge.pki.createCertificate();
  certificate.serialNumber = '4' + forge.util.bytesToHex(forge.random.getBytesSync(19));
  certificate.publicKey = keys.publicKey;
  certificate.validity.notBefore = new Date(); certificate.validity.notAfter = new Date(Date.now() + 86400000);
  certificate.setSubject([{ name: 'commonName', value: 'Tegin placeholder (never issued)' }]);
  certificate.sign(keys.privateKey, forge.md.sha256.create());
  const asn = forge.pki.certificateToAsn1(certificate);
  asn.value[0].value[3] = forge.asn1.fromDer(binary(certificateParts(issuer.raw).subject));
  return certificateInfo(new Uint8Array(Buffer.from(forge.asn1.toDer(asn).getBytes(), 'binary')));
}
const brief = result => ({ state: result.state, certificates: result.certificates.map(({ name, role, state, source, detail, thisUpdate, nextUpdate, code, errors }) => ({ name, role, state, source, detail, thisUpdate, nextUpdate, code, errors })) });

const checker = new RevocationChecker({ store: memoryStore() });
const started = performance.now();
const chain = await checker.checkPath([tsa, nca('nca_gost_2022'), nca('root_gost_2022')]);
console.log('TSA chain', JSON.stringify(brief(chain)));
assert.equal(chain.state, 'good');
assert.deepEqual(chain.certificates.map(entry => entry.source), ['ocsp', 'crl']);

for (const [name, rootName] of [['nca_rsa_2022', 'root_rsa_2020'], ['nca_gost_2022', 'root_gost_2022']]) {
  const result = await checker.checkPath([placeholder(nca(name)), nca(name), nca(rootName)]);
  console.log(`never-issued serial under ${name}`, JSON.stringify(brief(result)));
  assert.equal(result.state, 'unknown'); assert.equal(result.certificates[0].detail, 'not-issued');
}

// CRL path for the NCA RSA issuer (full ~100 KB + delta). The GOST full CRL (~20 MB) only with --gost-crl.
for (const name of ['nca_rsa_2022', ...(process.argv.includes('--gost-crl') ? ['nca_gost_2022'] : [])]) {
  const issuer = nca(name), certificate = placeholder(issuer), errors = [];
  const begin = performance.now();
  const result = await checker.viaCrl(certificate, issuer, profileFor(await fingerprint(issuer)), undefined, errors);
  console.log(`CRL ${name}`, JSON.stringify({ status: result?.status, source: result?.source, thisUpdate: result?.thisUpdate, nextUpdate: result?.nextUpdate, errors, ms: Math.round(performance.now() - begin) }));
  assert.equal(result.status, 'good'); assert.equal(result.source, 'crl+delta');
}
console.log(`Live revocation check completed in ${Math.round(performance.now() - started)} ms.`);
