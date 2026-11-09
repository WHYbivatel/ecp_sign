// Revocation sources are pinned to the SHA-256 fingerprint of the issuing CA certificate.
// URLs from certificates (AIA, CRL DP, Freshest CRL) are never fetched.
// Sources, retrieved 2026-11-09:
// - OCSP and NCA CRL/delta CRL: https://pki.gov.kz/ru/developers/ («Сервис OCSP», «Список отозванных сертификатов»).
// - Root CA CRLs: CRL Distribution Points of nca_rsa_2022 / nca_gost_2022 published at https://pki.gov.kz/ru/cert/.
//   The OCSP responder answers malformedRequest for these intermediate certificates.
export const OCSP_URL = 'http://ocsp.pki.gov.kz/';

const NCA_RSA_2022 = '84fb799a66140950818c056a5d9730acc2a7622cdd4ef0d47113b132fb892905';
const NCA_GOST_2022 = '32c7d233a42703a327f3025543a05b930e3f39a786c68dfa196baa86d5618524';
const ROOT_RSA_2020 = '9ba06354b626641715182e4d07c9dbaa1777720fa795d03174ffc68876535dcd';
const ROOT_GOST_2022 = 'af77725f8328bb24f89d81da3acdf7cee4324248538b7ba2cd2a860517fb9dca';

const KB = 1024, MB = 1024 * 1024;
export const LIMITS = Object.freeze({
  ocsp: { bytes: 64 * KB, timeout: 10000 },
  rootCrl: { bytes: 256 * KB, timeout: 15000 },
  delta: { bytes: 4 * MB, timeout: 30000 },
  // The NCA GOST full CRL was 20.3 MB on 2026-11-09.
  crl: { bytes: 48 * MB, timeout: 120000 }
});

const nca = name => ({
  ocsp: [OCSP_URL],
  crl: [`https://crl.pki.gov.kz/${name}.crl`, `https://crl1.pki.gov.kz/${name}.crl`],
  delta: [`https://crl.pki.gov.kz/${name.replace('nca_', 'nca_d_')}.crl`, `https://crl1.pki.gov.kz/${name.replace('nca_', 'nca_d_')}.crl`],
  crlLimit: 'crl',
  // Separate complete/delta number sequences; see deltaRelation in crl.js and
  // https://pki.gov.kz/docs/npa/CERTIFICATION%20PRACTICE_STATEMENT_v3.pdf (2.3).
  crlNumbering: 'nca'
});
const root = file => ({ ocsp: [], crl: [`https://crl.root.gov.kz/${file}`], delta: [], crlLimit: 'rootCrl', crlNumbering: 'rfc5280' });

const pinned = {
  [NCA_RSA_2022]: { name: 'НУЦ РК (RSA) 2022', ...nca('nca_rsa_2022') },
  [NCA_GOST_2022]: { name: 'НУЦ РК (GOST) 2022', ...nca('nca_gost_2022') },
  [ROOT_RSA_2020]: { name: 'КУЦ РК (RSA) 2020', ...root('rsa2020.crl') },
  [ROOT_GOST_2022]: { name: 'КУЦ РК (GOST) 2022', ...root('gost2015_2022.crl') }
};

// Test builds only (scripts/build.mjs with TEGIN_TEST_REVOCATION_ISSUERS): maps synthetic CA
// fingerprints to the same pinned NCA URLs. Production builds replace this with null.
const testIssuers = typeof __TEGIN_TEST_REVOCATION_ISSUERS__ !== 'undefined' ? __TEGIN_TEST_REVOCATION_ISSUERS__ : null;

export const ALLOWED_URLS = Object.freeze([...new Set(Object.values(pinned).flatMap(profile => [...profile.ocsp, ...profile.crl, ...profile.delta]))]);

export function profileFor(issuerFingerprint, extra = testIssuers) {
  if (pinned[issuerFingerprint]) return pinned[issuerFingerprint];
  const test = extra?.[issuerFingerprint];
  if (!test) return null;
  const base = test.like === 'root' ? root(test.rootCrl || 'rsa2020.crl') : nca(test.like || 'nca_rsa_2022');
  return { name: test.name || 'Тестовый УЦ', ...base };
}
