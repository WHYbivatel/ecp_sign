// Explicit opt-in live test: synthetic RSA signer, real NCA RSA TSA (policy 1.2.398.3.3.2.6.2) and real
// NCA OCSP/CRL for the TSA certificate, then EU DSS. Sends only hashes of synthetic data and public
// certificate serial numbers. Requires DSS_VALIDATOR (see tests/pades-crosscheck.mjs).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { longTermHarness } from './helpers/long-term.js';
import { signLongTerm, verifyLongTerm } from '../extension/crypto/cades-lt.js';
import { requestTimestamp, TSA_PROFILES } from '../extension/crypto/timestamp.js';
import { RevocationChecker, memoryStore } from '../extension/crypto/revocation.js';
import { trustStore } from '../extension/crypto/trust-store.js';
import { unbase64 } from '../extension/crypto/encoding.js';

const dss = process.env.DSS_VALIDATOR;
if (!dss) throw new Error('Set DSS_VALIDATOR to the EU DSS validator directory.');
const folder = mkdtempSync(join(tmpdir(), 'tegin-cades-lt-live-'));
const ncaRoot = trustStore.find(item => item.name === 'root_rsa_2020');
const pem = base64 => `-----BEGIN CERTIFICATE-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
const h = await longTermHarness();
const nca = new RevocationChecker({ store: memoryStore() });
const evidence = async (path, role) => {
  if (role !== 'timestamp') return h.evidence(path);
  const result = await nca.checkPath(path, { fresh: true });
  assert.ok(result.state === 'good' && result.required, `NCA TSA revocation: ${result.state}`);
  return result;
};
const anchors = [h.pki.root.der, unbase64(ncaRoot.certificate)];
const data = new TextEncoder().encode('Tegin public CAdES-LTA interoperability test; synthetic signer, no user data.');
try {
  const { cms, stamp, archive } = await signLongTerm(h.signer, data, { level: 'lta', signerPath: h.signerPath, evidence, requester: value => requestTimestamp(value, TSA_PROFILES.rsa) });
  const local = await verifyLongTerm(cms, { anchors });
  assert.equal(local.archives.length, 1);
  writeFileSync(join(folder, 'live.p7s'), cms);
  writeFileSync(join(folder, 'synthetic-root.pem'), h.pki.root.pem);
  writeFileSync(join(folder, 'nca-root.pem'), pem(ncaRoot.certificate));
  const [result] = JSON.parse(execFileSync('java', ['-cp', `${dss}/classes:${dss}/lib/*`, 'Validate', join(folder, 'live.p7s'),
    `${join(folder, 'synthetic-root.pem')},${join(folder, 'nca-root.pem')}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })).signatures;
  assert.equal(result.indication, 'TOTAL_PASSED', JSON.stringify(result));
  assert.equal(result.format, 'CAdES-BASELINE-LTA');
  for (const item of result.timestamps) assert.ok(item.indication === 'PASSED' && item.imprintIntact && item.signatureValid, JSON.stringify(item));
  const [ats] = result.timestamps.filter(item => item.type === 'ARCHIVE_TIMESTAMP');
  assert.ok(ats.atsHashIndexValid, JSON.stringify(ats));
  console.log(JSON.stringify({ format: result.format, indication: result.indication, revocations: result.revocations,
    signatureTimestamp: { time: stamp.time, authority: stamp.authority }, archiveTimestamp: { time: archive.time, authority: archive.authority },
    warnings: result.warnings }));
} finally {
  h.destroy();
  rmSync(folder, { recursive: true, force: true });
}
