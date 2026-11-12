// Independent CAdES-LT/LTA validation of extension output with EU DSS (ETSI EN 319 122-1 baseline).
// Synthetic RSA PKI, OCSP, CRL and TSA only. Requirements: DSS_VALIDATOR=<dir> with lib/ and classes/
// (see tests/pades-crosscheck.mjs).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { longTermHarness, editSignedData } from './helpers/long-term.js';
import { signLongTerm, verifyLongTerm, addArchiveTimestamp, addValidationData } from '../extension/crypto/cades-lt.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';

const dss = process.env.DSS_VALIDATOR;
if (!dss) throw new Error('Set DSS_VALIDATOR to the EU DSS validator directory.');
const folder = mkdtempSync(join(tmpdir(), 'tegin-cades-lt-crosscheck-'));
const file = name => join(folder, name);
const h = await longTermHarness();
writeFileSync(file('root.pem'), h.pki.root.pem);
const data = new TextEncoder().encode('Синтетический документ Tegin для CAdES-LTA');
writeFileSync(file('document.txt'), data);
let passed = 0;

function runDss(name, cms, detached) {
  writeFileSync(file(name), cms);
  const args = ['-cp', `${dss}/classes:${dss}/lib/*`, 'Validate', file(name), file('root.pem'), ...(detached ? [file('document.txt')] : [])];
  const [result, ...extra] = JSON.parse(execFileSync('java', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })).signatures;
  assert.equal(extra.length, 0);
  return result;
}
const archives = result => result.timestamps.filter(item => item.type === 'ARCHIVE_TIMESTAMP');
function expectPassed(name, cms, { format, archiveCount, detached = false }) {
  const result = runDss(name, cms, detached);
  assert.equal(result.indication, 'TOTAL_PASSED', `${name}: ${JSON.stringify(result)}`);
  assert.equal(result.format, format, name);
  assert.ok(result.intact && result.valid && result.bLevelValid, name);
  assert.deepEqual(result.errors, [], name);
  assert.ok(result.revocations >= 3, `${name}: signer and TSA revocation data are embedded`);
  const [signatureStamp] = result.timestamps.filter(item => item.type === 'SIGNATURE_TIMESTAMP');
  assert.equal(signatureStamp.indication, 'PASSED', name);
  assert.equal(archives(result).length, archiveCount, name);
  for (const item of archives(result)) {
    assert.equal(item.archiveType, 'CAdES_V3', name);
    assert.equal(item.atsHashIndexVersion, 'ATS_HASH_INDEX_V3', name);
    assert.ok(item.indication === 'PASSED' && item.imprintIntact && item.signatureValid && item.atsHashIndexValid, `${name}: ${JSON.stringify(item)}`);
    assert.deepEqual(item.atsHashIndexMessages, [], name);
  }
  passed++;
  return result;
}
// DSS always reports the broken hash index; its default policy keeps the LTA verdict when the removed
// item is still reachable elsewhere (a TSA certificate inside the token), so the verdict is returned.
function expectArchiveBroken(name, cms) {
  const result = runDss(name, cms);
  const [archive] = archives(result);
  assert.ok(archive && (!archive.imprintIntact || !archive.atsHashIndexValid), `${name}: ${JSON.stringify(archive)}`);
  passed++;
  return { format: result.format, messages: archive.atsHashIndexMessages };
}
async function expectRejected(name, promise, pattern) {
  await assert.rejects(promise, pattern, name);
  passed++;
}
const sign = (level, options = {}) => signLongTerm(h.signer, data, { level, signerPath: h.signerPath, evidence: h.evidence, requester: h.requester, ...options });

try {
  const { cms: lt } = await sign('lt');
  expectPassed('lt.p7s', lt, { format: 'CAdES-BASELINE-LT', archiveCount: 0 });
  assert.equal((await verifyLongTerm(lt, { anchors: h.anchors })).archives.length, 0);

  const { cms: lta, archive: firstArchive } = await sign('lta');
  expectPassed('lta.p7s', lta, { format: 'CAdES-BASELINE-LTA', archiveCount: 1 });
  assert.equal((await verifyLongTerm(lta, { anchors: h.anchors })).archives.length, 1);

  const { cms: detached } = await sign('lta', { encapsulate: false });
  expectPassed('lta-detached.p7s', detached, { format: 'CAdES-BASELINE-LTA', archiveCount: 1, detached: true });
  await verifyLongTerm(detached, { detached: data, anchors: h.anchors });
  await verifyCms(detached, { detached: data, anchors: h.anchors });

  // Re-archiving: fresh status for the first archive TSA, then a second archive-time-stamp-v3.
  const archiveStatus = await h.evidence(firstArchive.certificates);
  let renewed = addValidationData(lta, archiveStatus.evidence);
  ({ cms: renewed } = await addArchiveTimestamp(renewed, { requester: h.requester }));
  expectPassed('lta-twice.p7s', renewed, { format: 'CAdES-BASELINE-LTA', archiveCount: 2 });
  assert.equal((await verifyLongTerm(renewed, { anchors: h.anchors })).archives.length, 2);

  // Validation data added after the archive stamp is allowed (EN 319 122-1 5.5.3).
  const extended = addValidationData(lta, { certificates: [h.pki.responder.der] });
  expectPassed('lta-extended.p7s', extended, { format: 'CAdES-BASELINE-LTA', archiveCount: 1 });
  await verifyLongTerm(extended, { anchors: h.anchors });

  const withoutOcsp = editSignedData(lta, ({ crls }) => crls.splice(crls.findIndex(item => item.type === 1), 1));
  const ocspFinding = expectArchiveBroken('lta-ocsp-removed.p7s', withoutOcsp);
  assert.notEqual(ocspFinding.format, 'CAdES-BASELINE-LTA', JSON.stringify(ocspFinding));
  await expectRejected('ocsp removed', verifyLongTerm(withoutOcsp, { anchors: h.anchors }), /изменены или удалены/);

  const withoutCertificate = editSignedData(lta, ({ certificates }) => certificates.pop());
  const certificateFinding = expectArchiveBroken('lta-certificate-removed.p7s', withoutCertificate);
  console.log('certificate removed, DSS:', certificateFinding.format, certificateFinding.messages.join('; '));
  await expectRejected('certificate removed', verifyLongTerm(withoutCertificate, { anchors: h.anchors }), /изменены или удалены/);

  const changed = editSignedData(lta, ({ content }) => { content.value = content.value.replace('Tegin', 'Tegim'); });
  const changedResult = runDss('lta-content.p7s', changed);
  assert.equal(changedResult.indication, 'TOTAL_FAILED', JSON.stringify(changedResult));
  assert.equal(changedResult.intact, false);
  passed++;
  await expectRejected('content changed', verifyCms(changed, { anchors: h.anchors }), /./);

  console.log(`CAdES-LT/LTA crosscheck: ${passed} checks passed (EU DSS 6.5.1)`);
} finally {
  h.destroy();
  rmSync(folder, { recursive: true, force: true });
}
