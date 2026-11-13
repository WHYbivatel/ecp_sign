// Independent CAdES-LT/LTA validation of extension output with EU DSS (ETSI EN 319 122-1 baseline).
// Synthetic RSA PKI, OCSP, CRL and TSA only. Requirements: DSS_VALIDATOR=<dir> with lib/ and classes/
// (see tests/pades-crosscheck.mjs).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { longTermHarness, editSignedData, evaluateHistorical, signatureStamp } from './helpers/long-term.js';
import { ocspResponse, parseOcspRequest, crl } from './helpers/pki.js';
import { buildOcspRequest } from '../extension/crypto/ocsp.js';
import { signCms } from '../extension/crypto/cms.js';
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

  // Historical revocation status (crypto/historical.js) against DSS past-signature validation.
  assert.equal((await evaluateHistorical(h, lt)).state, 'good');
  assert.equal((await evaluateHistorical(h, renewed)).state, 'good');
  passed++;
  // CAdES-T with hand-made evidence: the signer's OCSP answer says revoked, before or after the stamp.
  const stamped = await signCms(h.signer, data, { cades: true, timestamp: true, timestampRequester: h.requester, signingTime: new Date() });
  const stamp = await signatureStamp(stamped, h.anchors);
  const [leaf, ca] = h.signerPath, tsaPath = stamp.certificates;
  const answer = async (certificate, issuer, options) => ocspResponse(parseOcspRequest((await buildOcspRequest(certificate, issuer)).body), { signer: h.pki.responder, nonce: null, ...options });
  const withEvidence = async leafOptions => addValidationData(stamped, {
    certificates: [...h.signerPath, ...tsaPath].map(item => item.raw).map(raw => Uint8Array.from(raw, char => char.charCodeAt(0))),
    crls: [crl(h.pki.root, { number: 3 })],
    ocsp: [await answer(leaf, ca, leafOptions), await answer(tsaPath[0], tsaPath[1], { thisUpdate: Date.now() })]
  });
  const stampTime = Date.parse(stamp.time);
  const comparisons = [];
  for (const [name, options, expected] of [
    ['revoked-after.p7s', { status: 'revoked', revocationTime: stampTime + 2000, reason: 1, thisUpdate: stampTime + 3000 }, 'good'],
    ['revoked-before.p7s', { status: 'revoked', revocationTime: stampTime - 3600000, reason: 1, thisUpdate: stampTime + 3000 }, 'revoked']
  ]) {
    const cms = await withEvidence(options);
    const tegin = await evaluateHistorical(h, cms);
    assert.equal(tegin.state, expected, `${name}: ${JSON.stringify(tegin.certificates)}`);
    const result = runDss(name, cms);
    comparisons.push(`${name}: Tegin ${tegin.state}, DSS ${result.indication}${result.subIndication ? '/' + result.subIndication : ''}`);
    if (expected === 'revoked') assert.notEqual(result.indication, 'TOTAL_PASSED', `${name}: ${JSON.stringify(result)}`);
    else assert.equal(result.indication, 'TOTAL_PASSED', `${name}: ${JSON.stringify(result)}`);
    passed++;
  }
  const bare = await evaluateHistorical(h, stamped);
  assert.equal(bare.state, 'indeterminate');
  const bareResult = runDss('t-only.p7s', stamped);
  comparisons.push(`t-only.p7s: Tegin ${bare.state}, DSS ${bareResult.indication}${bareResult.subIndication ? '/' + bareResult.subIndication : ''}`);
  assert.notEqual(bareResult.indication, 'TOTAL_PASSED', JSON.stringify(bareResult));
  passed++;
  console.log('historical status, Tegin vs DSS:\n  ' + comparisons.join('\n  '));

  console.log(`CAdES-LT/LTA crosscheck: ${passed} checks passed (EU DSS 6.5.1)`);
} finally {
  h.destroy();
  rmSync(folder, { recursive: true, force: true });
}
