import { buildOcspRequest, verifyOcspResponse } from './ocsp.js';
import { parseCrl, verifyCrl, statusFromCrls } from './crl.js';

// Revocation status at a past moment (the signature time-stamp) from evidence embedded in a CAdES-LT/LTA
// signature, offline. Follows the past-validation idea of ETSI EN 319 102-1 5.6.2.4 in a reduced form:
// - evidence is verified as of its own issuance (OCSP producedAt, CRL thisUpdate) against the issuer in
//   the path, the same responder and CRL rules as the online check (ocsp.js, crl.js);
// - its signing certificate must still have been valid when the evidence is proven to exist: the time
//   of the earliest verified archive time-stamp that covers it, otherwise the present;
// - "good" needs fresh evidence: issued at or after the moment, or (EN 319 102-1 5.2.5.4 without a
//   freshness constraint: nextUpdate - thisUpdate is the accepted age) published before the moment with
//   the moment inside thisUpdate..nextUpdate; a revocation dated at or before the moment is conclusive
//   from any verified evidence (certificateHold excepted);
// - everything else is indeterminate, with the reason.
// Paths come from verifyChain at the moment, trust anchor last; the anchor itself is not checked.

export const HISTORY_STATES = Object.freeze({ good: 'good', revoked: 'revoked', indeterminate: 'indeterminate' });
const SILENT = new Set(['OCSP_MISMATCH', 'OCSP_RESPONDER', 'CRL_ISSUER']);

function proofTimes(evidence, archives, now) {
  const times = new Map();
  for (const archive of archives) for (const index of archive.revocationItems || []) {
    const time = Date.parse(archive.time);
    if (!times.has(index) || time < times.get(index)) times.set(index, time);
  }
  return item => times.has(item.index) ? { at: times.get(item.index), by: 'archive' } : { at: now, by: 'present' };
}

async function candidates(certificate, issuer, evidence, proof, codes) {
  const found = [];
  const serial = Uint8Array.from(certificate.serial.value, char => char.charCodeAt(0));
  for (const item of evidence) {
    try {
      if (item.kind === 'ocsp') {
        for (const hash of ['SHA-256', 'SHA-1']) {
          const request = await buildOcspRequest(certificate, issuer, { hash, nonce: new Uint8Array(0) });
          let result;
          try { result = await verifyOcspResponse(item.raw, request, issuer, { historical: true }); }
          catch (error) { if (error.code === 'OCSP_MISMATCH') continue; throw error; }
          found.push({ ...result, signerNotAfter: Date.parse(result.signerNotAfter), proof: proof(item) });
          break;
        }
      } else if (item.kind === 'crl') {
        const crl = parseCrl(item.raw);
        await verifyCrl(crl, issuer, { now: crl.thisUpdate, kind: 'full' });
        found.push({ ...statusFromCrls(crl, null, serial), signerNotAfter: Date.parse(issuer.summary.notAfter), proof: proof(item) });
      }
    } catch (error) { if (!SILENT.has(error.code)) codes.add(error.code || 'EVIDENCE_MALFORMED'); }
  }
  return found;
}

function judge(found, moment, codes) {
  const proven = found.filter(item => item.proof.at <= item.signerNotAfter);
  if (found.length && !proven.length) codes.add('EVIDENCE_NOT_PROVEN');
  const revokedBefore = proven.find(item => item.status === 'revoked' && item.reason !== 'certificateHold' && Date.parse(item.revocationTime) <= moment);
  if (revokedBefore) return { state: HISTORY_STATES.revoked, source: revokedBefore.source, thisUpdate: revokedBefore.thisUpdate, revocationTime: revokedBefore.revocationTime, reason: revokedBefore.reason, provenBy: revokedBefore.proof.by };
  const freshness = item => Date.parse(item.thisUpdate) >= moment ? 'after' : item.nextUpdate && moment <= Date.parse(item.nextUpdate) ? 'window' : null;
  const fresh = proven.filter(freshness).sort((left, right) => (freshness(left) === 'after' ? 0 : 1) - (freshness(right) === 'after' ? 0 : 1));
  if (proven.length && !fresh.length) codes.add('EVIDENCE_BEFORE_TIME');
  const decisive = fresh.find(item => item.status === 'good' || (item.status === 'revoked' && Date.parse(item.revocationTime) > moment));
  if (decisive) return { state: HISTORY_STATES.good, source: decisive.source, thisUpdate: decisive.thisUpdate, freshness: freshness(decisive), provenBy: decisive.proof.by,
    ...(decisive.status === 'revoked' ? { revokedLater: decisive.revocationTime } : {}) };
  if (fresh.length) codes.add('STATUS_UNKNOWN');
  if (!found.length && !codes.size) codes.add('NO_EVIDENCE');
  return { state: HISTORY_STATES.indeterminate, code: [...codes].at(-1) || 'NO_EVIDENCE', codes: [...codes] };
}

// paths: [{ role: 'signer' | 'timestamp', certificates, time }]; evidence: embeddedRevocation(cms);
// archives: verified archive time-stamps with revocationItems (verifyLongTerm).
export async function historicalRevocation({ paths, evidence, archives = [], now = Date.now() }) {
  const proof = proofTimes(evidence, archives, now);
  const certificates = [];
  for (const { role, certificates: path, time } of paths) {
    const moment = Date.parse(time);
    for (let index = 0; index < path.length - 1; index++) {
      const codes = new Set();
      const found = await candidates(path[index], path[index + 1], evidence, proof, codes);
      certificates.push({ role, name: path[index].summary.name, ca: index > 0, time, ...judge(found, moment, codes) });
    }
  }
  const state = certificates.some(entry => entry.state === HISTORY_STATES.revoked) ? HISTORY_STATES.revoked
    : certificates.length && certificates.every(entry => entry.state === HISTORY_STATES.good) ? HISTORY_STATES.good : HISTORY_STATES.indeterminate;
  return { computed: true, state, time: paths.find(path => path.role === 'signer')?.time ?? null, certificates };
}
