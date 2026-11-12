// Trust material pinned in the extension. Offline: each bundled NCA certificate matches its recorded SHA-256 and
// is not close to expiry. --online (scheduled CI): the published copies at pki.gov.kz are byte-identical to the
// bundled ones, and the signed NCALayer module catalog verifies to the bundled roots, is signed by the recorded
// NCALayer certificate, and still matches the snapshot in extension/modules/catalog.js. Any change fails the run
// for a manual review; trust is never updated automatically.
import { createHash } from 'node:crypto';
import { trustStore } from '../extension/crypto/trust-store.js';
import { certificateInfo } from '../extension/crypto/signer.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';
import { catalog, catalogEvidence } from '../extension/modules/catalog.js';

const DAY = 86400000;
// Bundled roots anchor every chain check; the catalog signer only signs the snapshot data shown in the module list.
const ROOT_DAYS = [365, 730], SIGNER_DAYS = [60, 365];
const online = process.argv.includes('--online');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const problems = [];
const days = notAfter => Math.floor((Date.parse(notAfter) - Date.now()) / DAY);

function expiry(label, notAfter, [fail, warn]) {
  const left = days(notAfter);
  if (left < fail) problems.push(`${label}: expires ${notAfter.slice(0, 10)} (${left} days)`);
  else console.log(`${left < warn ? 'WARN' : 'OK'}: ${label} valid until ${notAfter.slice(0, 10)} (${left} days)`);
}

async function download(url) {
  const response = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0 (Tegin trust check)' }, signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

for (const entry of trustStore) {
  const raw = Buffer.from(entry.certificate, 'base64');
  if (sha256(raw) !== entry.sha256) problems.push(`${entry.name}: bundled certificate does not match its recorded SHA-256`);
  expiry(entry.name, certificateInfo(new Uint8Array(raw)).summary.notAfter, ROOT_DAYS);
  if (online) {
    try {
      const published = await download(entry.source);
      if (sha256(published) !== entry.sha256) problems.push(`${entry.name}: ${entry.source} now serves ${sha256(published)}, bundled ${entry.sha256}`);
      else console.log(`OK: ${entry.source} serves the bundled certificate`);
    } catch (error) {
      problems.push(`${entry.name}: ${error.message}`);
    }
  }
}

if (online) {
  try {
    const raw = await download(catalogEvidence.source);
    const cms = await verifyCms(raw);
    const signer = cms.signers[0];
    if (cms.signers.length !== 1 || !signer.trust.trusted) problems.push(`catalog: signature does not verify to the bundled NCA roots (${signer?.trust.reason})`);
    if (signer.trust.path[0].fingerprint !== catalogEvidence.signerFingerprint) problems.push(`catalog: signed by ${signer.trust.path[0].fingerprint}, recorded ${catalogEvidence.signerFingerprint}`);
    expiry(`NCALayer catalog signer (${signer.certificate.summary.name})`, signer.certificate.summary.notAfter, SIGNER_DAYS);
    const bundles = JSON.parse(new TextDecoder().decode(cms.content)).ncalayer.bundles;
    const key = entry => `${entry.symname} ${entry.version} ${entry.hash}`;
    const known = new Map(catalog.map(entry => [entry.symname, entry])), current = new Map(bundles.map(entry => [entry.symname, entry]));
    const added = bundles.filter(entry => !known.has(entry.symname)).map(key);
    const removed = catalog.filter(entry => !current.has(entry.symname)).map(key);
    const changed = bundles.filter(entry => known.has(entry.symname) && key(known.get(entry.symname)) !== key(entry)).map(entry => `${key(known.get(entry.symname))} -> ${entry.version} ${entry.hash}`);
    if (sha256(raw) === catalogEvidence.sha256) console.log(`OK: catalog unchanged since ${catalogEvidence.date} (${bundles.length} entries)`);
    else if (!added.length && !removed.length && !changed.length) console.log(`OK: catalog re-signed (${sha256(raw).slice(0, 16)}…), the ${bundles.length} entries are unchanged`);
    else problems.push(`catalog: differs from the ${catalogEvidence.date} snapshot (${catalogEvidence.count} -> ${bundles.length} entries)${[['added', added], ['removed', removed], ['changed', changed]].filter(([, list]) => list.length).map(([label, list]) => `\n  ${label}: ${list.join('; ')}`).join('')}`);
  } catch (error) {
    problems.push(`catalog: ${error.message}`);
  }
}

if (problems.length) {
  for (const problem of problems) console.error(`REVIEW: ${problem}`);
  process.exitCode = 1;
} else console.log(`Trust check passed${online ? ' (online)' : ''}.`);
