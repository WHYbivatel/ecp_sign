import { checkSignerConstraints, isUnifiedNcaCertificate } from './constraints.js';
import { openContainer } from './signer.js';
import { signCms } from './cms.js';
import { inspectPdf, signPades, checkPadesKey } from './pades.js';
import { signXml, verifyCreatedXml } from './xml.js';
import { base64, unbase64, utf8 } from './encoding.js';
import { verifyChain } from './chain.js';
import { forge, bytes as binaryBytes } from './encoding.js';
import { verifyCms, describeCms } from './cms-verify.js';
import { verifyEmbeddedTimestamp, requestTimestamp, TSA_PROFILES } from './timestamp.js';
import { signLongTerm, verifyLongTerm, checkLongTermKey, LT_OIDS } from './cades-lt.js';
import { A, oidValue } from './encoding.js';
import { RevocationChecker, blocks, summarize, assessHistory, isCurrent, STATES } from './revocation.js';
import { generateRequest, inspectCertificates, installCertificates, IssuanceError } from './issuance.js';
import { trustStore } from './trust-store.js';
import { changeContainerPassword } from './password-change.js';

// Test builds only (scripts/build.mjs with TEGIN_TEST_ISSUANCE_ANCHORS): synthetic roots accepted
// for issued certificates next to the bundled NCA roots.
const testIssuanceAnchors = typeof __TEGIN_TEST_ISSUANCE_ANCHORS__ !== 'undefined' ? __TEGIN_TEST_ISSUANCE_ANCHORS__ : null;
const issuanceTrust = () => testIssuanceAnchors
  ? { anchors: [...trustStore.filter(entry => entry.anchor).map(entry => unbase64(entry.certificate)), ...testIssuanceAnchors.map(unbase64)] } : {};
const publicTrust = trust => ({ trusted: trust.trusted, reason: trust.reason, path: trust.path });

let signer;
let busy = false;
let trust, revocationPath, checker;
function checkConstraints(request) {
  checkSignerConstraints(signer.info, request, trust);
  if (request.format === 'pades') checkPadesKey(signer);
  if (request.longTerm) {
    checkLongTermKey(signer);
    if (!trust.ncaTrusted) throw Object.assign(new Error('CAdES-LT и CAdES-LTA создаются только для сертификата с цепочкой НУЦ РК: для неё известны службы OCSP и CRL.'), { code: 'CADES_LT' });
  }
}
const revocation = () => checker ||= new RevocationChecker();
const notChecked = reason => summarize([], new Date().toISOString(), reason);
const REVOCATION_MESSAGES = {
  revoked: subject => `${subject} отозван. Операция заблокирована.`,
  unknown: subject => `${subject}: служба НУЦ сообщила, что статус неизвестен. Операция заблокирована.`,
  unavailable: () => 'Проверка отзыва недоступна: службы НУЦ не ответили или их ответ не прошёл проверку. Операция не выполнена, повторите позже.',
  'not-checked': () => 'Не все сертификаты цепочки удалось проверить на отзыв. Операция не выполнена.'
};
function revocationFailure(result, subject) {
  if (!blocks(result)) return null;
  const error = new Error(REVOCATION_MESSAGES[result.state](subject));
  error.code = `REVOCATION_${result.state.replace('-', '_').toUpperCase()}`; error.revocation = true;
  return error;
}
// A fresh check whose evidence already lapsed proves nothing: it counts as unavailable.
async function checkPath(path) {
  const result = path ? await revocation().checkPath(path) : notChecked('untrusted');
  return blocks(result) || isCurrent(result) ? result : { ...result, state: STATES.unavailable, reason: 'expired' };
}
// Chain built to the bundled NCA roots when possible: only that path has pinned revocation sources.
async function checkSigner() {
  trust.revocation = await checkPath(revocationPath);
  const failure = revocationFailure(trust.revocation, 'Сертификат ключа');
  if (failure) throw failure;
}
async function checkStamp(stamp) {
  stamp.revocation = await checkPath(stamp.certificates);
  const failure = revocationFailure(stamp.revocation, 'Сертификат службы меток времени НУЦ');
  if (failure) throw failure;
}
// CAdES-LT/LTA embeds the OCSP/CRL evidence itself, so it is obtained after the signature time-stamp
// and must be good for every certificate of the path.
async function longTermEvidence(path, role) {
  const result = await revocation().checkPath(path, { fresh: true });
  const current = blocks(result) || isCurrent(result) ? result : { ...result, state: STATES.unavailable, reason: 'expired' };
  const failure = revocationFailure(current, role === 'signer' ? 'Сертификат ключа' : 'Сертификат службы меток времени НУЦ');
  if (failure) throw failure;
  if (current.state !== STATES.good || !current.required || !(current.evidence?.ocsp.length || current.evidence?.crls.length)) throw revocationFailure({ state: STATES.notChecked, required: true }, '');
  if (role === 'signer') trust.revocation = current;
  return current;
}
// Signing many documents and checking TSA chains can outlast OCSP or CRL evidence; it has to
// apply at the moment the signature leaves the worker.
async function confirmCurrent(timestamps) {
  for (let pass = 0; pass < 3; pass++) {
    const stale = timestamps.filter(stamp => !isCurrent(stamp.revocation));
    if (isCurrent(trust.revocation) && !stale.length) return;
    if (!isCurrent(trust.revocation)) await checkSigner();
    for (const stamp of stale) await checkStamp(stamp);
  }
  throw revocationFailure({ state: STATES.unavailable, required: true }, 'Сертификат ключа');
}
self.onmessage = async ({ data }) => {
  if (busy) return;
  busy = true;
  try {
    if (data.kind === 'open') {
      signer?.destroy(); signer = null; trust = undefined; revocationPath = null;
      try { signer = await openContainer(new Uint8Array(data.container), data.password); }
      finally { new Uint8Array(data.container).fill(0); data.password = ''; }
      const request = data.request || {};
      const chain = request.signerParams?.chain;
      const anchors = chain?.length ? chain.map(pem => binaryBytes(forge.pem.decode(pem)[0].body)) : undefined;
      trust = await verifyChain(signer.info, signer.certificates, { anchors });
      trust.scope = anchors ? 'site' : 'nca';
      const ncaChain = anchors ? await verifyChain(signer.info, signer.certificates) : trust;
      trust.ncaTrusted = ncaChain.trusted;
      revocationPath = ncaChain.trusted ? ncaChain.certificates : trust.trusted ? trust.certificates : null;
      trust.revocation = notChecked('pending');
      signer.info.summary.unifiedNca = isUnifiedNcaCertificate(signer.info, trust);
      signer.info.summary.fingerprint = [...new Uint8Array(await crypto.subtle.digest('SHA-256', binaryBytes(signer.info.raw)))].map(value => value.toString(16).padStart(2, '0')).join('');
      checkConstraints(request);
      await checkSigner();
      self.postMessage({ kind: 'opened', certificate: { ...signer.info.summary, trust } });
    } else if (data.kind === 'inspect') {
      const raw = new Uint8Array(data.signature);
      try { self.postMessage({ kind: 'inspected', ...describeCms(raw) }); }
      finally { raw.fill(0); }
      self.close();
    } else if (data.kind === 'inspect-pdf') {
      const raw = new Uint8Array(data.document);
      try { self.postMessage({ kind: 'pdf-inspected', ...await inspectPdf(raw) }); }
      finally { raw.fill(0); }
      self.close();
    } else if (data.kind === 'verify') {
      const raw = new Uint8Array(data.signature);
      const original = data.original ? new Uint8Array(data.original) : undefined;
      try {
        const verified = await verifyCms(raw, { detached: original });
        const timestamps = [], signers = [];
        for (const signer of verified.signers) {
          const unsigned = signer.info.value.find(node => node.tagClass === A.Class.CONTEXT_SPECIFIC && node.type === 1);
          const stamps = (unsigned?.value || []).filter(attribute => oidValue(attribute.value[0]) === '1.2.840.113549.1.9.16.2.14');
          if (stamps.length > 1 || stamps[0]?.value[1].value.length > 1) throw new Error('Неоднозначные метки времени в подписи.');
          let stamp = null;
          if (stamps.length) {
            const verifiedStamp = await verifyEmbeddedTimestamp(stamps[0].value[1].value[0], signer.signature);
            // Network only on the user's explicit request; local verification stays offline by default.
            stamp = { time: verifiedStamp.time, authority: verifiedStamp.authority,
              revocation: data.checkRevocation ? await revocation().checkPath(verifiedStamp.certificates) : notChecked('not-requested') };
            timestamps.push(stamp);
          }
          if ((unsigned?.value || []).some(attribute => oidValue(attribute.value[0]) === LT_OIDS.archiveTimestampV3)) {
            for (const archive of (await verifyLongTerm(raw, { detached: original })).archives) timestamps.push({ kind: 'archive', time: archive.time, authority: archive.authority,
              revocation: data.checkRevocation ? await revocation().checkPath(archive.certificates) : notChecked('not-requested') });
          }
          const current = !data.checkRevocation ? notChecked('not-requested') : signer.trust.trusted ? await revocation().checkPath(signer.trust.certificates) : notChecked('untrusted');
          signers.push({ ...signer.certificate.summary, trust: { ...signer.trust, revocation: current }, history: assessHistory(current, stamp) });
        }
        const content = verified.content.slice();
        self.postMessage({ kind: 'verified', attached: verified.attached, signers, timestamps, content: content.buffer }, [content.buffer]);
      } finally { raw.fill(0); original?.fill(0); }
      self.close();
    } else if (data.kind === 'issue-generate') {
      let password = data.password; data.password = '';
      const result = await generateRequest(data.request, password, data.context);
      password = '';
      self.postMessage({ kind: 'issue-generated', ...result });
      self.close();
    } else if (data.kind === 'issue-inspect') {
      const { leaves } = await inspectCertificates(data.certificates.map(unbase64), data.pending, issuanceTrust());
      self.postMessage({ kind: 'issue-inspected', leaves: leaves.map(({ info, recordId, trust }) => ({ recordId, certificate: info.summary, trust: publicTrust(trust) })) });
      self.close();
    } else if (data.kind === 'issue-install') {
      let password = data.password; data.password = '';
      const files = await installCertificates(data.certificates.map(unbase64), data.pending, password, issuanceTrust());
      password = '';
      const containers = files.map(file => file.container.buffer);
      self.postMessage({ kind: 'issue-installed', files: files.map(({ recordId, slot, container, certificate }) => ({ recordId, slot, container: container.buffer, certificate })) }, containers);
      self.close();
    } else if (data.kind === 'change-password') {
      const raw = new Uint8Array(data.container);
      let oldPassword = data.oldPassword, newPassword = data.newPassword;
      data.oldPassword = data.newPassword = '';
      try {
        const changed = await changeContainerPassword(raw, oldPassword, newPassword);
        oldPassword = newPassword = '';
        self.postMessage({ kind: 'password-changed', container: changed.container.buffer, certificate: changed.certificate, protection: changed.protection }, [changed.container.buffer]);
      } finally { raw.fill(0); oldPassword = newPassword = ''; }
      self.close();
    } else if (data.kind === 'sign') {
      if (!signer) throw new Error('Сначала откройте ключ.');
      const request = data.request;
      if (Date.now() < Date.parse(signer.info.summary.notBefore) || Date.now() > Date.parse(signer.info.summary.notAfter)) throw new Error('Срок действия сертификата ещё не наступил или уже истёк.');
      checkConstraints(request);
      if (!isCurrent(trust.revocation)) await checkSigner();
      const results = [];
      const timestamps = [];
      for (const doc of request.documents) {
        const bytes = request.decode ? unbase64(doc) : utf8(doc);
        try {
          if (request.format === 'xml') {
            const original = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
            const signedXml = await signXml(signer, original, request.xpath);
            if (!await verifyCreatedXml(signer, signedXml, { original, ...request.xpath })) throw new Error('Не удалось проверить созданную XML-подпись.');
            results.push(signedXml);
          }
          else if (request.format === 'pades') results.push(base64(await signPades(signer, bytes)));
          else if (request.longTerm) {
            const detached = request.encapsulate ? undefined : bytes;
            const created = await signLongTerm(signer, bytes, { level: request.longTerm, encapsulate: request.encapsulate, signerPath: revocationPath,
              evidence: longTermEvidence, requester: data => requestTimestamp(data, TSA_PROFILES.rsa) });
            await verifyCms(created.cms, { detached });
            const embedded = await verifyLongTerm(created.cms, { detached });
            if (embedded.archives.length !== (request.longTerm === 'lta' ? 1 : 0)) throw new Error('Не удалось проверить созданную долгосрочную подпись.');
            timestamps.push(created.stamp, ...(created.archive ? [Object.assign(created.archive, { kind: 'archive' })] : []));
            results.push(base64(created.cms));
          }
          else if (request.format === 'raw') results.push(base64(request.digested ? await signer.signDigest(bytes) : await signer.sign(bytes)));
          else results.push(base64(await signCms(signer, bytes, { encapsulate: request.encapsulate, cades: request.cades, digested: request.digested,
            timestamp: request.timestamp, onTimestamp: stamp => timestamps.push(stamp) })));
        } finally { bytes.fill(0); }
      }
      // The token is verified to the NCA root; its certificates must also be unrevoked now, otherwise
      // the stamp would not prove the signing time later (Rules 500/НҚ p.14, p.17).
      for (const stamp of timestamps) await checkStamp(stamp);
      await confirmCurrent(timestamps);
      self.postMessage({ kind: 'signed', result: results, timestamps: timestamps.map(({ time, authority, revocation, kind }) => ({ time, authority, revocation, kind })) });
      signer.destroy(); signer = null;
      self.close();
    }
  } catch (error) {
    const certificate = data.kind === 'open' ? (signer ? { ...signer.info.summary, trust } : error.certificate) : undefined;
    const diagnostic = (data.kind === 'open' && !signer) || data.kind === 'change-password' ? error.diagnostic : undefined;
    const known = error.revocation || error instanceof IssuanceError || (data.kind === 'change-password' && typeof error.code === 'string');
    self.postMessage({ kind: 'error', message: error.message || 'Операция не выполнена.', certificate, code: known ? error.code : diagnostic?.code, diagnostic });
    if (data.kind === 'change-password') self.close();
    signer?.destroy(); signer = null;
  } finally { busy = false; }
};
