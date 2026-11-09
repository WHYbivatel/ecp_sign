import { checkSignerConstraints, isUnifiedNcaCertificate } from './constraints.js';
import { openContainer } from './signer.js';
import { signCms } from './cms.js';
import { signXml, verifyCreatedXml } from './xml.js';
import { base64, unbase64, utf8 } from './encoding.js';
import { verifyChain } from './chain.js';
import { forge, bytes as binaryBytes } from './encoding.js';
import { verifyCms, describeCms } from './cms-verify.js';
import { verifyEmbeddedTimestamp } from './timestamp.js';
import { A, oidValue } from './encoding.js';
import { RevocationChecker, blocks, summarize, assessHistory, REVOCATION_MAX_AGE } from './revocation.js';

let signer;
let busy = false;
let trust, revocationPath, checker;
function checkConstraints(request) { checkSignerConstraints(signer.info, request, trust); }
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
// Chain built to the bundled NCA roots when possible: only that path has pinned revocation sources.
async function checkSigner() {
  trust.revocation = revocationPath ? await revocation().checkPath(revocationPath) : notChecked('untrusted');
  const failure = revocationFailure(trust.revocation, 'Сертификат ключа');
  if (failure) throw failure;
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
          const current = !data.checkRevocation ? notChecked('not-requested') : signer.trust.trusted ? await revocation().checkPath(signer.trust.certificates) : notChecked('untrusted');
          signers.push({ ...signer.certificate.summary, trust: { ...signer.trust, revocation: current }, history: assessHistory(current, stamp) });
        }
        const content = verified.content.slice();
        self.postMessage({ kind: 'verified', attached: verified.attached, signers, timestamps, content: content.buffer }, [content.buffer]);
      } finally { raw.fill(0); original?.fill(0); }
      self.close();
    } else if (data.kind === 'sign') {
      if (!signer) throw new Error('Сначала откройте ключ.');
      const request = data.request;
      if (Date.now() < Date.parse(signer.info.summary.notBefore) || Date.now() > Date.parse(signer.info.summary.notAfter)) throw new Error('Срок действия сертификата ещё не наступил или уже истёк.');
      checkConstraints(request);
      if (trust.revocation.state !== 'not-checked' && Date.now() - Date.parse(trust.revocation.checkedAt) > REVOCATION_MAX_AGE) await checkSigner();
      const results = [];
      const timestamps = [];
      for (const doc of request.documents) {
        const bytes = request.decode ? unbase64(doc) : utf8(doc);
        try {
          if (request.format === 'xml') {
            const signedXml = await signXml(signer, new TextDecoder('utf-8', { fatal: true }).decode(bytes));
            if (request.moduleId === 'qiwi' && !await verifyCreatedXml(signer, signedXml)) throw new Error('Не удалось проверить созданную XML-подпись.');
            results.push(signedXml);
          }
          else if (request.format === 'raw') results.push(base64(request.digested ? await signer.signDigest(bytes) : await signer.sign(bytes)));
          else results.push(base64(await signCms(signer, bytes, { encapsulate: request.encapsulate, cades: request.cades, digested: request.digested,
            timestamp: request.timestamp, onTimestamp: stamp => timestamps.push(stamp) })));
        } finally { bytes.fill(0); }
      }
      // The token is verified to the NCA root; its certificates must also be unrevoked now, otherwise
      // the stamp would not prove the signing time later (Rules 500/НҚ p.14, p.17).
      for (const stamp of timestamps) {
        stamp.revocation = stamp.certificates ? await revocation().checkPath(stamp.certificates) : notChecked('untrusted');
        const failure = revocationFailure(stamp.revocation, 'Сертификат службы меток времени НУЦ');
        if (failure) throw failure;
      }
      self.postMessage({ kind: 'signed', result: results, timestamps: timestamps.map(({ time, authority, revocation }) => ({ time, authority, revocation })) });
      signer.destroy(); signer = null;
      self.close();
    }
  } catch (error) {
    const certificate = data.kind === 'open' ? (signer ? { ...signer.info.summary, trust } : error.certificate) : undefined;
    const diagnostic = data.kind === 'open' && !signer ? error.diagnostic : undefined;
    self.postMessage({ kind: 'error', message: error.message || 'Операция не выполнена.', certificate, code: error.revocation ? error.code : diagnostic?.code, diagnostic });
    signer?.destroy(); signer = null;
  } finally { busy = false; }
};
