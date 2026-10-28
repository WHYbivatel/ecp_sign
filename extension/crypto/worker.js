import { checkSignerConstraints } from './constraints.js';
import { openContainer } from './signer.js';
import { signCms } from './cms.js';
import { signXml } from './xml.js';
import { base64, unbase64, utf8 } from './encoding.js';
import { verifyChain } from './chain.js';
import { forge, bytes as binaryBytes } from './encoding.js';
import { verifyCms, describeCms } from './cms-verify.js';
import { verifyEmbeddedTimestamp } from './timestamp.js';
import { A, oidValue } from './encoding.js';

let signer;
let busy = false;
let trust;
function checkConstraints(request) { checkSignerConstraints(signer.info, request, trust); }
self.onmessage = async ({ data }) => {
  if (busy) return;
  busy = true;
  try {
    if (data.kind === 'open') {
      signer?.destroy(); signer = null; trust = undefined;
      try { signer = await openContainer(new Uint8Array(data.container), data.password); }
      finally { new Uint8Array(data.container).fill(0); data.password = ''; }
      const request = data.request || {};
      const chain = request.signerParams?.chain;
      const anchors = chain?.length ? chain.map(pem => binaryBytes(forge.pem.decode(pem)[0].body)) : undefined;
      trust = await verifyChain(signer.info, signer.certificates, { anchors });
      trust.scope = anchors ? 'site' : 'nca';
      signer.info.summary.fingerprint = [...new Uint8Array(await crypto.subtle.digest('SHA-256', binaryBytes(signer.info.raw)))].map(value => value.toString(16).padStart(2, '0')).join('');
      checkConstraints(request);
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
        const timestamps = [];
        for (const signer of verified.signers) {
          const unsigned = signer.info.value.find(node => node.tagClass === A.Class.CONTEXT_SPECIFIC && node.type === 1);
          const stamps = (unsigned?.value || []).filter(attribute => oidValue(attribute.value[0]) === '1.2.840.113549.1.9.16.2.14');
          if (stamps.length > 1 || stamps[0]?.value[1].value.length > 1) throw new Error('Неоднозначные метки времени в подписи.');
          if (stamps.length) {
            const stamp = await verifyEmbeddedTimestamp(stamps[0].value[1].value[0], signer.signature);
            timestamps.push({ time: stamp.time, authority: stamp.authority });
          }
        }
        const content = verified.content.slice();
        self.postMessage({ kind: 'verified', attached: verified.attached, signers: verified.signers.map(value => ({ ...value.certificate.summary, trust: value.trust })),
          timestamps, content: content.buffer }, [content.buffer]);
      } finally { raw.fill(0); original?.fill(0); }
      self.close();
    } else if (data.kind === 'sign') {
      if (!signer) throw new Error('Сначала откройте ключ.');
      const request = data.request;
      if (Date.now() > Date.parse(signer.info.summary.notAfter)) throw new Error('Срок сертификата истёк.');
      checkConstraints(request);
      const results = [];
      const timestamps = [];
      for (const doc of request.documents) {
        const bytes = request.decode ? unbase64(doc) : utf8(doc);
        try {
          if (request.format === 'xml') results.push(await signXml(signer, new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
          else if (request.format === 'raw') results.push(base64(request.digested ? await signer.signDigest(bytes) : await signer.sign(bytes)));
          else results.push(base64(await signCms(signer, bytes, { encapsulate: request.encapsulate, cades: request.cades, digested: request.digested,
            timestamp: request.timestamp, onTimestamp: stamp => timestamps.push(stamp) })));
        } finally { bytes.fill(0); }
      }
      self.postMessage({ kind: 'signed', result: results, timestamps });
      signer.destroy(); signer = null;
      self.close();
    }
  } catch (error) {
    const certificate = data.kind === 'open' ? (signer ? { ...signer.info.summary, trust } : error.certificate) : undefined;
    self.postMessage({ kind: 'error', message: error.message || 'Операция не выполнена.', certificate });
    signer?.destroy(); signer = null;
  } finally { busy = false; }
};
