import { certificateInfo } from './signer.js';
import { trustStore } from './trust-store.js';
import { bytes, der, oidValue, unbase64 } from './encoding.js';
import { verifySignedBytes, digestForOid } from './verification.js';

const hex = bytes => [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
const fingerprint = async cert => hex(await crypto.subtle.digest('SHA-256', bytes(cert.raw)).then(value => new Uint8Array(value)));

export async function verifyChain(leaf, additional = [], { anchors, now = Date.now(), includeBundled = true } = {}) {
  const bundled = includeBundled ? trustStore.map(entry => ({ ...entry, info: certificateInfo(unbase64(entry.certificate)) })) : [];
  const trusted = anchors === undefined ? bundled.filter(entry => entry.anchor).map(entry => entry.info) : anchors.map(certificateInfo);
  const candidates = [...additional, ...bundled.map(entry => entry.info), ...trusted].map(cert => cert.certificate ? cert : certificateInfo(cert));
  const anchorHashes = new Set(await Promise.all(trusted.map(fingerprint)));
  let failure = 'Цепочка до доверенного корня не найдена.';
  const valid = info => {
    if (now < Date.parse(info.summary.notBefore) || now > Date.parse(info.summary.notAfter)) { failure = 'Срок одного из сертификатов цепочки истёк или ещё не наступил.'; return false; }
    if (info.unknownCritical.length) { failure = 'В цепочке есть неподдерживаемое критическое расширение.'; return false; }
    return true;
  };
  async function walk(current, visited, caBelow) {
    if (!valid(current) || visited.length > 7) return null;
    const hash = await fingerprint(current);
    if (visited.includes(hash)) return null;
    if (anchorHashes.has(hash)) return [current];
    for (const issuer of candidates) {
      if (!issuer.ca || (issuer.keyUsage !== null && !(issuer.keyUsage & 4)) || der(current.issuer) !== der(issuer.subject)) continue;
      if (current.authorityKeyId && issuer.subjectKeyId && current.authorityKeyId !== issuer.subjectKeyId) continue;
      const below = caBelow + (current.ca ? 1 : 0);
      if (issuer.pathLength !== null && below > issuer.pathLength) continue;
      const sigBits = current.certificate.value[2].bitStringContents || current.certificate.value[2].value;
      if (!await verifySignedBytes(issuer, bytes(der(current.certificate.value[0])), bytes(sigBits.slice(1)), oidValue(current.certificate.value[1].value[0]))) continue;
      const tail = await walk(issuer, [...visited, hash], below);
      if (tail) return [current, ...tail];
    }
    return null;
  }
  try {
    const path = await walk(leaf.certificate ? leaf : certificateInfo(leaf), [], 0);
    if (path) return { trusted: true, revocation: 'not-checked', reason: 'Цепочка доверия проверена локально.',
      path: await Promise.all(path.map(async info => ({ name: info.summary.name, fingerprint: await fingerprint(info) }))) };
  } catch { failure = 'Не удалось проверить алгоритм или структуру цепочки.'; }
  return { trusted: false, revocation: 'not-checked', reason: failure, path: [] };
}
