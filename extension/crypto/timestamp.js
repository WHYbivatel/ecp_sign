import { A, O, seq, oid, octet, integer, algorithm, bytes, binary, der, parse, oidValue } from './encoding.js';
import { digestForOid, equalBytes } from './verification.js';
import { verifyCms, readCms } from './cms-verify.js';

export const TSA_URL = 'http://tsp.pki.gov.kz/';
export const TSA_POLICY = '1.2.398.3.3.2.6.4';
export async function makeTimestampRequest(signature) {
  const hashOid = O.hash512;
  const imprint = await digestForOid(hashOid, signature);
  const nonce = crypto.getRandomValues(new Uint8Array(16)); nonce[0] &= 127; nonce[0] |= 1;
  const body = bytes(der(seq(integer(1), seq(algorithm(hashOid), octet(imprint)), oid(TSA_POLICY),
    A.create(0, A.Type.INTEGER, false, binary(nonce)), A.create(0, A.Type.BOOLEAN, false, '\xff'))));
  return { body, hashOid, imprint, nonce, policy: TSA_POLICY };
}

export async function verifyTimestampResponse(raw, request, { anchors, now = Date.now(), historical = false } = {}) {
  if (raw.length > 256 * 1024) throw new Error('Ответ службы меток времени слишком большой.');
  const response = parse(raw);
  const status = response.value[0]?.value[0];
  if (status?.type !== A.Type.INTEGER || ![0, 1].includes(status.value.charCodeAt(0)) || status.value.length !== 1 || response.value.length !== 2) throw new Error('НУЦ не выдал метку времени.');
  const token = response.value[1];
  const tokenBytes = bytes(der(token));
  const claimedTime = historical ? A.generalizedTimeToDate(parse(readCms(tokenBytes).content).value[4].value).getTime() : now;
  const verified = await verifyCms(tokenBytes, { requireBinding: true, anchors, now: claimedTime });
  if (verified.contentType !== '1.2.840.113549.1.9.16.1.4' || verified.signers.length !== 1) throw new Error('Неверный тип метки времени.');
  const signer = verified.signers[0];
  if (!signer.trust.trusted || signer.certificate.eku.length !== 1 || signer.certificate.eku[0] !== '1.3.6.1.5.5.7.3.8' || !signer.certificate.ekuCritical) throw new Error('Сертификат службы меток времени не прошёл проверку.');
  const info = parse(verified.content).value;
  if (info[0].value !== '\x01' || oidValue(info[1]) !== request.policy || oidValue(info[2].value[0].value[0]) !== request.hashOid || !equalBytes(bytes(info[2].value[1].value), request.imprint)) throw new Error('Метка времени относится к другой подписи или политике.');
  const nonce = info.find((node, index) => index > 4 && node.type === A.Type.INTEGER && node.tagClass === 0);
  if (request.nonce && (!nonce || !equalBytes(bytes(nonce.value), request.nonce))) throw new Error('Служба вернула неверный nonce метки времени.');
  const time = A.generalizedTimeToDate(info[4].value).getTime();
  if (!Number.isFinite(time) || (historical ? time - now > 10 * 60 * 1000 : Math.abs(time - now) > 10 * 60 * 1000)) throw new Error('Время ответа НУЦ не соответствует текущей операции.');
  return { token, time: new Date(time).toISOString(), authority: signer.certificate.summary.name, revocation: 'not-checked' };
}

export async function verifyEmbeddedTimestamp(token, signature) {
  const info = parse(readCms(bytes(der(token))).content).value;
  const hashOid = oidValue(info[2].value[0].value[0]);
  const nonce = info.find((node, index) => index > 4 && node.type === A.Type.INTEGER && node.tagClass === 0);
  const request = { hashOid, imprint: await digestForOid(hashOid, signature), policy: TSA_POLICY, nonce: nonce ? bytes(nonce.value) : null };
  return verifyTimestampResponse(bytes(der(seq(seq(integer(0)), token))), request, { historical: true });
}

export async function requestTimestamp(signature) {
  const request = await makeTimestampRequest(signature);
  let response;
  try {
    response = await fetch(TSA_URL, { method: 'POST', headers: { 'Content-Type': 'application/timestamp-query', Accept: 'application/timestamp-reply' },
      body: request.body, credentials: 'omit', redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(20000) });
  } catch { throw new Error('Служба меток времени НУЦ недоступна. Подпись без запрошенной метки не выдавалась.'); }
  if (!response.ok || !response.headers.get('content-type')?.toLowerCase().includes('application/timestamp-reply')) throw new Error('НУЦ вернул неожиданный ответ службы времени.');
  const reader = response.body.getReader(); let length = 0; const chunks = [];
  while (true) {
    const { done, value } = await reader.read(); if (done) break;
    length += value.length; if (length > 256 * 1024) { await reader.cancel(); throw new Error('Ответ НУЦ слишком большой.'); }
    chunks.push(value);
  }
  const raw = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.length; }
  return verifyTimestampResponse(raw, request);
}
