// Texts of the signing window about revocation and signature verification. Pure functions, so the
// wording shown to the user is unit-tested (tests/verification-text.test.js).
export const dateTime = value => new Date(value).toLocaleString('ru-RU');
export const REVOCATION_LABELS = { good: 'Не отозван по актуальным данным', revoked: 'Отозван', unknown: 'Статус неизвестен', 'not-checked': 'Не проверялся', unavailable: 'Проверка недоступна' };
const REVOCATION_SOURCES = { ocsp: 'OCSP НУЦ', crl: 'список отзыва (CRL)', 'crl+delta': 'список отзыва (CRL + delta)' };
const REASONS = { keyCompromise: 'компрометация ключа', cACompromise: 'компрометация УЦ', affiliationChanged: 'изменение сведений', superseded: 'заменён', cessationOfOperation: 'прекращение деятельности', certificateHold: 'приостановлен', privilegeWithdrawn: 'отзыв полномочий', unspecified: 'причина не указана' };
const HASH_NAMES = { '2.16.840.1.101.3.4.2.1': 'SHA-256', '2.16.840.1.101.3.4.2.2': 'SHA-384', '2.16.840.1.101.3.4.2.3': 'SHA-512' };
const label = result => REVOCATION_LABELS[result?.state || 'not-checked'];

export function revocationNote(result) {
  if (!result) return '';
  const revoked = result.certificates?.find(entry => entry.state === 'revoked');
  if (result.state === 'good') return `Проверено ${dateTime(result.checkedAt)} по данным НУЦ для всей цепочки. Статус относится к моменту проверки.`;
  if (result.state === 'revoked') return `${revoked.role === 'ca' ? 'Сертификат УЦ в цепочке' : 'Сертификат'} отозван${revoked.revocationTime ? ' ' + dateTime(revoked.revocationTime) : ''}${revoked.reason ? ' (' + (REASONS[revoked.reason] || revoked.reason) + ')' : ''}. Операция заблокирована.`;
  if (result.state === 'unknown') return result.certificates.some(entry => entry.detail === 'not-issued') ? 'НУЦ сообщает, что такой сертификат им не выдавался. Операция заблокирована.' : 'Служба НУЦ не знает этот сертификат. Операция заблокирована.';
  if (result.state === 'unavailable') return 'Службы НУЦ не ответили или их ответ не прошёл проверку. Это не подтверждает, что сертификат действителен. Повторите позже.';
  if (result.reason === 'untrusted') return 'Цепочка доверия не подтверждена, поэтому статус отзыва проверить не у кого.';
  if (result.reason === 'not-requested') return 'Онлайн-проверка отзыва не запрашивалась.';
  if (result.reason === 'pending') return 'Проверка отзыва не выполнялась: операция остановлена раньше.';
  return 'Для УЦ этой цепочки нет проверенных адресов служб отзыва. Подтверждайте операцию, только если доверяете этому сертификату.';
}
export function revocationTechnical(result) {
  if (!result?.certificates?.length) return label(result);
  return result.certificates.map(entry => `${entry.name}: ${REVOCATION_LABELS[entry.state]}${entry.source ? ' · ' + REVOCATION_SOURCES[entry.source] : ''}${entry.thisUpdate ? ' · данные от ' + dateTime(entry.thisUpdate) : ''}${entry.code ? ' · ' + entry.code : ''}`).join('\n');
}
// Relation of the current revocation data to a verified time-stamp; never a status at that moment.
export function historyNote(history) {
  if (!history) return '';
  if (history.relation === 'revoked-after-timestamp') return `Сертификат отозван ${dateTime(history.revocationTime)}, позже метки времени ${dateTime(history.timestamp)}: метка подтверждает, что подпись существовала до отзыва.`;
  if (history.relation === 'revoked-before-timestamp') return `Сертификат отозван ${dateTime(history.revocationTime)}, раньше метки времени ${dateTime(history.timestamp)}: на момент метки он уже был отозван.`;
  if (history.relation === 'signing-time-unproven') return `Сертификат отозван${history.revocationTime ? ' ' + dateTime(history.revocationTime) : ''}. В подписи нет метки времени, поэтому момент подписания не подтверждён и относительно отзыва не определён.`;
  return '';
}

export const HISTORICAL_NOT_COMPUTED = 'Статус отзыва на момент меток: не вычислялся. Вложенные ответы OCSP и списки отзыва сохранены в подписи и сверены с архивными метками, но Tegin не вычисляет по ним состояние сертификатов в момент метки.';

const NOT_COMPUTED = {
  algorithm: 'Статус отзыва на момент метки: не вычислялся. Это делается только для подписей RSA: для ГОСТ нет независимого валидатора с казахстанскими OID.',
  untrusted: 'Статус отзыва на момент метки: не вычислялся. Цепочку подписанта до корня НУЦ на дату метки построить не удалось, поэтому вложенные данные отзыва не с чем сверить.'
};
const HISTORY_CODES = {
  NO_EVIDENCE: 'в подписи нет ответа OCSP или списка отзыва для этого сертификата',
  EVIDENCE_BEFORE_TIME: 'вложенные данные выпущены раньше метки и на её момент уже не действовали',
  EVIDENCE_NOT_PROVEN: 'срок сертификата, которым подписаны данные отзыва, истёк, а архивной метки, подтверждающей, что данные существовали раньше, нет',
  STATUS_UNKNOWN: 'служба отзыва не знает этот сертификат'
};
const FRESHNESS = { after: 'выпущены после метки', window: 'список действовал на момент метки' };
const PROOF = { archive: 'существование подтверждено архивной меткой', present: 'существование подтверждено только сейчас' };
const historyRole = entry => `${entry.role === 'timestamp' ? (entry.ca ? 'УЦ службы меток' : 'Служба меток') : entry.ca ? 'УЦ подписанта' : 'Подписант'} (${entry.name})`;

// Status at the signature time-stamp derived from the embedded OCSP/CRL (crypto/historical.js). Only a
// report with computed === true may state a status at that moment.
export function historicalText(historical) {
  if (historical?.computed !== true) return NOT_COMPUTED[historical?.reason] || HISTORICAL_NOT_COMPUTED;
  const at = dateTime(historical.time);
  const entries = historical.certificates || [];
  if (historical.state === 'revoked') {
    const entry = entries.find(item => item.state === 'revoked');
    return `Статус отзыва на момент метки ${at}: ${historyRole(entry)} уже был отозван ${dateTime(entry.revocationTime)}${entry.reason ? ' (' + (REASONS[entry.reason] || entry.reason) + ')' : ''}. Вычислено по вложенным данным отзыва.`;
  }
  const lines = entries.map(entry => entry.state === 'good'
    ? `${historyRole(entry)}: не отозван · ${REVOCATION_SOURCES[entry.source]} от ${dateTime(entry.thisUpdate)}, ${FRESHNESS[entry.freshness]} · ${PROOF[entry.provenBy]}${entry.revokedLater ? ` · отозван позже, ${dateTime(entry.revokedLater)}` : ''}`
    : `${historyRole(entry)}: не определён · ${HISTORY_CODES[entry.code] || `вложенные данные не прошли проверку (${entry.code})`}`);
  const head = historical.state === 'good'
    ? `Статус отзыва на момент метки ${at}: не отозван. Вычислено без сети по вложенным ответам OCSP и спискам отзыва для цепочек подписанта и службы меток.`
    : `Статус отзыва на момент метки ${at}: не определён. Вложенных доказательств недостаточно.`;
  return [head, ...lines].join('\n');
}

// CAdES-LT/LTA block of the verification result.
export function longTermText(longTerm) {
  if (!longTerm?.level) return '';
  const { embedded, archives } = longTerm;
  const lines = [`CAdES-${longTerm.level}: в подпись встроены сертификаты (${embedded.certificates}), ответы OCSP (${embedded.ocsp}) и списки отзыва (${embedded.crls}).`];
  if (!archives.length) lines.push('Архивных меток нет.');
  for (const archive of archives) {
    lines.push(`Архивная метка ${archive.index} из ${archives.length}: ${dateTime(archive.time)} · ${archive.authority || 'служба меток не указана'} · ${HASH_NAMES[archive.hashAlgorithm] || archive.hashAlgorithm}`,
      `Проверена: подпись службы меток и её цепочка НУЦ; сверены документ, подпись и учтённые меткой сертификаты (${archive.covers.certificates}), данные отзыва (${archive.covers.revocation}) и атрибуты (${archive.covers.attributes}).`,
      `Сертификат службы меток сейчас: ${label(archive.revocation).toLowerCase()}`);
  }
  lines.push(historicalText(longTerm.historical));
  if (longTerm.renewal) lines.push('Архивную метку можно продлить кнопкой «Продлить архивную метку»: прежние подписи, данные проверки и метки сохранятся.');
  else if (archives.length) lines.push('Продлить архивную метку в Tegin можно только для подписей RSA с меткой времени.');
  return lines.join('\n');
}

// Details of the verify screen. revocationRequested: the user ticked "Проверить отзыв онлайн".
export function verificationText(data, { revocationRequested }) {
  const trusted = data.signers.every(signer => signer.trust.trusted);
  const states = [...data.signers.map(signer => signer.trust.revocation), ...data.timestamps.map(stamp => stamp.revocation)].map(result => result?.state || 'not-checked');
  const revoked = states.includes('revoked');
  const signers = data.signers.map(signer => [signer.name, signer.algorithm, signer.trust.trusted ? 'Цепочка НУЦ РК подтверждена' : 'Цепочка доверия не подтверждена',
    `Статус отзыва сейчас: ${label(signer.trust.revocation).toLowerCase()}`, historyNote(signer.history) || revocationNote(signer.trust.revocation)].filter(Boolean).join('\n')).join('\n\n');
  const stamps = data.timestamps.filter(stamp => stamp.kind !== 'archive')
    .map(stamp => `Метка времени: ${dateTime(stamp.time)}\nСертификат службы меток: ${label(stamp.revocation).toLowerCase()}`).join('\n');
  const longTerm = longTermText(data.longTerm);
  const footer = states.some(state => state !== 'good' && state !== 'not-checked') ? 'Текущий статус отзыва сам по себе не определяет действительность подписи в прошлом.'
    : states.includes('not-checked') && !revocationRequested ? 'Чтобы узнать статус отзыва, отметьте «Проверить отзыв онлайн» и проверьте снова.' : '';
  return {
    revoked, trusted, warning: !trusted || states.some(state => state !== 'good' && state !== 'not-checked') || (data.longTerm?.historical?.computed === true && data.longTerm.historical.state !== 'good'),
    title: revoked ? 'Подпись соответствует документу' : 'Подпись верна',
    description: revoked ? 'Содержимое соответствует подписи, но сертификат отозван. Сведения о времени отзыва ниже.' : 'Содержимое соответствует криптографической подписи.',
    details: [signers, stamps, longTerm, footer].filter(Boolean).join('\n\n')
  };
}
