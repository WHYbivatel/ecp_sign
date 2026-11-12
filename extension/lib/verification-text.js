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

// CAdES-LT/LTA block of the verification result. Tegin has no historical revocation evaluation, so
// whatever the report carries, the text says the status at the time of the stamps was not computed.
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
  lines.push(HISTORICAL_NOT_COMPUTED);
  if (archives.length) lines.push('Продлить архивную метку в Tegin пока нельзя.');
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
    revoked, trusted, warning: !trusted || states.some(state => state !== 'good' && state !== 'not-checked'),
    title: revoked ? 'Подпись соответствует документу' : 'Подпись верна',
    description: revoked ? 'Содержимое соответствует подписи, но сертификат отозван. Сведения о времени отзыва ниже.' : 'Содержимое соответствует криптографической подписи.',
    details: [signers, stamps, longTerm, footer].filter(Boolean).join('\n\n')
  };
}
