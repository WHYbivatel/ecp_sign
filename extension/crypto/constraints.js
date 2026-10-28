export const CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';

export function checkSignerConstraints(info, request, trust) {
  const constraints = request.signerParams || {};
  for (const field of ['iin', 'bin', 'serialNumber']) {
    const normalize = value => field === 'serialNumber' ? String(value || '').toLowerCase().replace(/^0+/, '') : value;
    if (constraints[field] && normalize(constraints[field]) !== normalize(info.summary[field])) throw new Error('Сертификат не соответствует требованиям сайта.');
  }
  const missing = (constraints.extKeyUsageOids || []).filter(oid => !info.eku.includes(oid));
  if (missing.length) {
    if (missing.includes(CLIENT_AUTH)) throw new Error('Для входа сайт требует сертификат аутентификации. Выбранный сертификат не разрешает такой вход. Выберите ключ AUTH_RSA, если у вас раздельные ключи, или сертификат с назначением «Аутентификация клиента».');
    throw new Error('Назначение сертификата не соответствует требованиям сайта. Требуемые назначения (OID): ' + missing.join(', '));
  }
  if (request.trustRequired && !trust?.trusted) throw new Error('Сайт требует доверенную цепочку сертификата. ' + (trust?.reason || 'Цепочка не проверена.'));
}
