// The confirmation window promises the public certificate only: local trust and revocation
// results (check times, sources, fallbacks) stay in the extension.
const KEY_INFO_FIELDS = ['name', 'iin', 'bin', 'organization', 'issuer', 'notBefore', 'notAfter', 'serialNumber', 'extendedKeyUsageOids', 'certificate'];
// NCALayer Common Utils field names and formats win where they overlap, and fields it cannot read are left out.
// There is no key store alias to report.
export function keyInfoResult(certificate) {
  const result = Object.fromEntries(KEY_INFO_FIELDS.map(field => [field, certificate[field]]));
  return { ...result, extendedKeyUsageOids: [...certificate.extendedKeyUsageOids], cert: certificate.certificate,
    ...Object.fromEntries(Object.entries(certificate.knca).filter(([, value]) => value !== null)),
    certNotBefore: String(Date.parse(certificate.notBefore)), certNotAfter: String(Date.parse(certificate.notAfter)),
    pem: `-----BEGIN CERTIFICATE-----\n${certificate.certificate.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n` };
}

// Recognize only complete, known service payloads on their exact origins.
// Other XML, extra fields, unknown origins and document hashes keep their preview.
export function serviceOperation(request, origin) {
  if (request?.operation !== 'sign' || request.format !== 'xml' || request.decode || request.digested || request.documents?.length !== 1 || !request.signerParams?.extKeyUsageOids?.includes('1.3.6.1.5.5.7.3.2')) return null;
  if (typeof request.documents[0] !== 'string') return null;
  const xml = request.documents[0].replace(/^\s*<\?xml\s+version="1\.0"(?:\s+encoding="UTF-8")?(?:\s+standalone="yes")?\s*\?>/i, '').trim();
  if (origin === 'https://egov.kz' && /^<login>\s*<client-type>PORTAL<\/client-type>\s*<\/login>$/.test(xml)) return { title: 'Вход на сайт', description: 'Подтвердите вход с помощью ЭЦП.', button: 'Подтвердить вход' };
  const challenge = /^<key_settings_digi_sign>\s*<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}<\/uuid>\s*<date>(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))<\/date>\s*<\/key_settings_digi_sign>$/i.exec(xml);
  if (origin === 'https://nca.pki.gov.kz' && challenge && Number.isFinite(Date.parse(challenge[1]))) return { title: 'Подтверждение на сайте НУЦ', description: 'Сайт запросил подпись служебных данных. Продолжайте, если вы начали это действие.', button: 'Подтвердить' };
  return null;
}
