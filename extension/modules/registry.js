import { catalog } from './catalog.js';
export const COMMON = 'kz.gov.pki.knca.commonUtils';
export const BASICS = 'kz.gov.pki.knca.basics';
// Only explicit, inspected service IDs are routed. Never alias an unknown plugin
// to commonUtils: its policy or signed attributes may be materially different.
const definitions = [
  ['common', 'НУЦ · Common Utils', 'kz.gov.pki.osgi.layer.common', [COMMON], ['XML', 'CMS / CAdES', 'Сведения о сертификате'], 'Целый XML и данные base64; файловые ключи PKCS#12.'],
  ['basics', 'НУЦ · Basics', 'kz.gov.pki.knca.applet.knca_applet', [BASICS], ['XML', 'CMS / CAdES', 'Raw', 'Пакетная подпись'], 'До 10 документов; метки времени CMS; без аппаратных токенов.'],
  ['goszakup', 'Госзакупки · NURSign', 'kz.ecc.NurSignBundle', ['NURSign'], ['XML', 'CMS / CAdES', 'Пакетная подпись'], 'Данные в запросе: xml, multixml, binary, text, multitext. Загрузка по ссылкам, выбор файлов с диска и needHash пока недоступны.'],
  ['samruk', 'Самрук-Казына · ИСЭЗ', 'kz.sapa.eproc.osgi.EprocModule', ['kz.sapa.eproc.osgi.EprocModule'], ['XML'], 'Целый XML без XPath. Для каждой операции нужно выбрать ключ; пароль не кэшируется.'],
  ['qiwi', 'СФД · QIWI', 'kz.qiwi.osgi.SecurityUtils', ['kz.qiwi.osgi.SecurityUtils'], ['XML'], 'signXml и logOut. Подтверждение каждого подписания вместо сохранённого сеанса ключа.'],
  ['rating', '1С-Рейтинг · ЭДО', 'kz.rating1c.edo', ['kz.rating1c.edo.signUtils'], ['XML', 'CMS / CAdES', 'Сведения о сертификате'], 'Методы Common Utils для данных в памяти. Локальные пути, сохранение файлов и дополнительные службы недоступны.'],
  ['uchet', 'Uchet.kz', 'kz.uchet.signUtil', ['kz.uchet.signUtil.commonUtils'], ['XML'], 'Только signXml для целого документа. API с путями к ключам и паролями сайта не принимается.'],
  ['metadoc-info', 'MetaDoc · сведения о сертификате', 'kz.metadoc.NCAModule', ['kz.metadoc.ncamodule.knca.commonUtils'], ['Сведения о сертификате'], 'getKeyInfo и changeLocale. Подписание MetaDoc со специальными атрибутами и OCSP ещё не перенесено.']
];
export const modules = definitions.map(([id, name, bundle, services, features, limitations]) => ({ id, name, bundle, services, features, limitations, available: true, vendor: catalog.find(entry => entry.symname === bundle) }));
export const findModule = service => modules.find(module => module.services.includes(service));
export const DEFAULT_SETTINGS = Object.freeze({ enabled: true, origins: [], xml: true, cms: true, raw: true, timestamp: 'ask', maxBatch: 10 });
export function validateSettings(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !Object.hasOwn(DEFAULT_SETTINGS, key))) throw new Error('Некорректные настройки модуля.');
  const result = { ...DEFAULT_SETTINGS, ...value };
  for (const key of ['enabled', 'xml', 'cms', 'raw']) if (typeof result[key] !== 'boolean') throw new Error('Некорректный переключатель.');
  if (!['ask', 'deny'].includes(result.timestamp) || !Number.isInteger(result.maxBatch) || result.maxBatch < 1 || result.maxBatch > 10) throw new Error('Некорректные ограничения подписания.');
  if (!Array.isArray(result.origins) || result.origins.length > 30) throw new Error('Допускается до 30 адресов сайтов.');
  result.origins = [...new Set(result.origins.map(value => {
    if (typeof value !== 'string' || value.length > 250) throw new Error('Некорректный адрес сайта.');
    let url; try { url = new URL(value); } catch { throw new Error('Укажите полный адрес, например https://egov.kz'); }
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash || !(url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)))) throw new Error('Укажите только адрес HTTPS-сайта без пути, параметров и пароля.');
    return url.origin;
  }))];
  return result;
}
export function enforceSettings(module, normalized, origin, stored = {}) {
  const settings = validateSettings(stored);
  if (!settings.enabled) throw new Error(`Модуль «${module.name}» выключен. Откройте Tegin → Модули.`);
  if (settings.origins.length && !settings.origins.includes(origin)) throw new Error(`Этот сайт не разрешён в настройках модуля «${module.name}».`);
  if (normalized.format && ['xml', 'cms', 'raw'].includes(normalized.format) && !settings[normalized.format]) throw new Error('Этот формат подписи выключен в настройках модуля.');
  if (normalized.timestamp && settings.timestamp === 'deny') throw new Error('Модуль запросил обязательную метку времени, а она запрещена в настройках. Подпись без неё не создаётся.');
  if (normalized.documents?.length > settings.maxBatch) throw new Error('Число документов превышает ограничение модуля.');
}
