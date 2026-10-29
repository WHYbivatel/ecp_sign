import { modules, validateSettings } from './registry.js';
import { catalog } from './catalog.js';
const blockedReasons = {
  'kz.inessoft.kgd.knp.sono_knp_ncalayer_module': 'КНП использует команды с локальным хранилищем, паролем и отдельными службами SmartAuth. Эти операции пока не перенесены; пароль сайта Tegin не принимает.',
  'com.osdkz.esf.signer': 'Официальная ссылка ЭСФ сейчас возвращает страницу сайта вместо файла модуля. Проверить актуальный интерфейс и перенести его пока не удалось.',
  'kz.ecc.K2SignBundle': 'Модуль Казначейства создаёт ZIP с подписью и сертификатом, использует сеанс сайта и отправляет архив. Этот полный процесс ещё не реализован.',
  'kz.nitec.eup.eupsigner': 'Модулю нужны специальные атрибуты ЕСЭДО и подтверждение OCSP. Обычная CMS-подпись не заменяет этот формат.',
  'kz.bas.nca.signer': 'Модулю нужны специальные атрибуты, подтверждение OCSP и метка времени. Такой процесс ещё не перенесён.'
};
const descriptions = { common: 'Подпись и сведения о сертификате', basics: 'Подпись документов и пакетов', goszakup: 'Подпись документов для закупок', samruk: 'Подпись XML-документов', qiwi: 'Подпись XML-документов', rating: 'Подпись и сведения о сертификате', uchet: 'Подпись XML-документов', 'metadoc-info': 'Сведения о сертификате' };
const limitations = { common: 'Документы XML и данные сайта. Ключи .p12 и .pfx.', basics: 'До 10 документов за операцию. Аппаратные токены не поддерживаются.', goszakup: 'XML и данные сайта, включая пакеты документов. Загрузка по ссылке и выбор документа самим модулем пока недоступны.', samruk: 'Целые XML-документы. Подпись отдельных частей XML недоступна. Ключ нужно выбирать для каждой операции.', qiwi: 'Подпись XML с проверкой результата. Каждая операция требует подтверждения.', rating: 'XML и данные сайта. Работа с файлами по локальным путям недоступна.', uchet: 'Целые XML-документы. Работа с путями к ключам недоступна.', 'metadoc-info': 'Только сведения о сертификате. Подпись документов MetaDoc пока недоступна.' };
const displayNames = { common: 'НУЦ · базовые функции', basics: 'НУЦ · подписание', 'metadoc-info': 'MetaDoc' };
const icons = { common: 'Н', basics: 'Н', goszakup: 'ГЗ', samruk: 'СК', qiwi: 'Q', rating: '1С', uchet: 'U', 'metadoc-info': 'M' };
const api = globalThis.browser || chrome;
const $ = selector => document.querySelector(selector);
let settings = {}, saving = false;
const node = (tag, text, className) => { const element = document.createElement(tag); if (text) element.textContent = text; if (className) element.className = className; return element; };
function report(message, error = false) { $('#status').textContent = message; $('#status').toggleAttribute('data-error', error); }
function config(module) { return validateSettings(settings[module.id] || {}); }
async function save(module, value) {
  if (saving) return false;
  saving = true;
  try {
    const valid = validateSettings(value);
    const stored = (await api.storage.local.get('moduleSettings')).moduleSettings || {};
    const updated = { ...stored, [module.id]: valid };
    await api.storage.local.set({ moduleSettings: updated }); settings = updated;
    report('Настройки сохранены');
    return true;
  } catch (error) { report(error.message, true); return false; }
  finally { saving = false; }
}
function checkbox(label, checked) {
  const wrapper = node('label', '', 'toggle'); const input = document.createElement('input'); input.type = 'checkbox'; input.checked = checked;
  wrapper.append(input, node('span', label)); return { wrapper, input };
}
function card(module) {
  const state = config(module), article = node('article', '', 'panel module'); article.dataset.module = module.id;
  const top = node('div', '', 'module-top'), heading = node('div', '', 'module-heading');
  const title = node('div', '', 'title-row'); title.append(node('h2', displayNames[module.id] || module.name), node('span', 'Частично', 'badge'));
  heading.append(title, node('p', descriptions[module.id]));
  const enabled = checkbox('Включён', state.enabled); enabled.wrapper.classList.add('module-switch'); enabled.input.setAttribute('aria-label', `Включить ${module.name}`);
  enabled.input.addEventListener('change', async () => { enabled.input.disabled = true; if (!await save(module, { ...config(module), enabled: enabled.input.checked })) enabled.input.checked = !enabled.input.checked; enabled.input.disabled = false; });
  top.append(node('span', icons[module.id], 'module-icon'), heading, enabled.wrapper); article.append(top);
  const details = node('details'), summary = node('summary', 'Настроить'); details.append(summary);
  const form = node('form', '', 'controls');
  const origins = node('label', 'Сайты', 'wide');
  const textarea = document.createElement('textarea'); textarea.value = state.origins.join('\n'); textarea.placeholder = 'https://egov.kz'; origins.append(textarea, node('small', 'По одному адресу в строке. Пусто — все подключённые сайты.', 'hint')); form.append(origins);
  const formats = node('div', '', 'formats wide'), formatInputs = {};
  for (const [key, label] of [['xml', 'XML'], ['cms', 'CMS / CAdES'], ['raw', 'Raw']]) { if (!module.features.includes(label)) continue; const check = checkbox(label, state[key]); formatInputs[key] = check.input; formats.append(check.wrapper); }
  form.append(formats);
  const timestamp = node('label', 'Метка времени'); const select = document.createElement('select');
  for (const [value, title] of [['ask', 'По запросу сайта'], ['deny', 'Запретить']]) { const option = node('option', title); option.value = value; select.append(option); }
  select.value = state.timestamp; timestamp.append(select);
  timestamp.hidden = !module.features.includes('CMS / CAdES');
  const batch = node('label', 'Документов за раз'); const count = document.createElement('input'); count.type = 'number'; count.min = '1'; count.max = '10'; count.value = state.maxBatch; batch.hidden = !module.features.includes('Пакетная подпись'); batch.append(count); form.append(timestamp, batch);
  const button = node('button', 'Сохранить настройки', 'button'); button.type = 'submit';
  const actions = node('div', '', 'actions'); actions.append(button); form.append(actions); form.addEventListener('submit', async event => {
    event.preventDefault(); button.disabled = true;
    await save(module, { ...config(module), origins: textarea.value.split('\n').map(value => value.trim()).filter(Boolean), ...Object.fromEntries(Object.entries(formatInputs).map(([key, input]) => [key, input.checked])), timestamp: select.value, maxBatch: Number(count.value) });
    button.disabled = false;
  });
  const capabilities = node('details', '', 'capabilities'); capabilities.append(node('summary', 'Что доступно'), node('p', limitations[module.id])); form.append(capabilities);
  details.append(form); article.append(details); return article;
}
function render() {
  const query = $('#search').value.trim().toLocaleLowerCase('ru'), filter = $('#filter').value;
  const list = $('#list'); list.replaceChildren();
  for (const module of modules) {
    if (filter === 'unavailable' || (filter === 'enabled' && !config(module).enabled) || !`${module.name} ${displayNames[module.id] || ''} ${descriptions[module.id]} ${module.services} ${module.features}`.toLocaleLowerCase('ru').includes(query)) continue;
    list.append(card(module));
  }
  if (['all', 'unavailable'].includes(filter)) for (const entry of catalog) {
    if (modules.some(module => module.bundle === entry.symname) || !`${entry.name} ${entry.symname}`.toLocaleLowerCase('ru').includes(query)) continue;
    const article = node('article', '', 'panel module'); article.dataset.unavailable = '';
    article.append(node('h2', entry.name), node('span', entry.required ? 'Встроенные функции' : 'Недоступен', 'badge'));
    const description = node('details');
    description.append(node('summary', 'Подробнее'), node('p', entry.required ? 'Криптографические функции встроены в Tegin отдельно. Оригинальная библиотека NCALayer не устанавливается.' : (blockedReasons[entry.symname] || 'Этот модуль ещё не перенесён в Tegin.')));
    article.append(description);
    list.append(article);
  }
  $('#empty').hidden = Boolean(list.children.length);
}
$('#search').addEventListener('input', render); $('#filter').addEventListener('change', render);
async function initialize() {
try {
  settings = (await api.storage.local.get('moduleSettings')).moduleSettings || {};
  $('#summary').textContent = `${modules.length} доступно`;
  render();
} catch (error) { report(error.message, true); }

}
initialize();
