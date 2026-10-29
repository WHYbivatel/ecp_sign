import { modules, validateSettings } from './registry.js';
import { catalog } from './catalog.js';
const blockedReasons = {
  'kz.inessoft.kgd.knp.sono_knp_ncalayer_module': 'КНП использует команды с локальным хранилищем, паролем и отдельными службами SmartAuth. Эти операции пока не перенесены; пароль сайта Tegin не принимает.',
  'com.osdkz.esf.signer': 'Официальная ссылка ЭСФ сейчас возвращает страницу сайта вместо файла модуля. Проверить актуальный интерфейс и перенести его пока не удалось.',
  'kz.ecc.K2SignBundle': 'Модуль Казначейства создаёт ZIP с подписью и сертификатом, использует сеанс сайта и отправляет архив. Этот полный процесс ещё не реализован.',
  'kz.nitec.eup.eupsigner': 'Модулю нужны специальные атрибуты ЕСЭДО и подтверждение OCSP. Обычная CMS-подпись не заменяет этот формат.',
  'kz.bas.nca.signer': 'Модулю нужны специальные атрибуты, подтверждение OCSP и метка времени. Такой процесс ещё не перенесён.'
};
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
    report(`Настройки «${module.name}» сохранены. Они действуют и для ожидающих подтверждения запросов.`);
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
  const top = node('div', '', 'module-top'), heading = node('div'); heading.append(node('h2', module.name), node('span', 'Доступны отдельные функции', 'badge'));
  const enabled = checkbox('Включён', state.enabled); enabled.input.setAttribute('aria-label', `Включить ${module.name}`);
  enabled.input.addEventListener('change', async () => { enabled.input.disabled = true; if (!await save(module, { ...config(module), enabled: enabled.input.checked })) enabled.input.checked = !enabled.input.checked; enabled.input.disabled = false; });
  top.append(heading, enabled.wrapper); article.append(top, node('p', module.features.join(' · ')), node('p', module.limitations));
  const details = node('details'), summary = node('summary', 'Настройки и разрешения'); details.append(summary);
  const form = node('form', '', 'controls');
  const origins = node('label', 'Разрешённые сайты · по одному адресу в строке. Пусто — все сайты с доступом к Tegin.', 'wide');
  const textarea = document.createElement('textarea'); textarea.value = state.origins.join('\n'); textarea.placeholder = 'https://egov.kz'; origins.append(textarea); form.append(origins);
  const formats = node('div', '', 'formats wide'), formatInputs = {};
  for (const [key, label] of [['xml', 'XML'], ['cms', 'CMS / CAdES'], ['raw', 'Raw']]) { if (!module.features.includes(label)) continue; const check = checkbox(label, state[key]); formatInputs[key] = check.input; formats.append(check.wrapper); }
  form.append(formats);
  const timestamp = node('label', 'Метка времени НУЦ'); const select = document.createElement('select');
  for (const [value, title] of [['ask', 'По запросу сайта с вашим подтверждением'], ['deny', 'Запретить · запрос с меткой будет отклонён']]) { const option = node('option', title); option.value = value; select.append(option); }
  select.value = state.timestamp; timestamp.append(select);
  timestamp.hidden = !module.features.includes('CMS / CAdES');
  const batch = node('label', 'Документов за операцию · от 1 до 10'); const count = document.createElement('input'); count.type = 'number'; count.min = '1'; count.max = '10'; count.value = state.maxBatch; batch.hidden = !module.features.includes('Пакетная подпись'); batch.append(count); form.append(timestamp, batch);
  const button = node('button', 'Сохранить настройки', 'button'); button.type = 'submit';
  form.append(button); form.addEventListener('submit', async event => {
    event.preventDefault(); button.disabled = true;
    await save(module, { ...config(module), origins: textarea.value.split('\n').map(value => value.trim()).filter(Boolean), ...Object.fromEntries(Object.entries(formatInputs).map(([key, input]) => [key, input.checked])), timestamp: select.value, maxBatch: Number(count.value) });
    button.disabled = false;
  });
  details.append(form, node('p', module.services.join('\n'), 'service'), node('p', `Исследован интерфейс оригинального модуля ${module.vendor?.version || 'НУЦ'}. Реализация Tegin поставляется с расширением.`)); article.append(details); return article;
}
function render() {
  const query = $('#search').value.trim().toLocaleLowerCase('ru'), filter = $('#filter').value;
  const list = $('#list'); list.replaceChildren();
  for (const module of modules) {
    if (filter === 'unavailable' || (filter === 'enabled' && !config(module).enabled) || !`${module.name} ${module.services} ${module.features}`.toLocaleLowerCase('ru').includes(query)) continue;
    list.append(card(module));
  }
  if (['all', 'unavailable'].includes(filter)) for (const entry of catalog) {
    if (modules.some(module => module.bundle === entry.symname) || !`${entry.name} ${entry.symname}`.toLocaleLowerCase('ru').includes(query)) continue;
    const article = node('article', '', 'panel module'); article.dataset.unavailable = '';
    article.append(node('h2', entry.name), node('span', entry.required ? 'Системная библиотека NCALayer' : 'Требует переноса', 'badge'), node('p', entry.required ? 'Оригинальная Java-библиотека не устанавливается в браузер. Соответствующие криптографические функции Tegin встроены отдельно; это не копия библиотеки.' : (blockedReasons[entry.symname] || 'Совместимая реализация этого модуля пока недоступна. Включить его или установить Java-плагин в Tegin нельзя.')), node('p', `${entry.symname} · оригинальная версия ${entry.version}`, 'service'));
    list.append(article);
  }
  $('#empty').hidden = Boolean(list.children.length);
}
$('#search').addEventListener('input', render); $('#filter').addEventListener('change', render);
async function initialize() {
try {
  settings = (await api.storage.local.get('moduleSettings')).moduleSettings || {};
  $('#summary').textContent = `${modules.length} реализаций с доступными функциями · ${catalog.length} записей в каталоге NCALayer`;
  render();
} catch (error) { report(error.message, true); }

}
initialize();
