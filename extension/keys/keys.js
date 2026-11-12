import { listRecords, removeRecord } from '../lib/issuance-store.js';

const api = globalThis.browser || chrome;
const $ = selector => document.querySelector(selector);
const date = value => { const parsed = new Date(value); return Number.isNaN(parsed.getTime()) ? 'дата неизвестна' : parsed.toLocaleDateString('ru-RU'); };
const WARNINGS = {
  installed: 'Файл .p12 по этой заявке сохранён. Перед удалением убедитесь, что он открывается: выберите его как ключ в «Подписать файл» и введите пароль. Удалённую запись вернуть нельзя.',
  requested: 'Сертификат по этой заявке ещё не установлен. После удаления установить его можно будет только из резервной копии ключа заявки (файл .tegin-request.json). Без копии понадобится новая заявка.'
};

function report(text = '', error = false) {
  $('#status').textContent = text;
  $('#status').toggleAttribute('data-error', error);
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function row(record) {
  const installed = record.status === 'installed';
  const item = element('article', 'panel key-record');
  item.dataset.slot = record.slot;
  item.dataset.status = installed ? 'installed' : 'requested';
  const top = element('div', 'key-top');
  const heading = element('div', 'key-heading');
  heading.append(element('h2', '', `Заявка от ${date(record.created)}`),
    element('p', 'key-meta', [Array.isArray(record.algorithms) ? record.algorithms.join(', ') : '', `№ ${record.id.slice(0, 8)}`, record.slot.includes('~') ? 'из резервной копии' : ''].filter(Boolean).join(' · ')));
  const state = element('span', 'key-state', installed ? `Файл .p12 сохранён ${date(record.installed)}` : 'Сертификат не установлен');
  top.append(heading, state);
  const remove = element('button', 'button secondary key-remove', 'Удалить');
  remove.type = 'button';
  const confirmBox = element('div', 'key-confirm');
  confirmBox.hidden = true;
  confirmBox.setAttribute('role', 'group');
  confirmBox.setAttribute('aria-label', 'Подтверждение удаления');
  const actions = element('div', 'key-actions');
  const yes = element('button', 'button danger key-yes', 'Удалить запись'), no = element('button', 'button secondary key-no', 'Оставить');
  yes.type = no.type = 'button';
  actions.append(yes, no);
  confirmBox.append(element('p', '', WARNINGS[item.dataset.status]), actions);
  remove.addEventListener('click', () => { remove.hidden = true; confirmBox.hidden = false; no.focus(); });
  no.addEventListener('click', () => { confirmBox.hidden = true; remove.hidden = false; remove.focus(); });
  yes.addEventListener('click', async () => {
    yes.disabled = no.disabled = true;
    try {
      await removeRecord(api, record.slot);
      report('Запись удалена.');
      await render();
    } catch (error) { yes.disabled = no.disabled = false; report(error.message, true); }
  });
  item.append(top, remove, confirmBox);
  return item;
}

async function render() {
  const records = (await listRecords(api)).sort((a, b) => String(b.created).localeCompare(String(a.created)));
  $('#list').replaceChildren(...records.map(row));
  $('#empty').hidden = records.length > 0;
}

render().catch(error => report(error.message, true));
