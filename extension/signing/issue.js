import { PASSWORD_RULE, PASSWORD_HINT } from './issuance-protocol.js';

const $ = selector => document.querySelector(selector);
const api = globalThis.browser || chrome;
const id = location.hash.slice(1);
// Pending application keys, encrypted, kept until the certificate is installed or the user deletes them.
const STORE = 'issuance:';
const LABELS = { '2.5.4.3': 'Имя (CN)', '2.5.4.4': 'Фамилия', '2.5.4.42': 'Имя', '2.5.4.5': 'ИИН', '2.5.4.6': 'Страна', '2.5.4.7': 'Населённый пункт',
  '2.5.4.8': 'Регион', '2.5.4.10': 'Организация', '2.5.4.11': 'БИН', '2.5.4.12': 'Должность', '2.5.4.15': 'Категория', '2.5.4.46': 'Квалификатор DN',
  '1.2.840.113549.1.9.1': 'E-mail', '0.9.2342.19200300.100.1.25': 'Компонент домена' };
const status = $('#status');
let request, origin, worker, finished = false, busy = false, deadline = Date.now() + 180000, urls = [];
let canInstall = false, installed = [];

async function message(kind, extra = {}) {
  const reply = await api.runtime.sendMessage({ kind, id, ...extra });
  if (reply?.error) throw new Error(reply.error);
  return reply;
}
function report(text = '', error = false) {
  status.textContent = text;
  status.toggleAttribute('data-error', error);
  status.toggleAttribute('data-busy', busy && !error);
}
const generating = () => request?.operation === 'issue-generate';
function updateControls() {
  const password = $('#password').value;
  const ready = generating() ? PASSWORD_RULE.test(password) && password === $('#password-confirm').value : canInstall && PASSWORD_RULE.test(password);
  $('#approve').disabled = busy || finished || !request || !ready;
  $('#password').disabled = $('#password-confirm').disabled = busy || finished;
}
function clearPassword() { $('#password').value = ''; $('#password-confirm').value = ''; }
function stopWorker() { worker?.terminate(); worker = null; }

function run(payload) {
  stopWorker();
  return new Promise((resolve, reject) => {
    const current = worker = new Worker(api.runtime.getURL('crypto/worker.js'));
    const done = () => { current.terminate(); if (worker === current) worker = null; };
    current.onmessage = ({ data }) => {
      done();
      if (data.kind === 'error') reject(Object.assign(new Error(data.message), { code: data.code }));
      else resolve(data);
    };
    current.onerror = () => { done(); reject(new Error('Криптографический модуль остановился. Повторите попытку.')); };
    current.postMessage(payload);
  });
}

const validRecord = value => value && value.v === 1 && /^[0-9a-f-]{36}$/.test(value.id) && Array.isArray(value.identities) && value.identities.length >= 1 && value.identities.length <= 4 &&
  value.identities.every(item => typeof item === 'string' && /^[0-9a-f]{64}$/.test(item)) && value.sealed && typeof value.sealed === 'object' && typeof value.sealed.data === 'string';
async function records() {
  return Object.entries(await api.storage.local.get(null)).filter(([key, value]) => key.startsWith(STORE) && validRecord(value)).map(([, value]) => value);
}

function download(blob, filename, label) {
  const url = URL.createObjectURL(blob); urls.push(url);
  const link = document.createElement('a');
  link.className = 'button'; link.href = url; link.download = filename;
  link.innerHTML = '<svg class="icon"><use href="../assets/icons.svg#download"/></svg>';
  link.append(label);
  $('#downloads').append(link);
  return link;
}
function resultScreen(title, description, details) {
  $('#workspace').hidden = true; $('.approval-footer').hidden = true; $('#result-screen').hidden = false;
  $('#result-title').textContent = title; $('#result-description').textContent = description; $('#result-details').textContent = details;
}

function showGenerate() {
  $('#title').textContent = 'Создать ключ для заявки';
  $('#operation').textContent = 'Генерация ключа';
  $('#step').textContent = '01 / 02';
  const rows = [...request.dn, ...(request.email ? [['email', request.email]] : [])];
  $('#subject').replaceChildren(...rows.flatMap(([oid, value]) => {
    const term = document.createElement('dt'), detail = document.createElement('dd');
    term.textContent = oid === 'email' ? 'E-mail (доп. имя)' : LABELS[oid] || oid;
    detail.textContent = value;
    return [term, detail];
  }));
  $('#algorithms').textContent = request.keys.map(key => key.algorithm === 'RSA' ? `RSA · ${key.length} бит` : `ГОСТ 34.10-2015 · ${key.length} бит`).join(', ');
  $('#request-panel').hidden = false; $('#password-form').hidden = false;
  $('#password-hint').textContent = PASSWORD_HINT;
  $('#password-note').textContent = 'До выпуска сертификата ключ хранится в этом браузере в зашифрованном виде. Этот же пароль понадобится при установке сертификата и будет паролем файла .p12. Восстановить его нельзя.';
  $('#approve-label').textContent = 'Создать ключ и запрос';
}

async function generate() {
  const password = $('#password').value;
  busy = true; updateControls(); report('Создаём ключ и запрос на сертификат…');
  try {
    await message('nca:validate');
    const recordId = crypto.randomUUID();
    const result = await run({ kind: 'issue-generate', request, password, context: recordId });
    clearPassword();
    const record = { v: 1, id: recordId, origin, created: new Date().toISOString(), holder: request.dn.find(([oid]) => oid === '2.5.4.3')?.[1] || '',
      algorithms: result.algorithms, identities: result.identities, status: 'requested', sealed: result.sealed };
    await api.storage.local.set({ [STORE + recordId]: record });
    try { await message('nca:complete', { result: { pems: result.pems } }); }
    catch (error) { await api.storage.local.remove(STORE + recordId); throw error; }
    finished = true; busy = false;
    resultScreen('Запрос передан на сайт НУЦ', 'Сайт продолжит подачу заявки. Ключ остаётся в этом браузере в зашифрованном виде.',
      `Ключ: ${result.algorithms.join(', ')}\nПосле одобрения заявки откройте её статус на сайте НУЦ в этом же браузере и нажмите установку сертификата: Tegin найдёт ключ и сохранит файл .p12.\nСохраните резервную копию: без неё ключ пропадёт, если очистить данные расширения. Копия зашифрована вашим паролем.`);
    download(new Blob([JSON.stringify(record)], { type: 'application/json' }), `tegin-nuc-${record.created.slice(0, 10)}-${recordId.slice(0, 8)}.tegin-request.json`, 'Скачать резервную копию ключа заявки');
    report();
  } catch (error) {
    busy = false; clearPassword();
    report(error.message, true);
  } finally { updateControls(); }
}

function certificateCard({ certificate, trust, recordId }) {
  const card = document.createElement('article'); card.className = 'issue-certificate';
  const name = document.createElement('strong'); name.textContent = certificate.name || certificate.subjectDn;
  const details = document.createElement('p');
  details.textContent = [certificate.organization, certificate.iin && `ИИН ${certificate.iin}`, certificate.bin && `БИН ${certificate.bin}`].filter(Boolean).join(' · ') +
    `\n${certificate.algorithm} · действует с ${new Date(certificate.notBefore).toLocaleDateString('ru-RU')} по ${new Date(certificate.notAfter).toLocaleDateString('ru-RU')}\nВыдан: ${certificate.issuer}`;
  details.style.whiteSpace = 'pre-line';
  const chain = document.createElement('div'); chain.className = 'issue-state';
  chain.toggleAttribute(trust.trusted ? 'data-ok' : 'data-bad', true);
  chain.textContent = trust.trusted ? 'Цепочка до корня НУЦ РК подтверждена' : `Цепочка не подтверждена: ${trust.reason}`;
  const key = document.createElement('div'); key.className = 'issue-state';
  key.toggleAttribute(recordId ? 'data-ok' : 'data-bad', true);
  key.textContent = recordId ? 'Ключ заявки найден в этом браузере' : 'Ключ для этого сертификата в этом браузере не найден';
  card.append(name, details, chain, key);
  return card;
}

async function inspect() {
  canInstall = false; updateControls();
  const pending = (await records()).map(({ id: recordId, identities }) => ({ id: recordId, identities }));
  const { leaves } = await run({ kind: 'issue-inspect', certificates: request.certificates, pending });
  $('#certificates').replaceChildren(...leaves.map(certificateCard));
  $('#backup-import').hidden = leaves.every(leaf => leaf.recordId);
  canInstall = leaves.every(leaf => leaf.recordId && leaf.trust.trusted);
  if (!canInstall && leaves.some(leaf => !leaf.trust.trusted)) report('Сертификат не прошёл проверку цепочки НУЦ РК. Установка недоступна.', true);
  updateControls();
}

function showInstall() {
  $('#title').textContent = 'Установить сертификат';
  $('#subtitle').textContent = 'Tegin проверит сертификат и сохранит ключ с сертификатом в файл .p12.';
  $('#operation').textContent = 'Установка сертификата';
  $('#step').textContent = '02 / 02';
  $('#certificates-panel').hidden = false; $('#password-form').hidden = false; $('#confirm-group').hidden = true;
  $('#password').autocomplete = 'off';
  $('#password-heading').textContent = 'Пароль ключа заявки';
  $('#password-hint').textContent = 'Тот же пароль, что вы задали при создании ключа.';
  $('#password-note').textContent = 'Им же будет защищён файл .p12. Пароль никуда не сохраняется.';
  $('#security-text').textContent = 'Сайт получит только отметку об установке. Ключ и пароль остаются на устройстве.';
  $('#approve-label').textContent = 'Проверить и сохранить .p12';
}

const fileName = certificate => `tegin-${certificate.algorithm.startsWith('RSA') ? 'rsa' : 'gost'}-${(certificate.iin || certificate.bin || 'nuc')}-${certificate.serialNumber.slice(-8)}.p12`;
async function install() {
  const password = $('#password').value;
  busy = true; updateControls(); report('Проверяем сертификат и ключ…');
  try {
    await message('nca:validate');
    const pending = (await records()).map(({ id: recordId, identities, sealed }) => ({ id: recordId, identities, sealed }));
    const { files } = await run({ kind: 'issue-install', certificates: request.certificates, pending, password });
    clearPassword();
    busy = false; finished = true;
    installed = files.map(file => file.recordId);
    resultScreen('Сертификат готов к сохранению', 'Сохраните файл ЭЦП. После этого сайт НУЦ получит отметку об установке.',
      files.map(file => `${file.certificate.name} · ${file.certificate.algorithm}\nДействует до ${new Date(file.certificate.notAfter).toLocaleDateString('ru-RU')}`).join('\n\n') +
      '\n\nПароль файла .p12 — тот, что вы задали при создании ключа.');
    const pendingDownloads = new Set();
    for (const file of files) {
      const link = download(new Blob([file.container], { type: 'application/x-pkcs12' }), fileName(file.certificate), files.length > 1 ? `Скачать ${file.certificate.algorithm}` : 'Скачать файл ЭЦП (.p12)');
      pendingDownloads.add(link);
      link.addEventListener('click', () => {
        pendingDownloads.delete(link);
        if (!pendingDownloads.size) setTimeout(confirmInstalled, 0);
      }, { once: true });
    }
    report();
  } catch (error) {
    busy = false; clearPassword();
    report(error.message, true);
  } finally { updateControls(); }
}
let confirmed = false;
async function confirmInstalled() {
  if (confirmed) return;
  confirmed = true;
  for (const recordId of installed) {
    const key = STORE + recordId, record = (await api.storage.local.get(key))[key];
    if (record) await api.storage.local.set({ [key]: { ...record, status: 'installed', installed: new Date().toISOString() } });
  }
  $('#forget').hidden = false;
  try {
    await message('nca:complete', { result: { installed: true } });
    $('#result-title').textContent = 'Файл ЭЦП сохранён';
    $('#result-description').textContent = 'Сайт НУЦ получил отметку об установке. Файл можно скачать ещё раз, пока окно открыто.';
  } catch {
    $('#result-description').textContent = 'Файл сохранён, но сайт НУЦ отметку не получил: окно заявки закрыто или время истекло. Нажмите установку на странице статуса ещё раз.';
  }
}

$('#backup-file').addEventListener('change', async () => {
  const file = $('#backup-file').files[0];
  $('#backup-file').value = '';
  if (!file) return;
  try {
    if (file.size > 64 * 1024) throw new Error('Это не резервная копия ключа заявки Tegin.');
    let record;
    try { record = JSON.parse(await file.text()); } catch { throw new Error('Это не резервная копия ключа заявки Tegin.'); }
    if (!validRecord(record)) throw new Error('Это не резервная копия ключа заявки Tegin.');
    const { v, id: recordId, origin: source, created, holder, algorithms, identities, sealed } = record;
    await api.storage.local.set({ [STORE + recordId]: { v, id: recordId, origin: source, created, holder, algorithms, identities, status: 'requested', sealed } });
    report('Резервная копия добавлена.');
    await inspect();
  } catch (error) { report(error.message, true); }
});
$('#forget').addEventListener('click', async () => {
  if (!confirm('Удалить ключ заявки из браузера? Восстановить его можно будет только из сохранённого файла .p12 или резервной копии.')) return;
  await api.storage.local.remove(installed.map(recordId => STORE + recordId));
  $('#forget').hidden = true;
});
$('#password-form').addEventListener('submit', event => { event.preventDefault(); if (!$('#approve').disabled) $('#approve').click(); });
for (const field of ['#password', '#password-confirm']) $(field).addEventListener('input', updateControls);
$('#show-password').addEventListener('click', () => {
  const visible = $('#password').type === 'password';
  for (const field of ['#password', '#password-confirm']) $(field).type = visible ? 'text' : 'password';
  $('#show-password').setAttribute('aria-pressed', String(visible));
});
$('#approve').addEventListener('click', () => { if (!busy && !finished) (generating() ? generate() : install()); });
$('#cancel').addEventListener('click', async () => {
  finished = true; stopWorker(); clearPassword(); updateControls();
  await message('nca:cancel').catch(() => {});
  window.close();
});
$('#close').addEventListener('click', () => window.close());
window.addEventListener('pagehide', () => { stopWorker(); clearPassword(); for (const url of urls) URL.revokeObjectURL(url); });
setInterval(() => {
  if (finished || Date.now() < deadline) return;
  finished = true; stopWorker(); clearPassword(); updateControls();
  report('Время операции истекло. Запустите действие на сайте НУЦ ещё раз.', true);
  message('nca:cancel').catch(() => {});
}, 1000);

async function init() {
  try {
    const { record } = await message('nca:get');
    request = record.normalized; origin = record.origin; deadline = record.expires;
    $('#origin').textContent = origin;
    if (generating()) showGenerate();
    else { showInstall(); await inspect(); }
  } catch (error) { finished = true; report(error.message, true); }
  updateControls();
}
init();
