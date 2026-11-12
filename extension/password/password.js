import { passwordChecks } from '../lib/password-rule.js';
import { MAX_CONTAINER_BYTES } from '../lib/pkcs12.js';

const api = globalThis.browser || chrome;
const $ = selector => document.querySelector(selector);
const form = $('#change-form'), fileInput = $('#key-file'), picker = $('#key-drop');
const oldInput = $('#old-password'), newInput = $('#new-password'), repeatInput = $('#repeat-password');
const submit = $('#submit'), status = $('#status');
let file = null, downloadUrl = null, busy = false;

function report(text = '', state) {
  status.textContent = text;
  status.toggleAttribute('data-error', state === 'error');
  status.toggleAttribute('data-busy', state === 'busy');
}
const size = bytes => bytes < 1024 ? `${bytes} Б` : `${(bytes / 1024).toFixed(1).replace('.', ',')} КБ`;

function choose(selected) {
  report();
  if (!selected) return;
  if (!/\.(p12|pfx)$/i.test(selected.name)) { report('Выберите файл ключа .p12 или .pfx.', 'error'); return; }
  if (selected.size > MAX_CONTAINER_BYTES) { report('Размер файла превышает 4 МБ.', 'error'); return; }
  file = selected;
  $('#key-name').textContent = selected.name;
  $('#key-size').textContent = `${size(selected.size)} · будет создана копия с новым паролем`;
  picker.setAttribute('data-selected', '');
  update();
  oldInput.focus();
}
fileInput.addEventListener('change', () => choose(fileInput.files[0]));
picker.addEventListener('dragover', event => { event.preventDefault(); picker.setAttribute('data-drag', ''); });
picker.addEventListener('dragleave', () => picker.removeAttribute('data-drag'));
picker.addEventListener('drop', event => { event.preventDefault(); picker.removeAttribute('data-drag'); choose(event.dataTransfer.files[0]); });

for (const button of document.querySelectorAll('.reveal')) {
  button.addEventListener('click', () => {
    const input = $('#' + button.dataset.target), shown = input.type === 'text';
    input.type = shown ? 'password' : 'text';
    button.setAttribute('aria-pressed', String(!shown));
    button.setAttribute('aria-label', shown ? 'Показать пароль' : 'Скрыть пароль');
  });
}

function update() {
  const checks = passwordChecks(newInput.value, oldInput.value, repeatInput.value);
  for (const item of document.querySelectorAll('#rules li')) {
    const rule = item.dataset.rule;
    const touched = rule === 'repeat' ? repeatInput.value.length > 0 : rule === 'differs' ? newInput.value.length > 0 && oldInput.value.length > 0 : newInput.value.length > 0;
    item.toggleAttribute('data-ok', touched && checks[rule]);
    item.toggleAttribute('data-bad', touched && !checks[rule]);
  }
  submit.disabled = busy || !file || !oldInput.value || !Object.values(checks).every(Boolean);
}
for (const input of [oldInput, newInput, repeatInput]) input.addEventListener('input', update);

function clearPasswords() {
  for (const input of [oldInput, newInput, repeatInput]) { input.value = ''; input.type = 'password'; }
  for (const button of document.querySelectorAll('.reveal')) { button.setAttribute('aria-pressed', 'false'); button.setAttribute('aria-label', 'Показать пароль'); }
}

function change(container, oldPassword, newPassword) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(api.runtime.getURL('crypto/worker.js'));
    worker.onmessage = ({ data }) => {
      worker.terminate();
      if (data.kind === 'password-changed') resolve(data);
      else { const error = new Error(data.message || 'Не удалось сменить пароль ключа.'); error.code = data.code; reject(error); }
    };
    worker.onerror = event => { event.preventDefault(); worker.terminate(); reject(new Error('Не удалось сменить пароль ключа.')); };
    worker.postMessage({ kind: 'change-password', container, oldPassword, newPassword }, [container]);
  });
}

const MESSAGES = {
  PASSWORD_OR_DAMAGED: 'Текущий пароль не подошёл или файл повреждён.',
  CERTIFICATE_NOT_VALID_NOW: 'Срок действия сертификата этого ключа ещё не наступил или уже истёк. Такой ключ Tegin не перезаписывает.'
};

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (submit.disabled) return;
  busy = true; update();
  for (const input of [oldInput, newInput, repeatInput]) input.disabled = true;
  report('Открываем ключ и проверяем новый файл. Это займёт несколько секунд.', 'busy');
  try {
    const result = await change(await file.arrayBuffer(), oldInput.value, newInput.value);
    clearPasswords();
    const { certificate, protection } = result;
    const until = new Date(certificate.notAfter).toLocaleDateString('ru-RU');
    $('#result-holder').textContent = [certificate.name || 'Владелец не указан', certificate.algorithm, `сертификат до ${until}`].join(' · ');
    $('#protection-before').textContent = [protection.before.integrity, ...protection.before.encryption].join('; ');
    $('#protection-after').textContent = [protection.after.integrity, ...protection.after.encryption].join('; ');
    if (downloadUrl) URL.revokeObjectURL(downloadUrl);
    downloadUrl = URL.createObjectURL(new Blob([result.container], { type: 'application/x-pkcs12' }));
    const download = $('#download');
    download.href = downloadUrl;
    download.download = `${file.name.replace(/\.(p12|pfx)$/i, '')} (новый пароль).p12`;
    report();
    form.hidden = true;
    $('#result').hidden = false;
    $('#result-title').focus?.();
  } catch (error) {
    report(MESSAGES[error.code] || error.message, 'error');
    if (error.code === 'PASSWORD_OR_DAMAGED') oldInput.select();
  } finally {
    busy = false;
    for (const input of [oldInput, newInput, repeatInput]) input.disabled = false;
    update();
  }
});

$('#again').addEventListener('click', () => {
  if (downloadUrl) URL.revokeObjectURL(downloadUrl);
  downloadUrl = null; file = null; fileInput.value = '';
  clearPasswords();
  $('#key-name').textContent = 'Выбрать ключ';
  $('#key-size').textContent = 'Файл .p12 или .pfx, до 4 МБ';
  picker.removeAttribute('data-selected');
  $('#result').hidden = true;
  form.hidden = false;
  report(); update();
  picker.focus();
});
update();
