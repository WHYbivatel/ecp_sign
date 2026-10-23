import { base64, unbase64, bytes as binaryBytes } from '../lib/bytes.js';

const $ = selector => document.querySelector(selector);
const api = globalThis.browser || chrome;
const id = location.hash.slice(1);
let verifyMode = !id && new URLSearchParams(location.search).get('mode') === 'verify';
const DOC_LIMIT = 2 * 1024 * 1024, SIGNATURE_LIMIT = 8 * 1024 * 1024;
let request, worker, selectedCertificate, signatureFile, localName = '', generation = 0, previewGeneration = 0;
let finished = false, busy = false, downloadUrl, deadline = Date.now() + 180000;
let signatureInfo, createdSignature, createdName = '';
const status = $('#status');
const sizeLabel = count => count < 1024 ? `${count} Б` : `${new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 }).format(count / 1024)} КБ`;
const hex = value => [...value].map(byte => byte.toString(16).padStart(2, '0')).join('');

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
function updateControls() {
  $('#unlock').disabled = busy || finished || !request || !$('#key-file').files[0] || !$('#password').value;
  $('#approve').disabled = busy || finished || !worker || !selectedCertificate;
  $('#verify-submit').disabled = busy || finished || !signatureFile || !signatureInfo;
  for (const selector of ['#document', '#format', '#key-file', '#password', '#change-key']) $(selector).disabled = busy || finished;
  $('#original').disabled = busy || finished || !signatureInfo || signatureInfo.attached;
}
function lock() {
  generation++;
  worker?.terminate(); worker = null; selectedCertificate = null;
  busy = false;
  $('#password').value = ''; $('#password').type = 'password';
  $('#show-password').setAttribute('aria-pressed', 'false');
  $('#show-password').setAttribute('aria-label', 'Показать пароль');
  $('#certificate').hidden = true;
  $('#key-form').hidden = verifyMode;
  $('#step').textContent = '01 / 02';
  updateControls();
}
function dropTarget(label, input) {
  label.addEventListener('dragover', event => { event.preventDefault(); if (!busy && !finished) label.setAttribute('data-drag', ''); });
  label.addEventListener('dragleave', () => label.removeAttribute('data-drag'));
  label.addEventListener('drop', event => {
    event.preventDefault(); label.removeAttribute('data-drag');
    if (busy || finished || !event.dataTransfer.files.length) return;
    const files = new DataTransfer(); files.items.add(event.dataTransfer.files[0]);
    input.files = files.files; input.dispatchEvent(new Event('change'));
  });
}
dropTarget($('#document-drop'), $('#document'));
dropTarget($('#key-drop'), $('#key-file'));

for (const [name, other] of [['preview', 'source'], ['source', 'preview']]) $('#tab-' + name).addEventListener('click', () => {
  $('#' + name).hidden = false; $('#' + other).hidden = true;
  $('#tab-' + name).setAttribute('aria-selected', 'true'); $('#tab-' + other).setAttribute('aria-selected', 'false');
});
$('#show-password').addEventListener('click', () => {
  const shown = $('#password').type === 'password';
  $('#password').type = shown ? 'text' : 'password';
  $('#show-password').setAttribute('aria-pressed', String(shown));
  $('#show-password').setAttribute('aria-label', shown ? 'Скрыть пароль' : 'Показать пароль');
});
$('#password').addEventListener('input', updateControls);
$('#change-key').addEventListener('click', () => { lock(); report('Введите пароль или выберите другой ключ.'); $('#password').focus(); });

async function showData() {
  const revision = ++previewGeneration;
  $('#preview').textContent = verifyMode ? 'Выберите файл CMS/CAdES для проверки.' : 'Выберите документ для подписи.'; $('#source').textContent = '';
  if (verifyMode) $('#data-description').textContent = 'Проверка подписи не требует ключа ЭЦП.';
  $('#document-meta').hidden = true; $('#timestamp-note').hidden = !request?.timestamp;
  $('#document-count').textContent = '';
  if (!request) return;
  const info = request.operation === 'info';
  const label = request.timestamp ? 'CAdES-T' : request.cades ? 'CAdES-BES' : request.format.toUpperCase();
  $('#operation').textContent = info ? 'Сведения о сертификате' : `${label} · ${request.digested ? 'хеш документа' : request.documents.length + ' док.'}`;
  $('#data-description').textContent = info ? 'Сайт получит публичный сертификат. Закрытый ключ не передаётся.' : request.digested ? 'Сайт передал только хеш. Сам документ недоступен для просмотра. Подтверждая операцию, вы подписываете этот хеш.' : 'Проверьте документ: подпись будет создана для переданных данных.';
  $('#footer-note').lastChild.textContent = request.digested ? 'Подтверждение подписи хеша' : 'Подпись только с вашего согласия';
  if (info) { $('#preview').textContent = 'Для этой операции документ не требуется.'; $('#source').textContent = 'Публичные сведения о выбранном сертификате.'; return; }
  const previews = [], sources = []; let total = 0; const hashes = [];
  for (let index = 0; index < request.documents.length; index++) {
    const source = request.documents[index];
    const data = request.decode ? unbase64(source) : new TextEncoder().encode(source);
    try {
      total += data.length;
      let text;
      if (request.digested) text = `Хеш документа (${data.length} байт)\n\n${hex(data)}`;
      else {
        try {
          text = new TextDecoder('utf-8', { fatal: true }).decode(data);
          if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(text)) throw new Error();
        } catch { text = 'Бинарный документ\n\nЕго исходные байты будут использованы без изменения. Base64 доступен на вкладке «Исходные данные».'; }
      }
      const heading = request.documents.length > 1 ? `ДОКУМЕНТ ${index + 1}\n\n` : '';
      const clipped = value => value.length > 100000 ? value.slice(0, 100000) + '\n\n[Показаны первые 100 000 символов; подписываются все исходные данные.]' : value;
      previews.push(heading + clipped(text)); sources.push(heading + clipped(source));
      hashes.push(hex(new Uint8Array(await crypto.subtle.digest('SHA-256', data))));
    } finally { data.fill(0); }
  }
  if (revision !== previewGeneration) return;
  $('#preview').textContent = previews.join('\n\n'); $('#source').textContent = sources.join('\n\n');
  $('#document-count').textContent = request.documents.length > 1 ? `${request.documents.length} документа` : '';
  $('#document-size').textContent = sizeLabel(total);
  $('#document-hash').textContent = hashes.join('\n'); $('#document-meta').hidden = false;
}

async function localDocument(autoVerify = false) {
  lock(); request = null; signatureFile?.fill(0); signatureFile = null; signatureInfo = null;
  $('#original').value = ''; $('#original-controls').hidden = true;
  const file = $('#document').files[0];
  if (!file) { await showData(); updateControls(); return; }
  localName = file.name;
  $('#document-label').textContent = file.name; $('#document-hint').textContent = `${sizeLabel(file.size)} · нажмите, чтобы заменить`;
  const limit = verifyMode ? SIGNATURE_LIMIT : DOC_LIMIT;
  if (file.size > limit) throw new Error(`Файл превышает ${limit / 1024 / 1024} МБ.`);
  const current = generation;
  const buffer = new Uint8Array(await file.arrayBuffer());
  try {
    if (current !== generation) return;
    if (verifyMode) {
      signatureFile = buffer.slice();
      $('#preview').textContent = 'Определяем, находится ли документ внутри подписи…';
      $('#source').textContent = base64(buffer).slice(0, 100000);
      $('#operation').textContent = 'Проверка CMS / CAdES';
      $('#data-description').textContent = 'Файл и исходный документ останутся на устройстве.';
      $('#document-size').textContent = sizeLabel(buffer.length);
      $('#document-hash').textContent = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', buffer)));
      $('#document-meta').hidden = false;
      if (current !== generation) return;
      busy = true; updateControls(); report('Определяем тип подписи…');
      startWorker(current, async data => {
        if (data.kind !== 'inspected') return;
        signatureInfo = data; busy = false;
        $('#original-controls').hidden = data.attached;
        $('#preview').textContent = data.attached ? 'Документ уже находится внутри подписи. Исходный файл выбирать не нужно.' : 'Это отдельная подпись. Добавьте исходный документ, который подписывали.';
        report(data.attached ? 'Файл готов к проверке.' : 'Добавьте исходный документ ниже.');
        updateControls();
        if (autoVerify && data.attached) await verifySelected();
      });
      const signature = signatureFile.slice().buffer;
      worker.postMessage({ kind: 'inspect', signature }, [signature]);
    } else {
      const format = $('#format').value;
      request = { operation: 'sign', format: format === 'xml' ? 'xml' : 'cms',
        documents: [format === 'xml' ? new TextDecoder('utf-8', { fatal: true }).decode(buffer) : base64(buffer)],
        decode: format !== 'xml', encapsulate: !format.endsWith('-detached'), cades: format.startsWith('cades'), timestamp: format === 'cades-t' };
      await showData();
    }
    if (!verifyMode) report('Документ загружен. Выберите ключ ЭЦП.'); updateControls();
  } finally { buffer.fill(0); }
}
for (const selector of ['#document', '#format']) $(selector).addEventListener('change', () => localDocument().catch(error => { report(error.message, true); updateControls(); }));
$('#original').addEventListener('change', () => {
  report($('#original').files[0] ? 'Исходный документ выбран. Можно проверить подпись.' : 'Добавьте исходный документ.'); updateControls();
});
$('#key-file').addEventListener('change', () => {
  lock(); const file = $('#key-file').files[0];
  $('#key-name').textContent = file?.name || 'Выбрать ключ'; $('#key-size').textContent = file ? sizeLabel(file.size) : 'Файл .p12 или .pfx';
  report(file ? 'Ключ выбран. Введите пароль.' : ''); updateControls();
});

function showCertificate(certificate) {
  selectedCertificate = certificate;
  $('#key-form').hidden = true; $('#certificate').hidden = false;
  $('#holder').textContent = certificate.name || 'Сертификат ЭЦП';
  $('#cert-details').textContent = `${certificate.algorithm}\nДействует до ${new Date(certificate.notAfter).toLocaleDateString('ru-RU')}${certificate.organization ? '\n' + certificate.organization : ''}`;
  const trusted = certificate.trust?.trusted;
  $('#trust-state').toggleAttribute('data-trusted', Boolean(trusted));
  $('#trust-state').textContent = trusted ? (certificate.trust.scope === 'site' ? 'Цепочка УЦ, указанного сайтом, проверена' : 'Цепочка НУЦ РК подтверждена') : 'Цепочка доверия не подтверждена';
  $('#trust-note').textContent = trusted ? 'Подпись ключа и срок действия проверены локально.' : 'Ключ соответствует сертификату, но его УЦ не распознан. Подтверждайте операцию, только если доверяете этому сертификату.';
  $('#cert-identifier').textContent = [certificate.iin, certificate.bin].filter(Boolean).join(' / ') || 'Не указан';
  $('#cert-serial').textContent = certificate.serialNumber;
  $('#cert-fingerprint').textContent = certificate.fingerprint || '—';
  $('#step').textContent = '02 / 02'; updateControls();
}
function startWorker(current, handler) {
  worker = new Worker(api.runtime.getURL('crypto/worker.js'));
  worker.onerror = () => { if (current !== generation) return; lock(); report('Не удалось выполнить локальную криптографическую операцию.', true); };
  worker.onmessage = async ({ data }) => {
    if (current !== generation || finished) return;
    try {
      if (data.kind === 'error') { lock(); report(data.message, true); return; }
      await handler(data);
    } catch (error) { lock(); report(error.message, true); }
  };
}
function resultScreen({ title, description, details, download, filename, warning = false }) {
  finished = true; lock(); $('#key-file').value = '';
  $('#workspace').hidden = true; $('#result-screen').hidden = false; $('.approval-footer').hidden = true;
  $('#result-title').textContent = title; $('#result-description').textContent = description;
  $('#result-details').textContent = details;
  $('#result-icon').toggleAttribute('data-warning', warning);
  if (downloadUrl) { URL.revokeObjectURL(downloadUrl); downloadUrl = null; }
  $('#download').hidden = !download;
  if (download) {
    downloadUrl = URL.createObjectURL(download); $('#download').href = downloadUrl; $('#download').download = filename;
    $('#download-label').textContent = verifyMode ? 'Скачать подписанный документ' : 'Скачать подпись';
  }
  $('#verify-created').hidden = true;
  $('#again').hidden = Boolean(id);
  $('#again').textContent = verifyMode ? 'Проверить другую подпись' : 'Подписать ещё один файл';
}

$('#key-form').addEventListener('submit', async event => {
  event.preventDefault(); let container;
  try {
    if (finished || busy || !request) return;
    const file = $('#key-file').files[0]; if (!file || file.size > 4 * 1024 * 1024) throw new Error('Выберите файл ключа размером до 4 МБ.');
    let password = $('#password').value; if (!password) return;
    lock(); const current = generation; busy = true; updateControls(); report('Открываем ключ и проверяем сертификат…');
    if (id) await message('nca:validate');
    container = await file.arrayBuffer(); if (current !== generation || finished) return;
    startWorker(current, async data => {
      if (data.kind === 'opened') { busy = false; showCertificate(data.certificate); report('Ключ готов. Проверьте данные и подтвердите подпись.'); }
      else if (data.kind === 'signed') {
        const certificate = selectedCertificate;
        if (id) {
          await message('nca:complete', { result: data.result });
          resultScreen({ title: 'Подпись передана сайту', description: 'Операция завершена. Можно продолжить работу на сайте.', details: `${certificate.name}\n${request.timestamp ? 'Метка времени НУЦ проверена.' : 'Без метки времени.'}` });
          setTimeout(() => window.close(), 1200);
        } else {
          const xml = request.format === 'xml';
          const value = xml ? data.result[0] : unbase64(data.result[0]);
          const stamp = data.timestamps?.[0];
          resultScreen({ title: 'Документ подписан', description: 'Сохраните результат на своё устройство.',
            details: `${localName}\n${certificate.name}\n${stamp ? 'Метка НУЦ: ' + new Date(stamp.time).toLocaleString('ru-RU') : 'Подпись создана локально, без метки времени.'}`,
            download: new Blob([value], { type: xml ? 'application/xml' : 'application/pkcs7-mime' }),
            filename: (localName || 'document').replace(/[\\/]/g, '_') + (xml ? '.signed.xml' : '.p7s') });
          if (value instanceof Uint8Array) {
            createdSignature?.fill(0);
            createdSignature = request.encapsulate ? value.slice() : null;
            createdName = (localName || 'document') + '.p7s';
            $('#verify-created').hidden = !createdSignature;
            value.fill(0);
          }
        }
      }
    });
    worker.postMessage({ kind: 'open', container, password, request }, [container]); password = ''; container = null;
  } catch (error) { lock(); report(error.message, true); }
  finally { if (container?.byteLength) new Uint8Array(container).fill(0); }
});
$('#approve').addEventListener('click', async () => {
  if (busy || finished || !worker || !selectedCertificate) return;
  try {
    busy = true; updateControls(); report(request.timestamp ? 'Создаём подпись и запрашиваем метку НУЦ…' : 'Создаём подпись на устройстве…');
    if (id) await message('nca:validate');
    if (request.operation === 'info') {
      const certificate = selectedCertificate;
      await message('nca:complete', { result: { ...certificate, cert: certificate.certificate,
        subjectDn: certificate.subjectDn, issuerDn: certificate.issuerDn } });
      resultScreen({ title: 'Сведения переданы', description: 'Сайт получил публичный сертификат.', details: certificate.name });
      setTimeout(() => window.close(), 1000); return;
    }
    worker.postMessage({ kind: 'sign', request });
  } catch (error) { lock(); report(error.message, true); }
});
async function verifySelected() {
  if (busy || finished || !signatureFile || !signatureInfo) return;
  if (!signatureInfo.attached && !$('#original').files[0]) { report('Для этой отдельной подписи нужен исходный документ. Выберите файл, который подписывали.', true); return; }
  let original;
  try {
    lock(); const current = generation; busy = true; updateControls(); report('Проверяем подпись и цепочку сертификата…');
    const file = signatureInfo.attached ? undefined : $('#original').files[0];
    if (file?.size > DOC_LIMIT) throw new Error('Исходный документ превышает 2 МБ.');
    original = file ? await file.arrayBuffer() : undefined;
    if (current !== generation) return;
    startWorker(current, async data => {
      if (data.kind !== 'verified') return;
      const content = new Uint8Array(data.content);
      const trusted = data.signers.every(signer => signer.trust.trusted);
      const details = data.signers.map(signer => `${signer.name}\n${signer.algorithm}\n${signer.trust.trusted ? 'Цепочка НУЦ РК подтверждена' : 'Цепочка доверия не подтверждена'}`).join('\n\n');
      resultScreen({ title: 'Подпись верна', description: 'Содержимое соответствует криптографической подписи.',
        details: details + '\n\n' + (data.timestamps.length ? `Метка времени: ${new Date(data.timestamps[0].time).toLocaleString('ru-RU')}\n` : '') + 'Статус отзыва сертификатов не проверялся.',
        warning: !trusted, download: new Blob([content], { type: 'application/octet-stream' }), filename: (localName.replace(/\.(p7s|p7m|cms)$/i, '') || 'signed-document') + ( /\.[a-z0-9]{1,8}$/i.test(localName.replace(/\.(p7s|p7m|cms)$/i, '')) ? '' : '.bin') });
      content.fill(0);
    });
    const signature = signatureFile.slice().buffer;
    worker.postMessage({ kind: 'verify', signature, original }, original ? [signature, original] : [signature]); original = null;
  } catch (error) { lock(); report(error.message, true); }
  finally { if (original?.byteLength) new Uint8Array(original).fill(0); }
}
$('#verify-submit').addEventListener('click', verifySelected);
$('#cancel').addEventListener('click', async () => {
  finished = true; lock();
  if (id) { await message('nca:cancel').catch(() => {}); window.close(); }
  else location.assign(api.runtime.getURL('index.html?workspace=1'));
});
function localMode(mode, push = true) {
  if (id) return;
  verifyMode = mode === 'verify'; finished = false; lock(); previewGeneration++;
  request = null; signatureInfo = null;
  signatureFile?.fill(0); signatureFile = null; createdSignature?.fill(0); createdSignature = null;
  for (const selector of ['#document', '#original', '#key-file']) $(selector).value = '';
  $('#format').value = 'cms'; $('#advanced-settings').open = false;
  $('#key-name').textContent = 'Выбрать ключ'; $('#key-size').textContent = 'Файл .p12 или .pfx';
  $('#workspace').hidden = false; $('#result-screen').hidden = true; $('.approval-footer').hidden = false;
  $('#local-controls').hidden = false; $('#original-controls').hidden = true; $('#tool-nav').hidden = false;
  document.body.toggleAttribute('data-verify', verifyMode);
  $('#nav-sign').setAttribute('aria-current', verifyMode ? 'false' : 'page'); $('#nav-verify').setAttribute('aria-current', verifyMode ? 'page' : 'false');
  $('#title').textContent = verifyMode ? 'Проверить подпись' : 'Подписать документ';
  $('#subtitle').textContent = verifyMode ? 'Выберите подписанный файл. Ключ ЭЦП не нужен.' : 'Выберите документ, откройте ключ и подтвердите подпись.';
  $('#step').hidden = verifyMode; $('#operation').textContent = verifyMode ? 'Проверка подписи' : '';
  $('#file-heading').textContent = verifyMode ? 'Подписанный файл' : 'Документ';
  $('#document').accept = verifyMode ? '.p7s,.p7m,.cms' : '';
  $('#document-label').textContent = verifyMode ? 'Выберите подписанный файл' : 'Выберите или перетащите файл';
  $('#document-hint').textContent = verifyMode ? '.p7s, .p7m или .cms · до 8 МБ' : 'До 2 МБ · данные обрабатываются локально';
  $('#format-controls').hidden = verifyMode; $('#key-form').hidden = verifyMode; $('#verify-info').hidden = !verifyMode;
  $('#approve').hidden = verifyMode; $('#verify-submit').hidden = !verifyMode;
  $('#cancel').textContent = 'На главную';
  $('#footer-note').lastChild.textContent = verifyMode ? 'Данные не отправляются в сеть' : 'Подпись только с вашего согласия';
  $('.privacy-label').lastChild.textContent = verifyMode ? 'Проверка без передачи файлов' : 'Ваш ключ — только на устройстве';
  $('.security-note p').textContent = verifyMode ? 'Документ и подпись обрабатываются локально. Ключ ЭЦП не требуется.' : 'Закрытый ключ не передаётся сайту. Подпись создаётся в вашем браузере.';
  $('#tab-preview').click();
  if (downloadUrl) { URL.revokeObjectURL(downloadUrl); downloadUrl = null; }
  deadline = Date.now() + 180000;
  showData().catch(error => report(error.message, true)); updateControls(); report();
  if (push) history.pushState({ mode }, '', verifyMode ? '?mode=verify' : location.pathname);
}
for (const mode of ['sign', 'verify']) $('#nav-' + mode).addEventListener('click', event => { event.preventDefault(); localMode(mode); });
window.addEventListener('popstate', () => { if (!id) localMode(new URLSearchParams(location.search).get('mode'), false); });
$('#again').addEventListener('click', () => localMode(verifyMode ? 'verify' : 'sign', false));
$('#verify-created').addEventListener('click', async () => {
  if (!createdSignature) return;
  const value = createdSignature.slice(); const name = createdName;
  localMode('verify');
  try {
    const transfer = new DataTransfer(); transfer.items.add(new File([value], name, { type: 'application/pkcs7-mime' }));
    $('#document').files = transfer.files;
    await localDocument(true);
  } catch (error) { report(error.message, true); }
  finally { value.fill(0); }
});
window.addEventListener('pagehide', () => { lock(); signatureFile?.fill(0); createdSignature?.fill(0); if (downloadUrl) URL.revokeObjectURL(downloadUrl); });
setInterval(() => {
  if (finished || Date.now() < deadline) return;
  finished = true; lock(); report('Время операции истекло. Повторите запрос или откройте инструмент заново.', true);
  if (id) message('nca:cancel').catch(() => {});
}, 1000);

async function init() {
  try {
    if (id) {
      const { record } = await message('nca:get'); request = record.normalized; deadline = record.expires;
      $('#origin').textContent = record.origin;
      if (request.operation === 'info') { $('#title').textContent = 'Передать сведения'; $('#approve-label').textContent = 'Передать сведения'; }
      await showData();
    } else localMode(verifyMode ? 'verify' : 'sign', false);
    updateControls();
  } catch (error) { finished = true; lock(); report(error.message, true); }
}
init();
