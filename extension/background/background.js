import { findModule, enforceSettings } from '../modules/registry.js';
import { assembleResult } from '../modules/adapters.js';
import { normalizeRequest, successResponse, errorResponse } from '../signing/protocol.js';

const PREFIX = 'pending:';
const TTL = 3 * 60 * 1000;
const api = globalThis.browser || chrome;
const uiUrl = api.runtime.getURL('signing/approve.html');

// Local tools live in one normal browser tab; portal approval stays isolated.
api.action.onClicked.addListener(async tab => {
  const home = api.runtime.getURL('index.html');
  const modulesPage = api.runtime.getURL('modules/index.html');
  const tabs = await api.tabs.query({ url: [home + '*', uiUrl + '*', modulesPage + '*'] });
  const existing = tabs.find(item => item.url && !new URL(item.url).hash);
  if (existing) {
    await api.tabs.update(existing.id, { active: true });
    await api.windows.update(existing.windowId, { focused: true });
  } else {
    const source = Number.isInteger(tab?.id) ? '&site=' + tab.id : '';
    await api.tabs.create({ url: home + '?workspace=1' + source, ...(tab?.windowId ? { windowId: tab.windowId } : {}) });
  }
});

function isConfirmation(sender) {
  if (sender.id !== api.runtime.id || !sender.url) return false;
  const url = new URL(sender.url);
  const expected = new URL(uiUrl);
  return url.protocol === expected.protocol && url.host === expected.host && url.pathname === expected.pathname;
}
async function pending(id) { return (await api.storage.session.get(PREFIX + id))[PREFIX + id]; }
async function alive(record) {
  if (Date.now() > record.expires) return false;
  try {
    const answer = await Promise.race([
      api.tabs.sendMessage(record.tabId, { kind: 'nca:probe', instance: record.instance }, { frameId: record.frameId }),
      new Promise(resolve => setTimeout(() => resolve(null), 3000))
    ]);
    return answer?.instance === record.instance;
  } catch { return false; }
}
async function finish(record, response) {
  await api.storage.session.remove(PREFIX + record.id);
  await api.alarms.clear(PREFIX + record.id);
  try {
    await api.tabs.sendMessage(record.tabId, { kind: 'nca:response', instance: record.instance, token: record.token, response }, { frameId: record.frameId });
  } catch { /* The initiating document may have closed. */ }
}

async function handle(message, sender) {
  if (sender.id !== api.runtime.id) throw new Error('Недопустимый отправитель.');
  if (message.kind === 'nca:request') {
    if (!sender.tab || !sender.url || !Number.isInteger(sender.frameId) || !/^[a-z0-9-]{1,80}$/i.test(message.instance || '') || !/^[a-z0-9-]{1,80}$/i.test(message.token || '')) throw new Error('Некорректный источник запроса.');
    const origin = new URL(sender.url).origin;
    if (!origin.startsWith('https://') && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) throw new Error('Поддерживаются HTTPS-сайты.');
    let normalized;
    try { normalized = normalizeRequest(message.request); } catch (error) { return { response: errorResponse(message.request, error.message) }; }
    const module = findModule(message.request.module);
    try { if (module) enforceSettings(module, normalized, origin, (await api.storage.local.get('moduleSettings')).moduleSettings?.[module.id]); }
    catch (error) { return { response: errorResponse(message.request, error.message) }; }
    if (normalized.immediate) return { response: successResponse(message.request, normalized.value) };
    const records = Object.entries(await api.storage.session.get(null)).filter(([key]) => key.startsWith(PREFIX));
    for (const [, record] of records) if (Date.now() > record.expires) await finish(record, errorResponse(record.request, 'Время подтверждения истекло.', true));
    const active = records.map(([, record]) => record).filter(record => Date.now() <= record.expires);
    if (active.length >= 4 || active.some(record => record.tabId === sender.tab.id && record.frameId === sender.frameId)) throw new Error('Уже есть ожидающий запрос. Завершите или отмените его.');
    const id = crypto.randomUUID();
    const record = { id, origin, tabId: sender.tab.id, frameId: sender.frameId, instance: message.instance,
      token: message.token, request: message.request, normalized, expires: Date.now() + TTL };
    await api.storage.session.set({ [PREFIX + id]: record });
    await api.alarms.create(PREFIX + id, { when: record.expires });
    try {
      const win = await api.windows.create({ url: `${uiUrl}#${id}`, type: 'popup', width: 870, height: 850, focused: true });
      record.windowId = win.id;
      // A window closed immediately during startup must not resurrect its request.
      if (await pending(id)) await api.storage.session.set({ [PREFIX + id]: record });
      return { accepted: true };
    } catch (error) { await api.storage.session.remove(PREFIX + id); throw error; }
  }
  if (message.kind === 'nca:cancel-request' && sender.tab) {
    const records = await api.storage.session.get(null);
    for (const [key, record] of Object.entries(records)) {
      if (key.startsWith(PREFIX) && record.tabId === sender.tab.id && record.frameId === sender.frameId && record.instance === message.instance && record.token === message.token) {
        await finish(record, errorResponse(record.request, 'Операция отменена.', true));
        if (record.windowId) await api.windows.remove(record.windowId).catch(() => {});
      }
    }
    return { ok: true };
  }
  if (!isConfirmation(sender)) throw new Error('Запрос доступен только окну подтверждения расширения.');
  const record = await pending(message.id);
  if (!record) throw new Error('Запрос больше не действителен.');
  if (message.kind === 'nca:cancel') {
    await finish(record, errorResponse(record.request, 'Операция отменена пользователем.', true));
    return { ok: true };
  }
  if (!await alive(record)) {
    await finish(record, errorResponse(record.request, 'Страница закрыта, изменена или время запроса истекло.', true));
    throw new Error('Исходная страница больше не доступна.');
  }
  const module = findModule(record.request.module);
  if (module) enforceSettings(module, record.normalized, record.origin, (await api.storage.local.get('moduleSettings')).moduleSettings?.[module.id]);
  if (message.kind === 'nca:get' || message.kind === 'nca:validate') return { record };
  if (message.kind === 'nca:complete') {
    const result = assembleResult(record.normalized, message.result);
    await finish(record, successResponse(record.request, result));
    return { ok: true };
  }
  throw new Error('Неизвестное сообщение.');
}

// Serialize mutations: simultaneous frames must not bypass the pending limit.
let queue = Promise.resolve();
api.runtime.onMessage.addListener((message, sender, respond) => {
  if (typeof message?.kind !== 'string' || !message.kind.startsWith('nca:')) return false;
  const work = queue.then(() => handle(message, sender));
  queue = work.catch(() => {});
  work.then(respond, error => respond({ error: error.message }));
  return true;
});
api.windows.onRemoved.addListener(windowId => {
  queue = queue.then(async () => {
    for (const [key, record] of Object.entries(await api.storage.session.get(null))) {
      if (key.startsWith(PREFIX) && record.windowId === windowId) await finish(record, errorResponse(record.request, 'Окно подтверждения закрыто.', true));
    }
  }).catch(() => {});
});
api.alarms.onAlarm.addListener(alarm => {
  if (!alarm.name.startsWith(PREFIX)) return;
  queue = queue.then(async () => {
    const record = await pending(alarm.name.slice(PREFIX.length));
    if (!record) return;
    await finish(record, errorResponse(record.request, 'Время подтверждения истекло.', true));
    if (record.windowId) await api.windows.remove(record.windowId).catch(() => {});
  }).catch(() => {});
});
api.tabs.onRemoved.addListener(tabId => {
  queue = queue.then(async () => {
    for (const [key, record] of Object.entries(await api.storage.session.get(null))) {
      if (!key.startsWith(PREFIX) || record.tabId !== tabId) continue;
      await finish(record, errorResponse(record.request, 'Страница закрыта.', true));
      if (record.windowId) await api.windows.remove(record.windowId).catch(() => {});
    }
  }).catch(() => {});
});
