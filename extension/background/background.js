import { findModule, enforceSettings } from '../modules/registry.js';
import { assembleResult } from '../modules/adapters.js';
import { normalizeRequest, successResponse, errorResponse } from '../signing/protocol.js';
import { isIssuanceRequest, issuanceOrigin, normalizeIssuance, issuanceResult, issuanceError } from '../signing/issuance-protocol.js';
import { DIAGNOSTIC_PREFIX, DIAGNOSTIC_LIMIT, diagnosticEntry, responseCode } from '../signing/diagnostics.js';

const PREFIX = 'pending:';
const TTL = 3 * 60 * 1000;
const api = globalThis.browser || chrome;
const uiUrl = api.runtime.getURL('signing/approve.html');
const PAGES = ['signing/approve.html', 'signing/issue.html'];

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

// The extension page a message came from, if it is one of the confirmation windows.
function confirmationPage(sender) {
  if (sender.id !== api.runtime.id || !sender.url) return null;
  const url = new URL(sender.url);
  return PAGES.find(page => {
    const expected = new URL(api.runtime.getURL(page));
    return url.protocol === expected.protocol && url.host === expected.host && url.pathname === expected.pathname;
  }) || null;
}
// Per-tab log of portal calls for the popup: names, argument structure and the extension's own reason, no values.
async function diagnose(tabId, request, stage, code, reason) {
  const entry = diagnosticEntry(request, stage, code, reason);
  console.info('Tegin request', JSON.stringify(entry));
  const key = DIAGNOSTIC_PREFIX + tabId;
  const list = (await api.storage.session.get(key))[key] || [];
  await api.storage.session.set({ [key]: [entry, ...list].slice(0, DIAGNOSTIC_LIMIT) });
  const failed = !['ok', 'cancelled', 'window'].includes(entry.code);
  await api.action.setBadgeText({ tabId, text: failed ? '!' : '' }).catch(() => {});
  if (failed) await api.action.setBadgeBackgroundColor({ tabId, color: '#b42318' }).catch(() => {});
}
async function refuse(tabId, request, response) {
  await diagnose(tabId, request, 'refused', responseCode(response), response.message);
  return { response };
}
const abandon = (record, reason) => finish(record, errorResponse(record.request, reason, true), reason);
// Ends the request and closes its confirmation window, which can no longer act on it.
async function closeRequest(record, reason) {
  await abandon(record, reason);
  if (record.windowId) await api.windows.remove(record.windowId).catch(() => {});
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
async function finish(record, response, reason = response.message) {
  await api.storage.session.remove(PREFIX + record.id);
  await api.alarms.clear(PREFIX + record.id);
  await diagnose(record.tabId, record.request, 'finished', responseCode(response), reason);
  try {
    await api.tabs.sendMessage(record.tabId, { kind: 'nca:response', instance: record.instance, token: record.token, response }, { frameId: record.frameId });
  } catch { /* The initiating document may have closed. */ }
}

async function handle(message, sender) {
  if (sender.id !== api.runtime.id) throw new Error('Недопустимый отправитель.');
  if (message.kind === 'nca:request') {
    if (!sender.tab || !sender.url || !Number.isInteger(sender.frameId) || !/^[a-z0-9-]{1,80}$/i.test(message.instance || '') || !/^[a-z0-9-]{1,80}$/i.test(message.token || '')) throw new Error('Некорректный источник запроса.');
    let origin = new URL(sender.url).origin;
    if (!origin.startsWith('https://') && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) throw new Error('Поддерживаются HTTPS-сайты.');
    let normalized, request = message.request, page = 'signing/approve.html';
    if (isIssuanceRequest(message.request)) {
      // Key generation and installation: NUC request portal only, verified by the sender's URL.
      try { origin = issuanceOrigin(sender); normalized = normalizeIssuance(message.request); }
      catch (error) { return refuse(sender.tab.id, message.request, issuanceError(error.code, error.message)); }
      // Only the call identity is kept; the portal's storage hints are dropped.
      request = { module: message.request.module, method: message.request.method, class: message.request.class };
      page = 'signing/issue.html';
    } else {
      try { normalized = normalizeRequest(message.request); } catch (error) { return refuse(sender.tab.id, message.request, errorResponse(message.request, error.message)); }
      const module = findModule(message.request.module);
      try { if (module) enforceSettings(module, normalized, origin, (await api.storage.local.get('moduleSettings')).moduleSettings?.[module.id]); }
      catch (error) { return refuse(sender.tab.id, message.request, errorResponse(message.request, error.message)); }
      if (normalized.immediate) {
        await diagnose(sender.tab.id, message.request, 'answered', 'ok');
        return { response: successResponse(message.request, normalized.value) };
      }
    }
    const records = Object.entries(await api.storage.session.get(null)).filter(([key]) => key.startsWith(PREFIX));
    for (const [, record] of records) if (Date.now() > record.expires) await closeRequest(record, 'Время подтверждения истекло.');
    const active = records.map(([, record]) => record).filter(record => Date.now() <= record.expires);
    if (active.length >= 4 || active.some(record => record.tabId === sender.tab.id && record.frameId === sender.frameId)) {
      await diagnose(sender.tab.id, message.request, 'refused', 'BUSY', 'Уже есть ожидающий запрос.');
      throw new Error('Уже есть ожидающий запрос. Завершите или отмените его.');
    }
    const id = crypto.randomUUID();
    const record = { id, origin, tabId: sender.tab.id, frameId: sender.frameId, instance: message.instance,
      token: message.token, request, normalized, page, expires: Date.now() + TTL };
    await api.storage.session.set({ [PREFIX + id]: record });
    await api.alarms.create(PREFIX + id, { when: record.expires });
    await diagnose(sender.tab.id, message.request, 'window', 'window');
    try {
      const win = await api.windows.create({ url: `${api.runtime.getURL(page)}#${id}`, type: 'popup', width: 870, height: 850, focused: true });
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
        await closeRequest(record, 'Операция отменена.');
      }
    }
    return { ok: true };
  }
  const page = confirmationPage(sender);
  if (!page) throw new Error('Запрос доступен только окну подтверждения расширения.');
  const record = await pending(message.id);
  if (!record) throw new Error('Запрос больше не действителен.');
  if ((record.page || 'signing/approve.html') !== page) throw new Error('Запрос открыт не в своём окне подтверждения.');
  if (message.kind === 'nca:cancel') {
    await abandon(record, 'Операция отменена пользователем.');
    return { ok: true };
  }
  if (!await alive(record)) {
    await abandon(record, 'Страница закрыта, изменена или время запроса истекло.');
    throw new Error('Исходная страница больше не доступна.');
  }
  const module = record.normalized.issuance ? null : findModule(record.request.module);
  if (module) enforceSettings(module, record.normalized, record.origin, (await api.storage.local.get('moduleSettings')).moduleSettings?.[module.id]);
  if (message.kind === 'nca:get' || message.kind === 'nca:validate') return { record };
  if (message.kind === 'nca:complete' && record.normalized.issuance) {
    await finish(record, { status: true, body: issuanceResult(record.normalized, message.result) });
    return { ok: true };
  }
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
      if (key.startsWith(PREFIX) && record.windowId === windowId) await abandon(record, 'Окно подтверждения закрыто.');
    }
  }).catch(() => {});
});
api.alarms.onAlarm.addListener(alarm => {
  if (!alarm.name.startsWith(PREFIX)) return;
  queue = queue.then(async () => {
    const record = await pending(alarm.name.slice(PREFIX.length));
    if (!record) return;
    await closeRequest(record, 'Время подтверждения истекло.');
  }).catch(() => {});
});
api.tabs.onRemoved.addListener(tabId => {
  queue = queue.then(async () => {
    for (const [key, record] of Object.entries(await api.storage.session.get(null))) {
      if (!key.startsWith(PREFIX) || record.tabId !== tabId) continue;
      await closeRequest(record, 'Страница закрыта.');
    }
    await api.storage.session.remove(DIAGNOSTIC_PREFIX + tabId);
  }).catch(() => {});
});
