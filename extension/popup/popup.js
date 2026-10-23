const api = globalThis.browser || chrome;
const status = document.querySelector('#status');
const enable = document.querySelector('#enable');
let current;
async function openTool(mode = '') {
  try {
    const base = api.runtime.getURL('signing/approve.html');
    const url = base + (mode ? '?mode=' + mode : '');
    if (new URLSearchParams(location.search).has('workspace')) { location.assign(url); return; }
    const tabs = await api.tabs.query({ url: base + '*' });
    const existing = tabs.find(tab => !new URL(tab.url).hash);
    if (existing) {
      await api.tabs.update(existing.id, { active: true, ...(existing.url === url ? {} : { url }) });
      await api.windows.update(existing.windowId, { focused: true });
    } else await api.tabs.create({ url });
    if (!new URLSearchParams(location.search).has('workspace')) window.close();
  } catch (error) { status.textContent = error.message; }
}
if (new URLSearchParams(location.search).has('workspace')) document.body.setAttribute('data-workspace', '');
document.querySelector('#local').addEventListener('click', () => openTool());
document.querySelector('#verify').addEventListener('click', () => openTool('verify'));
async function loadSite() {
  try {
    const sourceId = new URLSearchParams(location.search).get('site');
    const tab = sourceId && /^\d+$/.test(sourceId) ? await api.tabs.get(Number(sourceId)) : (await api.tabs.query({ active: true, currentWindow: true }))[0];
    if (!tab?.url) throw new Error('Откройте обычную страницу сайта.');
    const url = new URL(tab.url);
    const local = url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname);
    if (url.protocol !== 'https:' && !local) throw new Error('Подключение доступно на HTTPS-сайтах.');
    const builtin = local || url.hostname.endsWith('.kz') || url.hostname === 'kz';
    const origin = `${url.origin}/*`;
    const allowed = builtin || await api.permissions.contains({ origins: [origin] });
    current = { tabId: tab.id, origin, allowed, builtin };
    document.querySelector('#site-name').textContent = url.host;
    const connected = allowed && await api.tabs.sendMessage(tab.id, { kind: 'nca:status' }, { frameId: 0 }).then(reply => reply?.active, () => false);
    document.querySelector('#site-state').textContent = connected ? 'Подключено' : allowed ? 'Нужно обновить' : 'Нет доступа';
    document.querySelector('#site-state').toggleAttribute('data-active', Boolean(connected));
    enable.firstChild.textContent = connected ? 'Обновить страницу сайта' : allowed ? 'Обновить для подключения' : 'Подключить сайт';
    enable.disabled = false;
  } catch (error) {
    document.querySelector('#site-name').textContent = 'Откройте сайт';
    document.querySelector('#site-state').textContent = '—';
    status.textContent = error.message;
    enable.disabled = true;
  }
}
enable.addEventListener('click', async () => {
  if (!current) return;
  try {
    enable.disabled = true;
    if (!current.allowed) {
      if (!await api.permissions.request({ origins: [current.origin] })) throw new Error('Доступ не предоставлен. Вы можете повторить подключение позже.');
    }
    if (!current.builtin) {
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(current.origin)));
      const id = [...digest.slice(0, 12)].map(byte => byte.toString(16).padStart(2, '0')).join('');
      const scripts = await api.scripting.getRegisteredContentScripts();
      const existing = scripts.filter(script => [`main-${id}`, `bridge-${id}`].includes(script.id));
      if (existing.length !== 2) {
        if (existing.length) await api.scripting.unregisterContentScripts({ ids: existing.map(script => script.id) });
        await api.scripting.registerContentScripts([
        { id: `main-${id}`, matches: [current.origin], js: ['content/inject.js'], world: 'MAIN', runAt: 'document_start', allFrames: true },
        { id: `bridge-${id}`, matches: [current.origin], js: ['content/bridge.js'], runAt: 'document_start', allFrames: true }
        ]);
      }
    }
    await api.tabs.reload(current.tabId); window.close();
  } catch (error) { status.textContent = error.message; enable.disabled = false; }
});
loadSite();
