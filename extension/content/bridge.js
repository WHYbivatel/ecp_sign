(() => {
  if (globalThis.__ncaBrowserBridge) return;
  globalThis.__ncaBrowserBridge = true;
  const api = globalThis.browser || chrome;
  const instance = crypto.randomUUID();
  const inflight = new Map();
  const reply = (id, response) => window.postMessage({ channel: 'ncabrowser:response', id, response }, location.origin);
  function cancel(token, pending) {
    clearTimeout(pending.timer); inflight.delete(token);
    api.runtime.sendMessage({ kind: 'nca:cancel-request', instance, token }).catch(() => {});
  }
  window.addEventListener('message', async event => {
    if (event.source !== window || event.origin !== location.origin) return;
    if (event.data?.channel === 'ncabrowser:cancel') {
      for (const [token, pending] of inflight) if (pending.id === event.data.id) cancel(token, pending);
      return;
    }
    if (event.data?.channel !== 'ncabrowser:request') return;
    const { id, request } = event.data;
    if (typeof id !== 'string' || id.length > 80 || JSON.stringify(request ?? null).length > 3 * 1024 * 1024) return;
    if (inflight.size >= 4) return reply(id, { code: '400', message: 'Слишком много запросов.' });
    const token = crypto.randomUUID();
    const timer = setTimeout(() => {
      inflight.delete(token);
      reply(id, { code: '500', message: 'Время подтверждения истекло.' });
      api.runtime.sendMessage({ kind: 'nca:cancel-request', instance, token }).catch(() => {});
    }, 185000);
    inflight.set(token, { id, timer });
    try {
      const answer = await api.runtime.sendMessage({ kind: 'nca:request', instance, token, request });
      if (answer.response || answer.error) {
        clearTimeout(timer); inflight.delete(token);
        reply(id, answer.response || { code: '400', status: false, message: answer.error });
      }
    } catch {
      clearTimeout(timer); inflight.delete(token);
      reply(id, { code: '400', status: false, message: 'Расширение недоступно. Перезагрузите страницу.' });
    }
  });
  window.addEventListener('pagehide', () => { for (const [token, pending] of inflight) cancel(token, pending); });
  api.runtime.onMessage.addListener((message, sender, respond) => {
    if (sender.id === api.runtime.id && message.kind === 'nca:status') { respond({ active: true }); return; }
    if (sender.id !== api.runtime.id || message.instance !== instance) return;
    if (message.kind === 'nca:probe') { respond({ instance }); return; }
    if (message.kind !== 'nca:response') return;
    const pending = inflight.get(message.token);
    if (!pending) return;
    clearTimeout(pending.timer); inflight.delete(message.token);
    reply(pending.id, message.response);
    respond({ ok: true });
  });
})();
