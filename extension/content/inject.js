(() => {
  if (window.WebSocket.__ncaBrowserAdapter) return;
  const NativeWebSocket = window.WebSocket;
  const nativeFetch = window.fetch;
  const sockets = new Map();
  function isNca(value) {
    try {
      const url = new URL(value, location.href);
      return ['wss:', 'ws:', 'https:', 'http:'].includes(url.protocol) && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) && url.port === '13579';
    } catch { return false; }
  }
  class LocalSocket extends EventTarget {
    constructor(url) {
      super();
      this.url = new URL(url, location.href).href;
      this.readyState = 0; this.bufferedAmount = 0; this.extensions = ''; this.protocol = ''; this.binaryType = 'blob';
      this.onopen = null; this.onmessage = null; this.onerror = null; this.onclose = null;
      this.pending = null; this.hasSentRequest = false;
      setTimeout(() => {
        if (this.readyState !== 0) return;
        this.readyState = 1; this.emit('open', new Event('open'));
        setTimeout(() => { if (this.readyState === 1 && !this.hasSentRequest) this.message({ result: { version: '1.4', implementation: 'Tegin' } }); }, 0);
      }, 0);
    }
    emit(type, event) { this.dispatchEvent(event); if (typeof this[`on${type}`] === 'function') this[`on${type}`](event); }
    message(value) { this.emit('message', new MessageEvent('message', { data: typeof value === 'string' ? value : JSON.stringify(value), origin: new URL(this.url).origin })); }
    send(data) {
      if (this.readyState === 0) throw new DOMException('WebSocket is connecting', 'InvalidStateError');
      if (this.readyState !== 1) return;
      if (data === '--heartbeat--') { setTimeout(() => this.message(data), 0); return; }
      if (typeof data !== 'string' || data.length > 3 * 1024 * 1024) { this.close(1008, 'Request too large'); return; }
      let request;
      try { request = JSON.parse(data); } catch { this.message({ code: '400', status: false, message: 'Некорректный JSON.' }); return; }
      if (this.pending) { this.close(1008, 'Only one pending request per socket'); return; }
      this.hasSentRequest = true;
      const id = crypto.randomUUID(); this.pending = id; sockets.set(id, this);
      window.postMessage({ channel: 'ncabrowser:request', id, request }, location.origin);
    }
    close(code = 1000, reason = '') {
      if (this.readyState === 3) return;
      if (this.pending) {
        window.postMessage({ channel: 'ncabrowser:cancel', id: this.pending }, location.origin);
        sockets.delete(this.pending); this.pending = null;
      }
      this.readyState = 3;
      this.emit('close', new CloseEvent('close', { code, reason, wasClean: true }));
    }
  }
  for (const [key, value] of Object.entries({ CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 })) {
    Object.defineProperty(LocalSocket.prototype, key, { value });
  }
  function WebSocket(url, protocols) {
    if (!new.target) throw new TypeError('Use new WebSocket');
    const parsed = new URL(url, location.href);
    if (!['ws:', 'wss:'].includes(parsed.protocol)) throw new DOMException('Invalid WebSocket protocol', 'SyntaxError');
    if (isNca(parsed.href)) return new LocalSocket(parsed.href);
    return protocols === undefined ? new NativeWebSocket(url) : new NativeWebSocket(url, protocols);
  }
  Object.setPrototypeOf(WebSocket, NativeWebSocket);
  WebSocket.prototype = NativeWebSocket.prototype;
  Object.defineProperty(WebSocket, '__ncaBrowserAdapter', { value: true });
  Object.defineProperty(WebSocket, Symbol.hasInstance, { value: value => value instanceof LocalSocket || value instanceof NativeWebSocket });
  window.WebSocket = WebSocket;
  if (nativeFetch) window.fetch = function(input, options) {
    const url = typeof input === 'string' || input instanceof URL ? String(input) : input.url;
    if (isNca(url)) return Promise.resolve(new Response('', { status: 200 }));
    return nativeFetch.call(this, input, options);
  };
  window.addEventListener('message', event => {
    if (event.source !== window || event.origin !== location.origin || event.data?.channel !== 'ncabrowser:response') return;
    const socket = sockets.get(event.data.id);
    if (!socket || socket.readyState !== 1) return;
    sockets.delete(event.data.id); socket.pending = null;
    socket.message(event.data.response);
  });
})();
