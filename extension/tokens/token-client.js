import { certificateInfo } from '../crypto/signer.js';
import { O } from '../crypto/encoding.js';
import { base64, unbase64 } from '../lib/bytes.js';

// Client of the local token host (docs/hardware-tokens.md) over a Native Messaging port. Not wired into
// the extension yet: connecting needs the "nativeMessaging" permission and an installed host, which ends
// the "no extra programs" property and is a separate decision. The port is runtime.connectNative's Port
// or any object with postMessage, onMessage, onDisconnect and disconnect.
export const TOKEN_HOST = 'kz.tegin.token';
export const TOKEN_PROTOCOL = 1;
const LIMITS = { tokens: 16, certificates: 32, certificate: 16 * 1024, signature: 2048, data: 16 * 1024, text: 128 };
export const TOKEN_MESSAGES = {
  PIN_INCORRECT: 'PIN не подошёл. Tegin не повторяет ввод сам: число попыток на токене ограничено.',
  PIN_LOCKED: 'PIN заблокирован на токене. Разблокировка — средствами производителя токена или в ЦОН.',
  PIN_LEN_RANGE: 'Длина PIN не подходит для этого токена.',
  PIN_INVALID: 'PIN содержит недопустимые символы.',
  PIN_REQUIRED: 'Введите PIN токена.',
  TOKEN_REMOVED: 'Токен извлечён или заменён. Подключите тот же токен и выберите сертификат снова.',
  KEY_NOT_FOUND: 'На токене нет ключа для выбранного сертификата.',
  MECHANISM_UNSUPPORTED: 'Токен не поддерживает нужный алгоритм подписи.',
  CANCELLED: 'Операция отменена.',
  BUSY: 'Токен занят другой операцией.',
  HOST_UNAVAILABLE: 'Программа для работы с токенами не установлена или не отвечает.',
  TIMEOUT: 'Токен не ответил вовремя.',
  BAD_RESPONSE: 'Некорректный ответ программы для работы с токенами.'
};
export class TokenError extends Error {
  constructor(code) { super(TOKEN_MESSAGES[code] || TOKEN_MESSAGES.BAD_RESPONSE); this.code = TOKEN_MESSAGES[code] ? code : 'TOKEN_ERROR'; }
}

const isText = (value, limit = LIMITS.text) => typeof value === 'string' && value.length <= limit;
const isBase64 = (value, limit) => typeof value === 'string' && value.length <= Math.ceil(limit / 3) * 4 && /^[A-Za-z0-9+/]*={0,2}$/.test(value);
function validTokens(tokens) {
  return Array.isArray(tokens) && tokens.length <= LIMITS.tokens && tokens.every(token =>
    Number.isInteger(token.module) && Number.isInteger(token.slot) && ['label', 'manufacturer', 'model', 'serial', 'moduleName'].every(key => isText(token[key])) &&
    token.flags && typeof token.flags === 'object' && Array.isArray(token.certificates) && token.certificates.length <= LIMITS.certificates &&
    token.certificates.every(cert => /^[0-9a-f]{2,128}$/.test(cert.keyId) && /^[0-9a-f]{64}$/.test(cert.sha256) && isText(cert.label) && isBase64(cert.certificate, LIMITS.certificate)));
}

export class TokenClient {
  constructor(port, { timeout = 180000 } = {}) {
    this.port = port; this.timeout = timeout; this.pending = new Map(); this.sequence = 0; this.closed = false;
    port.onMessage.addListener(message => this.receive(message));
    port.onDisconnect.addListener(() => this.close('HOST_UNAVAILABLE'));
  }
  receive(message) {
    const entry = message && typeof message === 'object' ? this.pending.get(message.id) : null;
    if (!entry) return;
    this.pending.delete(message.id); clearTimeout(entry.timer);
    if (message.v !== TOKEN_PROTOCOL || typeof message.ok !== 'boolean') return entry.reject(new TokenError('BAD_RESPONSE'));
    if (!message.ok) return entry.reject(new TokenError(message.code));
    try { entry.resolve(entry.check(message)); } catch { entry.reject(new TokenError('BAD_RESPONSE')); }
  }
  close(code) {
    if (this.closed) return;
    this.closed = true;
    for (const entry of this.pending.values()) { clearTimeout(entry.timer); entry.reject(new TokenError(code)); }
    this.pending.clear();
  }
  // Returns { id, result }: the id lets the caller cancel the request.
  request(op, fields, check) {
    if (this.closed) return { id: null, result: Promise.reject(new TokenError('HOST_UNAVAILABLE')) };
    const id = `r${++this.sequence}`;
    const result = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new TokenError('TIMEOUT')); }, this.timeout);
      this.pending.set(id, { resolve, reject, check, timer });
    });
    this.port.postMessage({ v: TOKEN_PROTOCOL, id, op, ...fields });
    return { id, result };
  }
  hello() {
    return this.request('hello', {}, message => {
      if (message.protocol !== TOKEN_PROTOCOL || !isText(message.host?.name) || !Array.isArray(message.mechanisms)) throw new Error();
      return { host: message.host, modules: message.modules, mechanisms: message.mechanisms };
    }).result;
  }
  list() {
    return this.request('list', {}, message => {
      if (!validTokens(message.tokens)) throw new Error();
      return message.tokens;
    }).result;
  }
  // The PIN travels only in this message; it is not kept here. A token with a protected authentication
  // path (PIN pad) gets no PIN at all.
  sign(token, certificate, data, pin) {
    if (!(data instanceof Uint8Array) || data.length > LIMITS.data) throw new TokenError('BAD_RESPONSE');
    return this.request('sign', {
      module: token.module, slot: token.slot, serial: token.serial, keyId: certificate.keyId, certificateSha256: certificate.sha256,
      mechanism: 'RSA-PKCS-SHA256', data: base64(data), ...(token.flags.protectedAuthenticationPath ? {} : { pin })
    }, message => {
      if (!isBase64(message.signature, LIMITS.signature)) throw new Error();
      return unbase64(message.signature);
    });
  }
  // The pending request is rejected at once; the host stops before login or signing if it has not passed them.
  cancel(id) {
    const entry = this.pending.get(id);
    if (!entry) return;
    this.pending.delete(id); clearTimeout(entry.timer);
    entry.reject(new TokenError('CANCELLED'));
    if (!this.closed) this.port.postMessage({ v: TOKEN_PROTOCOL, id: `c${++this.sequence}`, op: 'cancel', target: id });
  }
  disconnect() { this.close('CANCELLED'); this.port.disconnect(); }
}

// A signer for signCms backed by a key on the token. Only RSA: the token mechanisms for the Kazakh GOST
// algorithms are not documented for any device yet. pin() is asked once per signature and not stored.
export function tokenSigner(client, token, certificate, pin, { onRequest } = {}) {
  const raw = unbase64(certificate.certificate);
  const info = certificateInfo(raw);
  if (info.keyOid !== O.rsa) throw new TokenError('MECHANISM_UNSUPPORTED');
  return {
    info, certificates: [info],
    async digest(data) { return new Uint8Array(await crypto.subtle.digest('SHA-256', data)); },
    async sign(data) {
      const { id, result } = client.sign(token, certificate, data, token.flags.protectedAuthenticationPath ? undefined : await pin());
      onRequest?.(id);
      return result;
    },
    async signDigest() { throw new TokenError('MECHANISM_UNSUPPORTED'); },
    destroy() {}
  };
}
