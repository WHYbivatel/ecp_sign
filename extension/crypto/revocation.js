import { profileFor, ALLOWED_URLS, LIMITS } from './revocation-profiles.js';
import { buildOcspRequest, verifyOcspResponse, RevocationError, OCSP_LIMITS } from './ocsp.js';
import { parseCrl, verifyCrl, statusFromCrls } from './crl.js';
import { bytes } from './encoding.js';

// Per-certificate and overall states. Order is severity for the overall result.
export const STATES = Object.freeze({ revoked: 'revoked', unknown: 'unknown', unavailable: 'unavailable', notChecked: 'not-checked', good: 'good' });
const SEVERITY = [STATES.revoked, STATES.unknown, STATES.unavailable, STATES.notChecked, STATES.good];
export const REVOCATION_MAX_AGE = OCSP_LIMITS.maxAge;

const hex = value => [...value].map(byte => byte.toString(16).padStart(2, '0')).join('');
const fingerprint = async info => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(info.raw))));

const OCSP_TYPES = ['application/ocsp-response'];
const CRL_TYPES = ['application/pkix-crl', 'application/octet-stream', 'application/x-pkcs7-crl'];

// Only pinned URLs; no redirects, cookies, referrer or HTTP cache; bounded time and size.
export async function fetchBounded(url, { method = 'GET', body, types, limit, timeout, signal, fetchImpl = globalThis.fetch }) {
  if (!ALLOWED_URLS.includes(url)) throw new RevocationError('URL_NOT_ALLOWED', 'Адрес службы отзыва не входит в разрешённые.');
  if (signal?.aborted) throw new RevocationError('ABORTED', 'Проверка отменена.');
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeout);
  const forward = () => controller.abort();
  signal?.addEventListener('abort', forward, { once: true });
  const failure = () => signal?.aborted ? new RevocationError('ABORTED', 'Проверка отменена.') : timedOut ? new RevocationError('TIMEOUT', 'Служба отзыва не ответила вовремя.') : null;
  try {
    let response;
    try {
      response = await fetchImpl(url, { method, body, headers: method === 'POST' ? { 'Content-Type': 'application/ocsp-request', Accept: OCSP_TYPES[0] } : { Accept: CRL_TYPES[0] },
        credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer', signal: controller.signal });
    } catch { throw failure() || new RevocationError('NETWORK', 'Служба отзыва недоступна.'); }
    if (response.redirected || (response.url && response.url !== url) || response.type === 'opaque' || response.type === 'opaqueredirect') throw new RevocationError('REDIRECT', 'Служба отзыва перенаправила запрос.');
    if (!response.ok) throw new RevocationError('HTTP', `Служба отзыва вернула HTTP ${response.status}.`);
    const type = (response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    if (!types.includes(type)) throw new RevocationError('CONTENT_TYPE', 'Служба отзыва вернула неожиданный тип данных.');
    const declared = Number(response.headers.get('content-length'));
    if (declared > limit) throw new RevocationError('TOO_LARGE', 'Ответ службы отзыва слишком большой.');
    const reader = response.body.getReader();
    const chunks = []; let length = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        length += value.length;
        if (length > limit) { await reader.cancel().catch(() => {}); throw new RevocationError('TOO_LARGE', 'Ответ службы отзыва слишком большой.'); }
        chunks.push(value);
      }
    } catch (error) { throw error instanceof RevocationError ? error : failure() || new RevocationError('NETWORK', 'Связь со службой отзыва прервана.'); }
    const raw = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.length; }
    return raw;
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', forward); }
}

// CRLs are public NCA data; cached raw bytes are re-verified on every use and kept only until
// nextUpdate. Cache Storage of the extension origin is used where available. OCSP responses
// carry the user's serial number and stay in memory of the current Worker only.
export function memoryStore({ maxBytes = 64 * 1024 * 1024 } = {}) {
  const entries = new Map();
  return {
    async get(url) { const entry = entries.get(url); return entry && entry.expires > Date.now() ? entry.raw : (entries.delete(url), null); },
    async put(url, raw, expires) {
      if (raw.length > maxBytes) return;
      entries.delete(url); entries.set(url, { raw, expires });
      let total = [...entries.values()].reduce((sum, entry) => sum + entry.raw.length, 0);
      for (const [key, entry] of entries) { if (total <= maxBytes) break; entries.delete(key); total -= entry.raw.length; }
    },
    async delete(url) { entries.delete(url); },
    size: () => entries.size
  };
}
const CACHE_NAME = 'tegin-crl-v1';
export function cacheStorageStore() {
  if (!globalThis.caches) return null;
  const key = url => new Request(url);
  return {
    async get(url) {
      const cache = await caches.open(CACHE_NAME);
      const response = await cache.match(key(url));
      if (!response) return null;
      if (!(Number(response.headers.get('x-tegin-expires')) > Date.now())) { await cache.delete(key(url)); return null; }
      return new Uint8Array(await response.arrayBuffer());
    },
    async put(url, raw, expires) {
      const cache = await caches.open(CACHE_NAME);
      for (const request of await cache.keys()) if (!ALLOWED_URLS.includes(request.url)) await cache.delete(request);
      await cache.put(key(url), new Response(raw, { headers: { 'content-type': 'application/pkix-crl', 'x-tegin-expires': String(expires) } }));
    },
    async delete(url) { await (await caches.open(CACHE_NAME)).delete(key(url)); }
  };
}

export class RevocationChecker {
  constructor({ fetchImpl = globalThis.fetch?.bind(globalThis), store = cacheStorageStore() || memoryStore(), testIssuers, now = () => Date.now() } = {}) {
    this.fetchImpl = fetchImpl; this.store = store; this.testIssuers = testIssuers; this.now = now;
    this.ocspCache = new Map(); this.crls = new Map();
  }

  async crl(urls, issuer, kind, limitName, signal, errors) {
    for (const url of urls) {
      const memo = this.crls.get(url);
      if (memo && memo.crl.nextUpdate >= this.now()) return memo.crl;
      let cached = null;
      try { cached = await this.store.get(url); } catch {}
      if (cached) {
        try { const crl = await verifyCrl(parseCrl(cached), issuer, { now: this.now(), kind }); this.crls.set(url, { crl }); return crl; }
        catch { await this.store.delete(url).catch(() => {}); }
      }
      try {
        const raw = await fetchBounded(url, { types: CRL_TYPES, ...limitOf(limitName), signal, fetchImpl: this.fetchImpl });
        const crl = await verifyCrl(parseCrl(raw), issuer, { now: this.now(), kind });
        this.crls.set(url, { crl });
        await this.store.put(url, raw, crl.nextUpdate).catch(() => {});
        return crl;
      } catch (error) {
        if (error.code === 'ABORTED') throw error;
        errors.push(error.code || 'CRL');
      }
    }
    return null;
  }

  async viaOcsp(certificate, issuer, profile, signal, errors) {
    for (const url of profile.ocsp) {
      try {
        const request = await buildOcspRequest(certificate, issuer);
        const cached = this.ocspCache.get(request.key);
        if (cached && cached.expires > this.now()) return cached.result;
        const raw = await fetchBounded(url, { method: 'POST', body: request.body, types: OCSP_TYPES, ...limitOf('ocsp'), signal, fetchImpl: this.fetchImpl });
        const result = await verifyOcspResponse(raw, request, issuer, { now: this.now() });
        this.ocspCache.set(request.key, { result, expires: result.expires });
        if (this.ocspCache.size > 32) this.ocspCache.delete(this.ocspCache.keys().next().value);
        return result;
      } catch (error) {
        if (error.code === 'ABORTED') throw error;
        errors.push(error.code || 'OCSP');
      }
    }
    return null;
  }

  async viaCrl(certificate, issuer, profile, signal, errors) {
    if (!profile.crl.length) return null;
    const full = await this.crl(profile.crl, issuer, 'full', profile.crlLimit, signal, errors);
    if (!full) return null;
    const delta = profile.delta.length ? await this.crl(profile.delta, issuer, 'delta', 'delta', signal, errors) : null;
    try {
      const serial = Uint8Array.from(certificate.serial.value, char => char.charCodeAt(0));
      return statusFromCrls(full, delta, serial);
    } catch (error) {
      errors.push(error.code || 'CRL');
      if (!delta) return null;
      try { return statusFromCrls(full, null, Uint8Array.from(certificate.serial.value, char => char.charCodeAt(0))); }
      catch (retry) { errors.push(retry.code || 'CRL'); return null; }
    }
  }

  // Checks every certificate of a built path except the trust anchor (the last element).
  async checkPath(path, { signal } = {}) {
    const checkedAt = new Date(this.now()).toISOString();
    if (!path?.length) return summarize([], checkedAt, 'chain');
    const certificates = [];
    for (let index = 0; index < path.length - 1; index++) {
      const certificate = path[index], issuer = path[index + 1];
      const profile = profileFor(await fingerprint(issuer), this.testIssuers);
      const entry = { name: certificate.summary.name, role: index === 0 ? 'end-entity' : 'ca', issuer: issuer.summary.name, required: Boolean(profile) };
      if (!profile) { certificates.push({ ...entry, state: STATES.notChecked, code: 'UNSUPPORTED_CA' }); continue; }
      const errors = [];
      let result = profile.ocsp.length ? await this.viaOcsp(certificate, issuer, profile, signal, errors) : null;
      if (!result) result = await this.viaCrl(certificate, issuer, profile, signal, errors);
      if (!result) { certificates.push({ ...entry, state: STATES.unavailable, code: errors.at(-1) || 'UNAVAILABLE', errors: [...new Set(errors)] }); continue; }
      const { status, expires, ...details } = result;
      certificates.push({ ...entry, ...details, state: status === 'good' ? STATES.good : status === 'revoked' ? STATES.revoked : STATES.unknown,
        ...(errors.length ? { errors: [...new Set(errors)] } : {}) });
    }
    return summarize(certificates, checkedAt);
  }
}

function limitOf(name) { return { limit: LIMITS[name].bytes, timeout: LIMITS[name].timeout }; }

export function summarize(certificates, checkedAt, reason) {
  const required = certificates.some(entry => entry.required);
  let state = certificates.length ? SEVERITY.find(candidate => certificates.some(entry => entry.state === candidate)) : STATES.notChecked;
  return { state, required, checkedAt, certificates, ...(reason ? { reason } : {}) };
}

// Current status versus the moment proven by a verified timestamp (Rules 500/НҚ p.14). It
// describes evidence only and never turns the current status into a verdict on an old signature.
export function assessHistory(current, stamp) {
  if (current.state !== STATES.revoked) return { basis: stamp ? 'timestamp' : 'none', relation: current.state === STATES.good ? 'not-revoked-now' : 'undetermined' };
  const times = current.certificates.filter(entry => entry.state === STATES.revoked).map(entry => Date.parse(entry.revocationTime)).filter(Number.isFinite);
  const revocationTime = times.length ? new Date(Math.min(...times)).toISOString() : null;
  if (!stamp) return { basis: 'none', relation: 'signing-time-unproven', revocationTime };
  if (!revocationTime) return { basis: 'timestamp', relation: 'undetermined', timestamp: stamp.time };
  return { basis: 'timestamp', relation: Date.parse(revocationTime) > Date.parse(stamp.time) ? 'revoked-after-timestamp' : 'revoked-before-timestamp', revocationTime, timestamp: stamp.time };
}

// Policy (docs/certificate-revocation.md): for chains whose issuers have pinned NCA sources the
// operation requires "good" for every checked certificate. Revoked always blocks.
export const blocks = result => result.state === STATES.revoked || (result.required && result.state !== STATES.good);
