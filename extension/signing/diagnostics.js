// Safe description of portal requests: names and argument structure only, never values.
export const DIAGNOSTIC_PREFIX = 'diagnostic:';
export const DIAGNOSTIC_LIMIT = 8;
const NAME = /^[A-Za-z0-9_.-]{1,64}$/;

const name = value => typeof value === 'string' && NAME.test(value) ? value : value == null ? null : '?';

export function argumentShape(value, depth = 0) {
  if (value === null) return 'null';
  if (Array.isArray(value)) {
    if (!value.length || depth >= 2) return `array(${value.length})`;
    const items = [...new Set(value.slice(0, 64).map(item => JSON.stringify(argumentShape(item, depth + 1))))];
    return { array: value.length, items: items.slice(0, 4).map(item => JSON.parse(item)) };
  }
  if (typeof value === 'object') {
    if (depth >= 3) return 'object';
    const keys = Object.keys(value).slice(0, 32);
    return Object.fromEntries(keys.map(key => [NAME.test(key) ? key : '?', argumentShape(value[key], depth + 1)]));
  }
  if (typeof value === 'string') return value ? 'string' : 'empty';
  return typeof value;
}

export function responseCode(response) {
  if (!response || typeof response !== 'object') return 'none';
  if (response.status === false) return name(response.code) || 'error';
  if (response.status === true) return response.body && typeof response.body === 'object' && !Object.keys(response.body).length ? 'cancelled' : 'ok';
  return name(response.code) || 'none';
}

// Reasons are the extension's own fixed texts; anything long or multi-line is cut.
export function diagnosticEntry(request, stage, code, reason = '') {
  return {
    at: Date.now(),
    module: name(request?.module), method: name(request?.method), class: name(request?.class),
    args: argumentShape(request?.args ?? null),
    stage, code: name(code) || '?',
    reason: String(reason || '').split('\n')[0].slice(0, 200)
  };
}
