import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../extension/content/bridge.js', import.meta.url), 'utf8');

// bridge.js in a page context whose background never answers, with timers run by hand.
function loadBridge() {
  const timers = [], replies = [], sent = [], listeners = {};
  const window = {
    location: { origin: 'https://example.kz' },
    addEventListener: (type, listener) => { listeners[type] = listener; },
    postMessage: message => replies.push(message)
  };
  const chrome = { runtime: { id: 'tegin', sendMessage: message => { sent.push(message); return new Promise(() => {}); }, onMessage: { addListener() {} } } };
  const context = vm.createContext({ window, chrome, crypto: globalThis.crypto, setTimeout: (run, delay) => timers.push({ run, delay }) && timers.length, clearTimeout() {}, location: window.location, document: {} });
  vm.runInContext(source, context);
  const send = (id, request) => listeners.message({ source: window, origin: window.location.origin, data: { channel: 'tegin:request', id, request } });
  return { timers, replies, sent, send };
}

test('the fallback timer answers in the form of the request module', async () => {
  const bridge = loadBridge();
  bridge.send('b1', { module: 'kz.gov.pki.knca.basics', method: 'sign', args: {} });
  bridge.send('c1', { module: 'kz.gov.pki.knca.commonUtils', method: 'signXml', args: [] });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(bridge.timers.map(timer => timer.delay), [185000, 185000]);
  for (const timer of bridge.timers) timer.run();
  assert.deepEqual(JSON.parse(JSON.stringify(bridge.replies.map(({ id, response }) => ({ id, response })))), [
    { id: 'b1', response: { status: true, body: {} } },
    { id: 'c1', response: { code: '500', message: 'action.canceled' } }
  ]);
  assert.deepEqual(bridge.sent.filter(message => message.kind === 'nca:cancel-request').length, 2);
});
