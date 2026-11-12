import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createSign } from 'node:crypto';
import { TokenClient, TokenError, tokenSigner, TOKEN_PROTOCOL } from '../extension/tokens/token-client.js';
import { signCms } from '../extension/crypto/cms.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';
import { forge } from '../extension/crypto/encoding.js';
import { gostFixture } from './helpers/fixtures.js';

// Synthetic RSA key "on the token": only the fake host below uses the private key.
const keys = forge.pki.rsa.generateKeyPair(2048);
const cert = forge.pki.createCertificate();
cert.publicKey = keys.publicKey; cert.serialNumber = '0a';
cert.validity.notBefore = new Date(Date.now() - 86400000); cert.validity.notAfter = new Date(Date.now() + 86400000);
cert.setSubject([{ name: 'commonName', value: 'Tegin token test' }]); cert.setIssuer([{ name: 'commonName', value: 'Tegin token test' }]);
cert.sign(keys.privateKey, forge.md.sha256.create());
const certDer = Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), 'binary');
const privatePem = forge.pki.privateKeyToPem(keys.privateKey);
const PIN = '271828';
const token = (flags = {}, certificate = certDer) => ({ module: 0, moduleName: 'libsofthsm2.so', slot: 7, label: 'Tegin', manufacturer: 'SoftHSM', model: 'SoftHSM v2', serial: 'a1b2c3',
  flags: { protectedAuthenticationPath: false, loginRequired: true, pinCountLow: false, pinFinalTry: false, pinLocked: false, ...flags },
  certificates: [{ keyId: '01', label: 'Tegin', certificate: certificate.toString('base64'), sha256: createHash('sha256').update(certificate).digest('hex') }] });

// Fake host on the port: answers by op; `hold` keeps sign requests unanswered.
function fakePort({ reply, hold = false } = {}) {
  const listeners = { message: [], disconnect: [] };
  const sent = [];
  const port = {
    sent,
    postMessage(message) {
      sent.push(structuredClone(message));
      if (hold && message.op === 'sign') return;
      queueMicrotask(() => { const answer = reply?.(message); if (answer) listeners.message.forEach(fn => fn(answer)); });
    },
    onMessage: { addListener: fn => listeners.message.push(fn) },
    onDisconnect: { addListener: fn => listeners.disconnect.push(fn) },
    disconnect() {},
    drop() { listeners.disconnect.forEach(fn => fn()); }
  };
  return port;
}
const ok = (message, fields) => ({ v: TOKEN_PROTOCOL, id: message.id, ok: true, ...fields });
const hostSign = message => {
  if (message.pin !== PIN) return { v: TOKEN_PROTOCOL, id: message.id, ok: false, code: 'PIN_INCORRECT' };
  return ok(message, { signature: createSign('sha256').update(Buffer.from(message.data, 'base64')).sign(privatePem).toString('base64') });
};

test('list validates the host answer and refuses malformed tokens', async () => {
  const good = new TokenClient(fakePort({ reply: message => ok(message, { tokens: [token()] }) }));
  assert.equal((await good.list())[0].certificates[0].keyId, '01');
  for (const tokens of [[{ ...token(), slot: 'x' }], [{ ...token(), certificates: [{ keyId: 'zz', sha256: '0', label: '', certificate: '' }] }], Array(17).fill(token()), 'none']) {
    const bad = new TokenClient(fakePort({ reply: message => ok(message, { tokens }) }));
    await assert.rejects(bad.list(), { code: 'BAD_RESPONSE' });
  }
  const wrongVersion = new TokenClient(fakePort({ reply: message => ({ ...ok(message, { tokens: [] }), v: 2 }) }));
  await assert.rejects(wrongVersion.list(), { code: 'BAD_RESPONSE' });
});

test('a token signer produces a CMS that verifies; the PIN goes only into the sign message', async () => {
  const port = fakePort({ reply: message => message.op === 'sign' ? hostSign(message) : null });
  const client = new TokenClient(port);
  let asked = 0;
  const signer = tokenSigner(client, token(), token().certificates[0], async () => { asked++; return PIN; });
  const data = new TextEncoder().encode('Синтетический документ для токена');
  const cms = await signCms(signer, data, { cades: true });
  const verified = await verifyCms(cms, { anchors: [new Uint8Array(certDer)] });
  assert.equal(verified.signers.length, 1);
  assert.equal(Buffer.from(verified.content).toString(), Buffer.from(data).toString());
  assert.equal(asked, 1);
  const sign = port.sent.find(message => message.op === 'sign');
  assert.deepEqual(Object.keys(sign).sort(), ['certificateSha256', 'data', 'id', 'keyId', 'mechanism', 'module', 'op', 'pin', 'serial', 'slot', 'v']);
  assert.equal(sign.mechanism, 'RSA-PKCS-SHA256');
  assert.equal(port.sent.filter(message => JSON.stringify(message).includes(PIN)).length, 1, 'the PIN is sent once, in the sign message');
});

test('a PIN pad token gets no PIN; a wrong PIN is reported once and never retried', async () => {
  const port = fakePort({ reply: message => message.op === 'sign' ? hostSign(message) : null });
  const client = new TokenClient(port);
  const padded = token({ protectedAuthenticationPath: true });
  let asked = 0;
  await assert.rejects(tokenSigner(client, padded, padded.certificates[0], async () => { asked++; return PIN; }).sign(new Uint8Array(32)), { code: 'PIN_INCORRECT' });
  assert.equal(asked, 0);
  assert.equal('pin' in port.sent.at(-1), false);
  const wrong = tokenSigner(client, token(), token().certificates[0], async () => '000000');
  await assert.rejects(wrong.sign(new Uint8Array(32)), error => { assert.equal(error.code, 'PIN_INCORRECT'); assert.doesNotMatch(error.message, /000000/); return true; });
  assert.equal(port.sent.filter(message => message.op === 'sign').length, 2, 'no automatic retry');
});

test('cancel rejects the pending signature at once and tells the host', async () => {
  const port = fakePort({ hold: true, reply: message => message.op === 'cancel' ? ok(message, { cancelled: true }) : null });
  const client = new TokenClient(port);
  let requestId;
  const pending = tokenSigner(client, token(), token().certificates[0], async () => PIN, { onRequest: id => { requestId = id; } }).sign(new Uint8Array(32));
  await new Promise(done => setTimeout(done, 0));
  client.cancel(requestId);
  await assert.rejects(pending, { code: 'CANCELLED' });
  assert.deepEqual(port.sent.at(-1), { v: TOKEN_PROTOCOL, id: port.sent.at(-1).id, op: 'cancel', target: requestId });
});

test('a host that disappears fails pending and later requests', async () => {
  const port = fakePort({ hold: true });
  const client = new TokenClient(port);
  const pending = client.sign(token(), token().certificates[0], new Uint8Array(32), PIN).result;
  port.drop();
  await assert.rejects(pending, { code: 'HOST_UNAVAILABLE' });
  await assert.rejects(client.list(), { code: 'HOST_UNAVAILABLE' });
});

test('host error codes map to fixed texts; unknown codes do not leak host text', async () => {
  for (const code of ['TOKEN_REMOVED', 'PIN_LOCKED', 'KEY_NOT_FOUND']) {
    const client = new TokenClient(fakePort({ reply: message => ({ v: TOKEN_PROTOCOL, id: message.id, ok: false, code }) }));
    await assert.rejects(client.list(), error => error instanceof TokenError && error.code === code);
  }
  const client = new TokenClient(fakePort({ reply: message => ({ v: TOKEN_PROTOCOL, id: message.id, ok: false, code: '<script>' }) }));
  await assert.rejects(client.list(), { code: 'TOKEN_ERROR', message: 'Некорректный ответ программы для работы с токенами.' });
});

test('GOST certificates on a token are refused before any request', () => {
  const gost = Buffer.from(gostFixture('512').certificate, 'base64');
  const port = fakePort();
  assert.throws(() => tokenSigner(new TokenClient(port), token({}, gost), token({}, gost).certificates[0], async () => PIN), { code: 'MECHANISM_UNSUPPORTED' });
  assert.equal(port.sent.length, 0);
});
