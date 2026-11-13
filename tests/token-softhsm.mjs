// The token host prototype (native-host/tegin_token_host.py) against SoftHSM2, a software PKCS#11 token,
// driven by the extension's TokenClient over the Native Messaging framing. Stand-in for a physical token:
// it checks the protocol, PIN handling, cancel and the host's reaction to a token that disappears; it says
// nothing about a particular device, its driver or the Kazakh GOST mechanisms.
// Needs softhsm2, opensc (pkcs11-tool), python3-pykcs11 and openssl; tests/token-softhsm.sh runs it in a
// disposable container. Synthetic key and PIN only.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { TokenClient, tokenSigner, TOKEN_PROTOCOL } from '../extension/tokens/token-client.js';
import { signCms } from '../extension/crypto/cms.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';
import { spawnTokenHost } from './helpers/token-host.js';

const MODULE = ['/usr/lib/softhsm/libsofthsm2.so', '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so', '/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so'].find(existsSync);
if (!MODULE) throw new Error('SoftHSM2 module not found; run tests/token-softhsm.sh');
const PIN = '481516', SO_PIN = '23420815', WRONG = '999999', LABEL = 'Tegin test token';
const folder = mkdtempSync(join(tmpdir(), 'tegin-softhsm-'));
const env = { ...process.env, SOFTHSM2_CONF: join(folder, 'softhsm2.conf') };
writeFileSync(env.SOFTHSM2_CONF, `directories.tokendir = ${join(folder, 'tokens')}\nobjectstore.backend = file\nlog.level = ERROR\n`);
execFileSync('mkdir', ['-p', join(folder, 'tokens')]);
const run = (command, args) => execFileSync(command, args, { env, stdio: 'pipe', encoding: 'utf8' });

// A token with one RSA key and its certificate, as a card issued with a key pair would hold.
function provision(label, name) {
  run('softhsm2-util', ['--init-token', '--free', '--label', label, '--pin', PIN, '--so-pin', SO_PIN]);
  run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(folder, `${name}.key`), '-out', join(folder, `${name}.pem`), '-days', '2', '-subj', `/CN=${label}`]);
  run('openssl', ['pkcs8', '-topk8', '-nocrypt', '-in', join(folder, `${name}.key`), '-outform', 'DER', '-out', join(folder, `${name}.p8`)]);
  run('openssl', ['x509', '-in', join(folder, `${name}.pem`), '-outform', 'DER', '-out', join(folder, `${name}.der`)]);
  for (const [file, type] of [[`${name}.p8`, 'privkey'], [`${name}.der`, 'cert']]) {
    run('pkcs11-tool', ['--module', MODULE, '--token-label', label, '--login', '--pin', PIN, '--write-object', join(folder, file), '--type', type, '--id', '01', '--label', name]);
  }
  rmSync(join(folder, `${name}.key`)); rmSync(join(folder, `${name}.p8`));
  return new Uint8Array(readFileSync(join(folder, `${name}.der`)));
}

const host = (extraEnv = {}) => spawnTokenHost({ ...env, TEGIN_TOKEN_MODULES: MODULE, ...extraEnv });
const until = async (check, what) => { for (let i = 0; i < 200; i++) { if (check()) return; await new Promise(done => setTimeout(done, 25)); } throw new Error(`timeout: ${what}`); };
const ports = [];
const open = (extraEnv) => { const port = host(extraEnv); ports.push(port); return { port, client: new TokenClient(port, { timeout: 30000 }) }; };

try {
  const certificate = provision(LABEL, 'signer');
  console.log(`ENV: SoftHSM2 ${run('softhsm2-util', ['--version']).trim()}, ${run('openssl', ['version']).trim()}, module ${MODULE}`);

  // 1. Detect the token and choose the certificate.
  const { port, client } = open();
  const hello = await client.hello();
  assert.equal(hello.host.name, 'kz.tegin.token');
  assert.deepEqual(hello.modules, ['libsofthsm2.so']);
  const tokens = await client.list();
  assert.equal(tokens.length, 1);
  const [token] = tokens;
  assert.equal(token.label, LABEL);
  assert.equal(token.flags.loginRequired, true);
  assert.equal(token.certificates.length, 1);
  const [choice] = token.certificates;
  assert.equal(choice.sha256, createHash('sha256').update(certificate).digest('hex'));
  console.log(`PASS: token detected (${token.manufacturer} ${token.model}, serial ${token.serial}), its certificate listed and chosen by SHA-256`);

  // 2. Sign a test document: the token signs the signed attributes, the extension builds the CMS.
  const document = new TextEncoder().encode('Синтетический документ Tegin для подписи на токене');
  let asked = 0;
  const cms = await signCms(tokenSigner(client, token, choice, async () => { asked++; return PIN; }), document, { cades: true });
  assert.equal(asked, 1);
  const verified = await verifyCms(cms, { anchors: [certificate] });
  assert.equal(Buffer.from(verified.content).toString(), Buffer.from(document).toString());
  writeFileSync(join(folder, 'document.p7s'), cms);
  const opensslOut = execFileSync('openssl', ['cms', '-verify', '-inform', 'DER', '-in', join(folder, 'document.p7s'), '-CAfile', join(folder, 'signer.pem'), '-binary'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  assert.equal(opensslOut.toString(), Buffer.from(document).toString());
  console.log('PASS: the token signed a CAdES-BES of the test document; Tegin and OpenSSL (openssl cms -verify) accept it, the content matches');

  // 3. Wrong PIN: one attempt, a fixed message, no retry.
  const before = port.sent.length;
  await assert.rejects(tokenSigner(client, token, choice, async () => WRONG).sign(new Uint8Array(32)), error => { assert.equal(error.code, 'PIN_INCORRECT'); assert.doesNotMatch(error.message, new RegExp(WRONG)); return true; });
  assert.equal(port.sent.slice(before).filter(message => JSON.parse(message).op === 'sign').length, 1, 'no automatic PIN retry');
  console.log('PASS: wrong PIN refused once with PIN_INCORRECT, no retry');

  // 4. The host refuses fields it does not know, such as a library path chosen by the caller.
  port.postMessage({ v: TOKEN_PROTOCOL, id: 'raw-1', op: 'sign', module: 0, slot: token.slot, serial: token.serial, keyId: '01', certificateSha256: choice.sha256, mechanism: 'RSA-PKCS-SHA256', data: 'AA==', pin: PIN, library: '/tmp/other.so' });
  await until(() => port.frames.some(frame => frame.id === 'raw-1'), 'raw-1');
  assert.equal(port.frames.find(frame => frame.id === 'raw-1').code, 'BAD_REQUEST');
  console.log('PASS: a request naming a PKCS#11 library is refused (BAD_REQUEST); modules come only from the installer allowlist');

  // 5. Cancel while the host waits before login: no signature, the host stops before C_Login.
  const slow = open({ TEGIN_TOKEN_HOST_TEST: '1', TEGIN_TOKEN_HOST_TEST_PAUSE_MS: '1500' });
  const [slowToken] = await slow.client.list();
  let requestId;
  const pending = tokenSigner(slow.client, slowToken, slowToken.certificates[0], async () => PIN, { onRequest: id => { requestId = id; } }).sign(new Uint8Array(32));
  await until(() => requestId, 'request id');
  await new Promise(done => setTimeout(done, 200));
  slow.client.cancel(requestId);
  await assert.rejects(pending, { code: 'CANCELLED' });
  await until(() => slow.port.frames.some(frame => frame.id === requestId), 'host answer to the cancelled request');
  const answer = slow.port.frames.find(frame => frame.id === requestId);
  assert.equal(answer.ok, false); assert.equal(answer.code, 'CANCELLED'); assert.equal('signature' in answer, false);
  console.log('PASS: cancel rejects at once; the host answers CANCELLED for that request and produces no signature');

  // 6. Removal: the chosen token disappears before signing; a different token takes its place.
  run('softhsm2-util', ['--delete-token', '--token', LABEL]);
  await assert.rejects(tokenSigner(client, token, choice, async () => PIN).sign(new Uint8Array(32)), { code: 'TOKEN_REMOVED' });
  assert.equal((await client.list()).length, 0);
  // SoftHSM does not show a token created after the process started, so the replacement is seen by a new host connection.
  provision(LABEL, 'other');
  const fresh = open();
  const [replacement] = await fresh.client.list();
  assert.equal(replacement.label, LABEL);
  assert.notEqual(replacement.serial, token.serial);
  await assert.rejects(tokenSigner(fresh.client, token, choice, async () => PIN).sign(new Uint8Array(32)), { code: 'TOKEN_REMOVED' });
  await assert.rejects(tokenSigner(fresh.client, replacement, { ...replacement.certificates[0], sha256: choice.sha256 }, async () => PIN).sign(new Uint8Array(32)), { code: 'KEY_NOT_FOUND' });
  console.log('PASS: removed token -> TOKEN_REMOVED and an empty list; a different token in its place is not used for the earlier choice');

  // 7. Logs and messages: the PIN appears only in the sign requests, never in host output.
  for (const instance of ports) {
    instance.disconnect();
    await instance.exited;
    for (const secret of [PIN, WRONG]) assert.ok(!instance.log().includes(secret), 'host log holds no PIN');
    assert.ok(!instance.frames.some(frame => JSON.stringify(frame).includes(PIN)), 'host answers hold no PIN');
    for (const line of instance.log().trim().split('\n').filter(Boolean)) assert.deepEqual(Object.keys(JSON.parse(line)).filter(key => !['event', 'op', 'code', 'ckr', 'found', 'module'].includes(key)), []);
  }
  console.log('PASS: host stderr carries only event names and codes; neither PIN appears in host output');
  console.log('SoftHSM token host checks completed.');
} catch (error) {
  for (const instance of ports) console.error('host log:', instance.log(), 'codes:', instance.frames.map(frame => frame.code).filter(Boolean));
  throw error;
} finally {
  for (const instance of ports) instance.disconnect();
  rmSync(folder, { recursive: true, force: true });
}
