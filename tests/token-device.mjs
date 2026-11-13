// Device trial of the token host prototype: the minimal scenario of docs/hardware-tokens.md on a physical token
// through the vendor's PKCS#11 module. Run by whoever holds the device, with a synthetic RSA key and certificate
// written to the token for the trial and its test PIN. Prints an anonymized JSON report (no serial numbers, no
// certificate, no PIN) to return; the signed test document stays in TEGIN_TOKEN_OUT for checks by Kalkan.
//
//   TEGIN_TOKEN_MODULES=<path to the PKCS#11 library from the vendor documentation>
//   TEGIN_TOKEN_PIN=<test PIN of the trial token>     (omit for a PIN pad)
//   TEGIN_TOKEN_OUT=<folder for document.txt, document.p7s, signer.der>   (default: a temporary folder)
//   TEGIN_TOKEN_WRONG_PIN=1   also try one wrong PIN (uses one attempt of the token's counter)
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir, platform, arch, release } from 'node:os';
import { basename, delimiter, join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import assert from 'node:assert/strict';
import { TokenClient, tokenSigner } from '../extension/tokens/token-client.js';
import { signCms } from '../extension/crypto/cms.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';
import { spawnTokenHost } from './helpers/token-host.js';

const MODULES = process.env.TEGIN_TOKEN_MODULES;
if (!MODULES) throw new Error('Set TEGIN_TOKEN_MODULES to the PKCS#11 library path from the vendor documentation');
const PIN = process.env.TEGIN_TOKEN_PIN || null;
const out = process.env.TEGIN_TOKEN_OUT || mkdtempSync(join(tmpdir(), 'tegin-token-'));
mkdirSync(out, { recursive: true });
const prompt = createInterface({ input: process.stdin, output: process.stdout });
const report = { os: `${platform()} ${release()} ${arch()}`, node: process.version, modules: MODULES.split(delimiter).filter(Boolean).map(path => basename(path)), steps: [] };
const step = (name, result, detail = {}) => { report.steps.push({ name, result, ...detail }); console.log(`${result === 'pass' ? 'PASS' : result.toUpperCase()}: ${name}`); };
const code = async promise => { try { await promise; return 'none'; } catch (error) { return error.code || error.name; } };
const ports = [];
const open = () => { const port = spawnTokenHost({ ...process.env, TEGIN_TOKEN_MODULES: MODULES }); ports.push(port); return { port, client: new TokenClient(port, { timeout: 120000 }) }; };

try {
  const { client } = open();
  const hello = await client.hello();
  report.host = { ...hello.host, mechanisms: hello.mechanisms };
  const tokens = await client.list();
  assert.ok(tokens.length > 0, 'no token with a certificate found; check the module path and that the token is inserted');
  const [token] = tokens;
  const [choice] = token.certificates;
  report.token = { manufacturer: token.manufacturer, model: token.model, flags: token.flags, certificates: token.certificates.length };
  step('hello and list: the token and its certificate are found', 'pass');

  const document = new TextEncoder().encode('Синтетический документ Tegin для испытания токена');
  const started = performance.now();
  const cms = await signCms(tokenSigner(client, token, choice, async () => PIN), document, { cades: true });
  report.signMs = Math.round(performance.now() - started);
  const certificate = Buffer.from(choice.certificate, 'base64');
  writeFileSync(join(out, 'document.txt'), document); writeFileSync(join(out, 'document.p7s'), cms); writeFileSync(join(out, 'signer.der'), certificate);
  const verified = await verifyCms(cms, { anchors: [new Uint8Array(certificate)] });
  assert.equal(Buffer.from(verified.content).toString(), Buffer.from(document).toString());
  step('CAdES-BES signed on the token, Tegin verifyCms accepts it', 'pass');
  try {
    execFileSync('openssl', ['x509', '-inform', 'DER', '-in', join(out, 'signer.der'), '-out', join(out, 'signer.pem')], { stdio: 'pipe' });
    const content = execFileSync('openssl', ['cms', '-verify', '-binary', '-inform', 'DER', '-in', join(out, 'document.p7s'), '-CAfile', join(out, 'signer.pem'), '-purpose', 'any'], { stdio: ['ignore', 'pipe', 'pipe'] });
    assert.equal(content.toString(), Buffer.from(document).toString());
    step('openssl cms -verify accepts the signature', 'pass');
  } catch (error) { step('openssl cms -verify', error.code === 'ENOENT' ? 'skipped' : 'fail', { code: error.code === 'ENOENT' ? 'NO_OPENSSL' : 'VERIFY_FAILED' }); }

  if (process.env.TEGIN_TOKEN_WRONG_PIN === '1' && PIN) {
    const result = await code(tokenSigner(client, token, choice, async () => PIN + '0').sign(new Uint8Array(32)));
    const [after] = await client.list();
    step('one wrong PIN is refused, no retry', result === 'PIN_INCORRECT' ? 'pass' : 'fail', { code: result, flagsAfter: after?.flags });
  }

  let requestId;
  const pending = tokenSigner(client, token, choice, async () => PIN, { onRequest: id => { requestId = id; } }).sign(new Uint8Array(32));
  while (!requestId) await new Promise(done => setTimeout(done, 5));
  client.cancel(requestId);
  const cancelled = await code(pending);
  step('cancel right after the request: no signature', cancelled === 'CANCELLED' ? 'pass' : 'fail', { code: cancelled });

  await prompt.question('Извлеките токен и нажмите Enter. ');
  const removed = await code(tokenSigner(client, token, choice, async () => PIN).sign(new Uint8Array(32)));
  step('token removed after the certificate was chosen', removed === 'TOKEN_REMOVED' ? 'pass' : 'fail', { code: removed, listed: (await client.list()).length });

  await prompt.question('Вставьте токен обратно и нажмите Enter. ');
  const again = open();
  const [back] = await again.client.list();
  const resumed = back ? await code(tokenSigner(again.client, back, back.certificates[0], async () => PIN).sign(new Uint8Array(32))) : 'NOT_LISTED';
  step('the token inserted again signs through a new host connection', resumed === 'none' ? 'pass' : 'fail', { code: resumed });

  for (const instance of ports) { instance.disconnect(); await instance.exited; }
  const leaked = PIN && ports.some(instance => instance.log().includes(PIN) || instance.frames.some(frame => JSON.stringify(frame).includes(PIN)));
  step('host log and answers hold no PIN', leaked ? 'fail' : 'pass');
} catch (error) {
  step('run', 'fail', { code: error.code || error.name, message: error.code ? undefined : String(error.message).slice(0, 200) });
  process.exitCode = 1;
} finally {
  prompt.close();
  for (const instance of ports) instance.disconnect();
  console.log(`\nFiles for the Kalkan check: ${out}`);
  console.log('Report to return (no serial numbers, certificate or PIN):');
  console.log(JSON.stringify(report, null, 2));
}
