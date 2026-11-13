// File limits in the signing window: 2 MB for a signature with the document inside, 16 MB for a detached signature
// and for the original of a detached signature, 8 MB for a signature file. Boundary sizes, the hint to switch to a
// detached signature, cancellation mid-operation, retry after a refusal; time and, on Linux, the peak memory of the
// extension renderer. Synthetic keys and random bytes only.
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import assert from 'node:assert/strict';
import { rsaFixture, gostFixture, PASSWORD } from './helpers/fixtures.js';
import { browserName, extensionWorker, launchExtension } from './helpers/browser.js';

const MB = 1024 * 1024;
const folder = mkdtempSync(join(tmpdir(), 'tegin-limits-'));
const rsa = rsaFixture({ keyUsage: 'digitalSignature,nonRepudiation' });
const gost = gostFixture('512', { keyUsage: true });
const atLimit = randomBytes(16 * MB), overLimit = randomBytes(16 * MB + 1), small = randomBytes(2 * MB), justOver = randomBytes(2 * MB + 1);
writeFileSync(join(folder, 'document.bin'), atLimit);
writeFileSync(join(folder, 'cert.pem'), rsa.certificate);
const file = (name, buffer) => ({ name, mimeType: 'application/octet-stream', buffer });

// Peak resident memory of the renderer that hosts extension pages and their workers (Linux /proc only).
function rendererRss() {
  if (process.platform !== 'linux') return null;
  let total = 0;
  for (const pid of readdirSync('/proc').filter(name => /^\d+$/.test(name))) {
    try {
      const cmdline = readFileSync(`/proc/${pid}/cmdline`, 'utf8');
      if (!cmdline.includes('--type=renderer') || !cmdline.includes('--extension-process') || !cmdline.includes(folder)) continue;
      total += Number(/VmRSS:\s+(\d+)/.exec(readFileSync(`/proc/${pid}/status`, 'utf8'))[1]) * 1024;
    } catch {}
  }
  return total;
}
async function measure(action) {
  const before = rendererRss();
  let peak = before;
  const timer = before === null ? null : setInterval(() => { peak = Math.max(peak, rendererRss()); }, 50);
  const start = performance.now();
  try { await action(); } finally { clearInterval(timer); }
  return { ms: Math.round(performance.now() - start), deltaMB: before === null ? null : Math.round((peak - before) / MB) };
}
const report = (label, { ms, deltaMB }) => console.log(`MEASURE: ${label}: ${ms} ms${deltaMB === null ? '' : `, renderer peak +${deltaMB} MB`}`);

const context = await launchExtension(join(folder, 'profile'), resolve('dist/chromium'), { viewport: { width: 1000, height: 900 } });
try {
  const extensionId = new URL((await extensionWorker(context)).url()).host;
  const tool = await context.newPage();
  await tool.goto(`chrome-extension://${extensionId}/signing/approve.html`);
  const status = tool.locator('#status');
  const openKey = async (key, name) => {
    await tool.locator('#key-file').setInputFiles(file(name, Buffer.from(key.container)));
    await tool.locator('#password').fill(PASSWORD); await tool.locator('#unlock').click();
    await tool.locator('#certificate:not([hidden])').waitFor();
  };
  assert.match(await tool.locator('#document-hint').textContent(), /До 2 МБ, отдельная подпись до 16 МБ/);
  const loaded = async size => {
    await tool.locator('#document-hint').filter({ hasText: new RegExp(`^${size}.* · нажмите, чтобы заменить`) }).waitFor();
    await status.filter({ hasText: 'Документ загружен' }).waitFor();
    assert.equal(await status.getAttribute('data-error'), null);
  };
  const chooseFormat = async value => {
    await tool.locator('#advanced-settings').evaluate(node => { node.open = true; });
    await tool.locator('#format').selectOption(value);
  };

  // Signature with the document inside: exactly 2 MB passes, one byte more is refused with the way out.
  await tool.locator('#document').setInputFiles(file('small.bin', small));
  await loaded('2');
  await tool.locator('#document').setInputFiles(file('just-over.bin', justOver));
  await tool.locator('#status[data-error]').filter({ hasText: 'отдельной подписью до 16 МБ' }).waitFor();
  assert.equal(await tool.locator('#advanced-settings').evaluate(node => node.open), true);
  console.log('PASS: with the document inside, 2 MB is accepted and 2 MB + 1 byte is refused with the hint to choose a detached signature (settings opened)');

  // Retry after the refusal: the same 16 MB file passes once a detached format is chosen; 16 MB + 1 never does.
  await tool.locator('#document').setInputFiles(file('scan-16mb.bin', atLimit));
  await tool.locator('#status[data-error]').filter({ hasText: 'отдельной подписью' }).waitFor();
  await chooseFormat('cms-detached');
  await loaded('16');
  await tool.locator('#document').setInputFiles(file('over.bin', overLimit));
  await tool.locator('#status[data-error]').filter({ hasText: 'Файл превышает 16 МБ' }).waitFor();
  await tool.locator('#document').setInputFiles(file('scan-16mb.bin', atLimit));
  await loaded('16');
  console.log('PASS: 16 MB passes with a detached format after the refusal; 16 MB + 1 byte is refused even for a detached signature');

  // Cancellation mid-operation: switching the tool stops the worker; no result, no download; the retry succeeds.
  await openKey(gost, 'gost.p12');
  await tool.locator('#approve').click();
  await tool.locator('#status[data-busy]').waitFor();
  await tool.locator('#nav-verify').click();
  await tool.locator('#title').filter({ hasText: 'Проверить подпись' }).waitFor();
  await tool.waitForTimeout(12000);
  assert.equal(await tool.locator('#result-screen').isHidden(), true, 'a cancelled signature shows no result');
  await tool.locator('#nav-sign').click();
  assert.equal(await tool.locator('#password').inputValue(), '');
  await chooseFormat('cms-detached');
  await tool.locator('#document').setInputFiles(file('scan-16mb.bin', atLimit));
  await loaded('16');
  await openKey(gost, 'gost.p12');
  report(`GOST 512 detached CMS, 16 MB, ${browserName}`, await measure(async () => {
    await tool.locator('#approve').click();
    await tool.locator('#result-title').filter({ hasText: 'Документ подписан' }).waitFor({ timeout: 120000 });
  }));
  console.log('PASS: a GOST signature cancelled mid-operation (tool switched) leaves no result and wipes the password; the retry signs 16 MB');

  // RSA detached at the limit, checked by OpenSSL against the 16 MB original.
  await tool.locator('#again').click();
  await chooseFormat('cms-detached');
  await tool.locator('#document').setInputFiles(file('scan-16mb.bin', atLimit));
  await loaded('16');
  await openKey(rsa, 'rsa.p12');
  report(`RSA detached CMS, 16 MB, ${browserName}`, await measure(async () => {
    await tool.locator('#approve').click();
    await tool.locator('#result-title').filter({ hasText: 'Документ подписан' }).waitFor({ timeout: 120000 });
  }));
  const download = tool.waitForEvent('download'); await tool.locator('#download').click();
  const signature = join(folder, 'detached.p7s'); await (await download).saveAs(signature);
  // OpenSSL takes -content even when the document is inside, so the signature size shows it is detached.
  assert.ok(readFileSync(signature).length < 64 * 1024, 'the 16 MB document is not inside the signature');
  execFileSync('openssl', ['cms', '-verify', '-binary', '-inform', 'DER', '-in', signature, '-content', join(folder, 'document.bin'), '-CAfile', join(folder, 'cert.pem'), '-purpose', 'any', '-out', join(folder, 'out.bin')], { stdio: 'pipe' });
  assert.ok(readFileSync(join(folder, 'out.bin')).equals(atLimit));
  console.log('PASS: RSA detached CMS of a 16 MB file verified by OpenSSL against the original');

  // Verification of a detached signature: the 16 MB original is accepted, 16 MB + 1 refused, then the retry passes.
  await tool.goto(`chrome-extension://${extensionId}/signing/approve.html?mode=verify`);
  await tool.locator('#document').setInputFiles(signature);
  await tool.locator('#original-controls:not([hidden])').waitFor();
  await tool.locator('#original').setInputFiles(file('over.bin', overLimit));
  await tool.locator('#verify-submit').click();
  await tool.locator('#status[data-error]').filter({ hasText: 'Исходный документ превышает 16 МБ' }).waitFor();
  await tool.locator('#original').setInputFiles(file('scan-16mb.bin', atLimit));
  report(`verify detached CMS, 16 MB original, ${browserName}`, await measure(async () => {
    await tool.locator('#verify-submit').click();
    await tool.locator('#result-title').filter({ hasText: 'Подпись верна' }).waitFor({ timeout: 120000 });
  }));
  console.log('PASS: verification takes a 16 MB original, refuses 16 MB + 1 byte, and the retry with the right file is valid');

  // Signature files stay at 8 MB.
  await tool.locator('#again').click();
  await tool.locator('#document').setInputFiles(file('big.p7s', randomBytes(8 * MB + 1)));
  await tool.locator('#status[data-error]').filter({ hasText: 'Файл превышает 8 МБ' }).waitFor();
  console.log('PASS: a signature file over 8 MB is refused');
  console.log('Limits E2E completed.');
} finally {
  await context.close().catch(() => {});
  rmSync(folder, { recursive: true, force: true });
}
