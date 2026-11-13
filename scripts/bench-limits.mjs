// Time and peak memory of the local signing and verification core on synthetic inputs, one child process per run.
// node scripts/bench-limits.mjs [sizes in MB, default 2,8,16,32]
// Inputs: a text PDF, a "scan" PDF (one incompressible image per page) and CMS files made from them.
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const MB = 1024 * 1024;
const [mode, ...rest] = process.argv.slice(2);

async function signer(kind) {
  const { rsaFixture, gostFixture, PASSWORD } = await import('../tests/helpers/fixtures.js');
  const { openContainer } = await import('../extension/crypto/signer.js');
  const fixture = kind === 'gost' ? gostFixture('512', { keyUsage: true }) : rsaFixture({ keyUsage: 'digitalSignature,nonRepudiation' });
  return openContainer(fixture.container, PASSWORD);
}

async function pdf(kind, bytes) {
  const { PDFDocument, StandardFonts } = await import('pdf-lib');
  const doc = await PDFDocument.create();
  if (kind === 'scan') {
    // A JPEG header around random data: pdf-lib embeds it as DCT without decoding, like a scanner output.
    const page = Math.min(bytes, 2 * MB);
    for (let left = bytes; left > 0; left -= page) {
      const body = randomBytes(Math.min(page, left));
      const jpeg = Buffer.concat([Buffer.from('ffd8ffe000104a46494600010100000100010000ffc0001108080008000301220002110103110 1ffda000c03010002110311003f00'.replace(/ /g, ''), 'hex'), body, Buffer.from('ffd9', 'hex')]);
      const image = await doc.embedJpg(jpeg).catch(() => null);
      const sheet = doc.addPage([595, 842]);
      if (image) sheet.drawImage(image, { x: 0, y: 0, width: 595, height: 842 });
      else sheet.drawText('x');
    }
  } else {
    const font = await doc.embedFont(StandardFonts.Helvetica);
    const line = 'Synthetic contract text for a size test, no personal data. '.repeat(2);
    while (true) {
      const page = doc.addPage([595, 842]);
      for (let y = 800; y > 40; y -= 12) page.drawText(line, { x: 20, y, size: 8, font });
      if (doc.getPageCount() % 20 === 0 && (await doc.save({ useObjectStreams: false })).length >= bytes) break;
    }
  }
  return doc.save({ useObjectStreams: false });
}

if (mode === '--one') {
  const [operation, input, extra] = rest;
  const data = new Uint8Array(readFileSync(input));
  const start = performance.now();
  if (operation.startsWith('verify')) {
    const { verifyCms } = await import('../extension/crypto/cms-verify.js');
    await verifyCms(data, extra ? { detached: new Uint8Array(readFileSync(extra)) } : {});
  } else if (operation === 'inspect-pdf') {
    const { inspectPdf } = await import('../extension/crypto/pades.js');
    await inspectPdf(data);
  } else {
    const key = await signer(operation.includes('gost') ? 'gost' : 'rsa');
    const begin = performance.now();
    if (operation === 'pades-rsa') {
      const { signPades } = await import('../extension/crypto/pades.js');
      await signPades(key, data);
    } else {
      const { signCms } = await import('../extension/crypto/cms.js');
      const out = await signCms(key, data, { encapsulate: !operation.includes('detached'), cades: true });
      if (extra) writeFileSync(extra, out);
    }
    process.stdout.write(JSON.stringify({ ms: Math.round(performance.now() - begin), rssMB: Math.round(process.resourceUsage().maxRSS / 1024) }));
    process.exit(0);
  }
  process.stdout.write(JSON.stringify({ ms: Math.round(performance.now() - start), rssMB: Math.round(process.resourceUsage().maxRSS / 1024) }));
  process.exit(0);
}

const sizes = (mode || '2,8,16,32').split(',').map(Number);
const folder = mkdtempSync(join(tmpdir(), 'tegin-bench-'));
const self = fileURLToPath(import.meta.url);
const run = (...args) => JSON.parse(execFileSync(process.execPath, ['--max-old-space-size=4096', self, '--one', ...args], { encoding: 'utf8', maxBuffer: 16 * MB }));
const baseline = run('inspect-pdf', (writeFileSync(join(folder, 'tiny.pdf'), await pdf('text', 1)), join(folder, 'tiny.pdf')));
console.log(`node ${process.version}, ${process.platform} ${process.arch}; process with a tiny PDF: ${baseline.rssMB} MB RSS`);
console.log('| Input | MB | Operation | Time, ms | Peak RSS, MB |');
console.log('|---|---|---|---|---|');
try {
  for (const size of sizes) {
    for (const kind of ['text', 'scan']) {
      const file = join(folder, `${kind}-${size}.pdf`);
      writeFileSync(file, await pdf(kind, size * MB));
      const actual = (readFileSync(file).length / MB).toFixed(1);
      const attached = join(folder, `${kind}-${size}.p7s`), detached = join(folder, `${kind}-${size}-detached.p7s`);
      const rows = [
        ['inspect-pdf', run('inspect-pdf', file)],
        ['pades-rsa', run('pades-rsa', file)],
        ['cms-attached-rsa', run('cms-attached-rsa', file, attached)],
        ['cms-detached-rsa', run('cms-detached-rsa', file, detached)],
        ['cms-attached-gost', run('cms-attached-gost', file)],
        ['cms-detached-gost', run('cms-detached-gost', file)],
        ['verify-attached', readFileSync(attached).length > 8 * MB ? { ms: 'выше лимита ядра 8 МБ', rssMB: '—' } : run('verify-attached', attached)],
        ['verify-detached', run('verify-detached', detached, file)],
      ];
      for (const [operation, { ms, rssMB }] of rows) console.log(`| ${kind} PDF | ${actual} | ${operation} | ${ms} | ${rssMB} |`);
    }
  }
} finally { rmSync(folder, { recursive: true, force: true }); }
