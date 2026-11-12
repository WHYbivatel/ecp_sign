import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PDFDocument, StandardFonts } from 'pdf-lib';
import { inspectPdf, signPades } from '../extension/crypto/pades.js';
import { openContainer } from '../extension/crypto/signer.js';
import { rsaFixture, PASSWORD } from './helpers/fixtures.js';

// Mutation fuzzing of the local PDF path: inspectPdf must only refuse with its own PDF_* codes,
// and every document it accepts must sign (signPades re-checks its own output) or be refused.
// Deterministic: `node tests/fuzz-pdf.mjs [count] [seed]`. Synthetic documents and key only.
// FUZZ_PDF_OUT=<dir> also writes every signed output and the certificate for external validators.
const count = Number(process.argv[2] || 3000);
let seed = Number(process.argv[3] || 20261112);
const rand = n => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
async function base(pages, form) {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  for (let i = 0; i < pages; i++) doc.addPage().drawText(`Synthetic page ${i}`, { x: 50, y: 700, font });
  if (form) doc.getForm().createTextField('name').addToPage(doc.getPage(0), { x: 50, y: 600 });
  return new Uint8Array(await doc.save({ useObjectStreams: form }));
}
const snippets = ['['.repeat(64), '<<'.repeat(32), '/Type /Sig', '/Perms << >>', '/XFA [ ]', '/FT /Sig', '1 0 R', '99999999 0 R', '/Kids [3 0 R 3 0 R]',
  '/Parent 3 0 R', 'stream\n', 'endstream', '/Length 999999999', 'xref\n0 1\n', 'trailer << /Root 99 0 R >>', '/Filter /FlateDecode', '%%EOF', '/Count 2147483647', '/Prev 0'];
function mutate(input) {
  const out = Array.from(input);
  const kind = rand(5);
  if (kind === 0) for (let i = 0; i < 1 + rand(20); i++) out[rand(out.length)] = rand(256);
  else if (kind === 1) out.length = rand(out.length);
  else if (kind === 2) out.splice(rand(out.length), 0, ...new TextEncoder().encode(snippets[rand(snippets.length)].repeat(1 + rand(50))));
  else if (kind === 3) out.splice(rand(out.length), rand(200));
  else { const start = rand(out.length); out.splice(rand(out.length), 0, ...out.slice(start, start + rand(400))); }
  return Uint8Array.from(out);
}

const fixture = rsaFixture({ purpose: 'emailProtection' });
const signer = await openContainer(fixture.container, PASSWORD);
const out = process.env.FUZZ_PDF_OUT;
if (out) { mkdirSync(out, { recursive: true }); writeFileSync(join(out, 'cert.pem'), fixture.certificate); }
const bases = [await base(1, false), await base(5, true), await base(40, false)];
const result = { inputs: count, refused: {}, accepted: 0, signed: 0, signingRefused: {}, unexpected: [], maxInspectMs: 0, maxSignMs: 0 };
const quiet = console.log; console.log = () => {};
try {
  for (let i = 0; i < count; i++) {
    let data = bases[rand(bases.length)];
    for (let k = 0; k <= rand(3); k++) data = mutate(data);
    let started = performance.now();
    try { await inspectPdf(data); result.accepted++; }
    catch (error) { if (error.pdf) result.refused[error.code] = (result.refused[error.code] || 0) + 1; else result.unexpected.push(`inspect #${i}: ${String(error).slice(0, 120)}`); continue; }
    finally { result.maxInspectMs = Math.max(result.maxInspectMs, Math.round(performance.now() - started)); }
    started = performance.now();
    try { const signed = await signPades(signer, data); if (signed.length > data.length) { result.signed++; if (out) { writeFileSync(join(out, `signed-${i}.pdf`), signed); writeFileSync(join(out, `input-${i}.pdf`), data); } } else result.unexpected.push(`sign #${i}: output not larger than input`); }
    catch (error) { const key = String(error.code || error.message).slice(0, 80); result.signingRefused[key] = (result.signingRefused[key] || 0) + 1; }
    result.maxSignMs = Math.max(result.maxSignMs, Math.round(performance.now() - started));
  }
} finally { console.log = quiet; signer.destroy(); }
console.log(JSON.stringify(result, null, 1));
if (result.unexpected.length) process.exitCode = 1;
