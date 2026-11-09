// Independent PAdES validation of extension output: EU DSS (Java, ETSI baseline profiles) and pyHanko.
// Synthetic keys and documents only. Requirements:
//   DSS_VALIDATOR=<dir> with lib/ (mvn -f tests/interop/dss/pom.xml dependency:copy-dependencies -DoutputDirectory=<dir>/lib)
//     and classes/ (javac -cp "<dir>/lib/*" -d <dir>/classes tests/interop/dss/Validate.java)
//   python3 with pyHanko 0.38.0 (tests/independent_pades.py)
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { PDFDocument, StandardFonts } from 'pdf-lib';
import { rsaFixture, PASSWORD } from './helpers/fixtures.js';
import { openContainer } from '../extension/crypto/signer.js';
import { signPades, inspectPdf } from '../extension/crypto/pades.js';

const dss = process.env.DSS_VALIDATOR;
if (!dss) throw new Error('Set DSS_VALIDATOR to the EU DSS validator directory.');
const folder = mkdtempSync(join(tmpdir(), 'tegin-pades-crosscheck-'));
const file = name => join(folder, name);
const python = resolve('tests/independent_pades.py');
const runDss = (pdf, cert) => JSON.parse(execFileSync('java', ['-cp', `${dss}/classes:${dss}/lib/*`, 'Validate', pdf, cert], { encoding: 'utf8' })).signatures;
const runHanko = (pdf, cert) => JSON.parse(execFileSync('python3', [python, 'validate', pdf, cert], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })).signatures;
const hanko = (...args) => execFileSync('python3', [python, ...args], { stdio: 'pipe' });

async function document(text, { objectStreams = false, field = false } = {}) {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  doc.addPage([595, 842]).drawText(text, { x: 50, y: 780, size: 16, font });
  doc.addPage([595, 842]).drawText('Page 2', { x: 50, y: 780, size: 12, font });
  if (field) { const input = doc.getForm().createTextField('customer'); input.setText('Synthetic'); input.addToPage(doc.getPage(0), { x: 50, y: 700, width: 200, height: 20 }); }
  return doc.save({ useObjectStreams: objectStreams });
}
function expectValid(name, cert) {
  const [dssResult, ...extraDss] = runDss(file(name), cert);
  const [hankoResult, ...extraHanko] = runHanko(file(name), cert);
  assert.equal(extraDss.length + extraHanko.length, 0);
  assert.equal(dssResult.indication, 'TOTAL_PASSED', JSON.stringify(dssResult));
  assert.equal(dssResult.format, 'PAdES-BASELINE-B');
  assert.ok(dssResult.intact && dssResult.valid && dssResult.bLevelValid && dssResult.byteRangeValid);
  assert.equal(dssResult.subFilter, 'ETSI.CAdES.detached');
  assert.equal(dssResult.modifications, false);
  assert.deepEqual(dssResult.errors, []);
  assert.ok(hankoResult.intact && hankoResult.valid && hankoResult.trusted && hankoResult.bottomLine && hankoResult.detached, JSON.stringify(hankoResult));
  assert.equal(hankoResult.coverage, 'ENTIRE_FILE');
  assert.equal(hankoResult.modificationLevel, 'NONE');
  assert.equal(hankoResult.adesBasic, 'PASSED');
  assert.deepEqual(hankoResult.signedAttributes, ['1.2.840.113549.1.9.16.2.47', '1.2.840.113549.1.9.3', '1.2.840.113549.1.9.4']);
  return { dss: dssResult, hanko: hankoResult };
}
function expectBroken(name, cert) {
  const [dssResult] = runDss(file(name), cert), [hankoResult] = runHanko(file(name), cert);
  assert.equal(dssResult.indication, 'TOTAL_FAILED', JSON.stringify(dssResult));
  assert.equal(dssResult.intact, false);
  assert.equal(hankoResult.intact, false); assert.equal(hankoResult.bottomLine, false);
  return { dss: `${dssResult.indication}/${dssResult.subIndication}`, hanko: 'intact=false' };
}

try {
  for (const keySpec of ['rsa:2048', 'rsa:3072', 'rsa:4096']) {
    const key = rsaFixture({ purpose: 'emailProtection', keySpec, subject: '/CN=Тегін синтетикалық тест' });
    const signer = await openContainer(key.container, PASSWORD);
    const cert = file(`${keySpec.replace(':', '')}.pem`); writeFileSync(cert, key.certificate);
    for (const [label, options] of [['plain', {}], ['object streams + form field', { objectStreams: true, field: true }]]) {
      const name = `${keySpec.replace(':', '')}-${label.replace(/\W+/g, '-')}.pdf`;
      writeFileSync(file(name), await signPades(signer, await document('Contract 100 KZT', options)));
      const { dss: d, hanko: h } = expectValid(name, cert);
      console.log(`PASS: ${keySpec} ${label}: DSS ${d.indication} ${d.format}; pyHanko ${h.coverage}, modifications ${h.modificationLevel}, AdES basic ${h.adesBasic}`);
    }
    if (keySpec !== 'rsa:2048') continue;

    const signed = readFileSync(file('rsa2048-plain.pdf'));
    const tampered = Buffer.from(signed.toString('latin1').replace('/MediaBox [ 0 0 595 842 ]', '/MediaBox [ 0 0 595 841 ]'), 'latin1');
    assert.notDeepEqual(tampered, signed);
    writeFileSync(file('tampered.pdf'), tampered);
    let outcome = expectBroken('tampered.pdf', cert);
    console.log(`PASS: page size changed by one byte inside the signed range: DSS ${outcome.dss}, pyHanko ${outcome.hanko}`);

    const other = Buffer.from(await signPades(signer, await document('Contract 900 KZT')));
    const range = buffer => /\/ByteRange \[(\d+) (\d+) (\d+) (\d+) *\]/.exec(buffer.toString('latin1')).slice(1).map(Number);
    const [, first, second] = range(signed), [, otherFirst, otherSecond] = range(other);
    assert.equal(otherSecond - otherFirst, second - first, 'the /Contents slots have the same size');
    writeFileSync(file('substituted.pdf'), Buffer.concat([signed.subarray(0, first), other.subarray(otherFirst, otherSecond), signed.subarray(second)]));
    outcome = expectBroken('substituted.pdf', cert);
    console.log(`PASS: signature of another document placed into this PDF: DSS ${outcome.dss}, pyHanko ${outcome.hanko}`);

    hanko('modify', file('rsa2048-plain.pdf'), file('modified.pdf'));
    const [dssModified] = runDss(file('modified.pdf'), cert), [hankoModified] = runHanko(file('modified.pdf'), cert);
    assert.equal(dssModified.modifications, true, JSON.stringify(dssModified));
    assert.equal(dssModified.objectModifications, true);
    assert.notEqual(dssModified.byteRange, `[0, ${first}, ${second}, ${readFileSync(file('modified.pdf')).length - second}]`);
    assert.equal(hankoModified.coverage, 'ENTIRE_REVISION');
    assert.notEqual(hankoModified.modificationLevel, 'NONE');
    assert.equal(hankoModified.bottomLine, false);
    console.log(`PASS: page drawn over in an incremental update after signing: DSS modifications=${dssModified.modifications}, object modifications=${dssModified.objectModifications}, indication ${dssModified.indication} (signed revision intact), warnings ${JSON.stringify(dssModified.warnings)}; pyHanko coverage ${hankoModified.coverage}, modifications ${hankoModified.modificationLevel}, bottom line false`);

    writeFileSync(file('plain.pdf'), await document('Contract 100 KZT'));
    hanko('encrypt', file('plain.pdf'), file('encrypted.pdf'));
    await assert.rejects(inspectPdf(new Uint8Array(readFileSync(file('encrypted.pdf')))), error => error.code === 'PDF_ENCRYPTED');
    writeFileSync(file('key.pem'), key.publicKey);
    hanko('sign', file('plain.pdf'), file('foreign.pdf'), file('key.pem'), cert);
    const foreign = new Uint8Array(readFileSync(file('foreign.pdf')));
    await assert.rejects(inspectPdf(foreign), error => error.code === 'PDF_SIGNED');
    await assert.rejects(signPades(signer, foreign), error => error.code === 'PDF_SIGNED');
    assert.equal(runHanko(file('foreign.pdf'), cert)[0].bottomLine, true);
    console.log('PASS: real encrypted PDF (pyHanko) and PDF signed by pyHanko are refused; the foreign signature stays valid');
  }
} finally { rmSync(folder, { recursive: true, force: true }); }
