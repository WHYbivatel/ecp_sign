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
import { appendInfoRevision, hybridPdf } from './helpers/pdf-structures.js';

const dss = process.env.DSS_VALIDATOR;
if (!dss) throw new Error('Set DSS_VALIDATOR to the EU DSS validator directory.');
const folder = mkdtempSync(join(tmpdir(), 'tegin-pades-crosscheck-'));
const file = name => join(folder, name);
const python = resolve('tests/independent_pades.py');
const runDss = (pdf, cert) => JSON.parse(execFileSync('java', ['-cp', `${dss}/classes:${dss}/lib/*`, 'Validate', pdf, cert], { encoding: 'utf8' })).signatures;
const runHanko = (pdf, cert, mode = 'strict') => JSON.parse(execFileSync('python3', [python, 'validate', pdf, cert, mode], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })).signatures;
const hanko = (...args) => execFileSync('python3', [python, ...args], { stdio: 'pipe' });

async function document(text, { objectStreams = false, field = false } = {}) {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  doc.addPage([595, 842]).drawText(text, { x: 50, y: 780, size: 16, font });
  doc.addPage([595, 842]).drawText('Page 2', { x: 50, y: 780, size: 12, font });
  if (field) { const input = doc.getForm().createTextField('customer'); input.setText('Synthetic'); input.addToPage(doc.getPage(0), { x: 50, y: 700, width: 200, height: 20 }); }
  return doc.save({ useObjectStreams: objectStreams });
}
function expectValid(name, cert, mode) {
  const [dssResult, ...extraDss] = runDss(file(name), cert);
  const [hankoResult, ...extraHanko] = runHanko(file(name), cert, mode);
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
// Two signatures in separate revisions: the earlier one sees only a signature added after it.
function expectTwo(name, cert, { foreignSecond = false } = {}) {
  const dssResults = runDss(file(name), cert), hankoResults = runHanko(file(name), cert);
  assert.equal(dssResults.length, 2); assert.equal(hankoResults.length, 2);
  for (const item of dssResults) {
    assert.equal(item.indication, 'TOTAL_PASSED', JSON.stringify(item));
    assert.ok(item.intact && item.valid && item.byteRangeValid);
    assert.equal(item.modifications, false, JSON.stringify(item));
    assert.equal(item.undefinedChanges + item.annotationChanges, 0, JSON.stringify(item));
    // pyHanko registers its ESIC developer extension in the catalog; Tegin adds none.
    if (!foreignSecond) assert.equal(item.extensionChanges, 0, JSON.stringify(item));
  }
  assert.ok(dssResults[0].signatureOrFormFillChanges > 0, JSON.stringify(dssResults[0]));
  for (const item of hankoResults) assert.ok(item.intact && item.valid && item.trusted && item.bottomLine && item.docmdpOk, JSON.stringify(item));
  const [first, second] = hankoResults;
  assert.equal(first.coverage, 'ENTIRE_REVISION'); assert.equal(first.modificationLevel, 'FORM_FILLING');
  assert.equal(second.coverage, 'ENTIRE_FILE'); assert.equal(second.modificationLevel, 'NONE');
  if (!foreignSecond) { assert.equal(dssResults[1].format, 'PAdES-BASELINE-B'); assert.equal(second.adesBasic, 'PASSED'); }
  assert.notEqual(first.fieldName, second.fieldName);
  return {
    first: `DSS ${dssResults[0].indication}, signature/form-fill changes ${dssResults[0].signatureOrFormFillChanges}, extension ${dssResults[0].extensionChanges}, undefined 0; pyHanko ${first.coverage}/${first.modificationLevel}`,
    second: `DSS ${dssResults[1].indication} ${dssResults[1].format}; pyHanko ${second.coverage}/${second.modificationLevel}`
  };
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
    console.log('PASS: real encrypted PDF (pyHanko) is refused');

    // Second signature: Tegin after Tegin, Tegin after pyHanko, pyHanko after Tegin.
    for (const [label, base] of [['plain', 'rsa2048-plain.pdf'], ['object streams + form field', 'rsa2048-object-streams-form-field.pdf'], ['after a pyHanko signature', 'foreign.pdf']]) {
      const first = new Uint8Array(readFileSync(file(base)));
      const second = await signPades(signer, first);
      assert.deepEqual(second.subarray(0, first.length), first, 'first signed revision is byte-identical');
      const name = `second-${label.replace(/\W+/g, '-')}.pdf`;
      writeFileSync(file(name), second);
      const result = expectTwo(name, cert);
      console.log(`PASS: second Tegin signature, ${label}: first ${result.first}; second ${result.second}; first revision bytes unchanged`);
    }
    hanko('sign', file('rsa2048-plain.pdf'), file('hanko-second.pdf'), file('key.pem'), cert);
    assert.deepEqual(readFileSync(file('hanko-second.pdf')).subarray(0, signed.length), signed);
    const result = expectTwo('hanko-second.pdf', cert, { foreignSecond: true });
    console.log(`PASS: pyHanko signs after Tegin: first ${result.first}; second ${result.second}`);

    hanko('modify', file('second-plain.pdf'), file('second-modified.pdf'));
    const dssBoth = runDss(file('second-modified.pdf'), cert), hankoBoth = runHanko(file('second-modified.pdf'), cert);
    assert.equal(dssBoth.length, 2); assert.equal(hankoBoth.length, 2);
    for (const item of dssBoth) {
      assert.ok(item.intact && item.valid, JSON.stringify(item));
      assert.equal(item.modifications, true);
      assert.ok(item.undefinedChanges > 0, JSON.stringify(item));
      assert.ok(item.warnings.some(warning => /undefined object modifications/.test(warning)), JSON.stringify(item));
    }
    for (const item of hankoBoth) {
      assert.ok(item.intact && item.valid, JSON.stringify(item));
      assert.equal(item.coverage, 'ENTIRE_REVISION');
      assert.equal(item.modificationLevel, 'OTHER');
      assert.equal(item.bottomLine, false);
    }
    console.log(`PASS: page drawn over after two signatures: DSS undefined changes ${dssBoth.map(item => item.undefinedChanges).join('/')}, warnings ${JSON.stringify(dssBoth[0].warnings)}; pyHanko ${hankoBoth.map(item => item.modificationLevel).join('/')}, bottom line false`);

    const two = readFileSync(file('second-plain.pdf'));
    const changed = Buffer.from(two.toString('latin1').replace('/MediaBox [ 0 0 595 842 ]', '/MediaBox [ 0 0 595 841 ]'), 'latin1');
    assert.notDeepEqual(changed, two);
    writeFileSync(file('second-tampered.pdf'), changed);
    const dssTampered = runDss(file('second-tampered.pdf'), cert), hankoTampered = runHanko(file('second-tampered.pdf'), cert);
    assert.ok(dssTampered.every(item => item.indication === 'TOTAL_FAILED' && !item.intact), JSON.stringify(dssTampered));
    assert.ok(hankoTampered.every(item => !item.intact && !item.bottomLine));
    console.log('PASS: byte changed inside the first revision of a two-signature PDF: both signatures fail in DSS and pyHanko');

    // Structures pdf-lib does not write: hybrid references and an unsigned revision before signing.
    // pyHanko's strict reader refuses every signature in a hybrid-reference file by policy; it is read leniently here.
    writeFileSync(file('hybrid.pdf'), await signPades(signer, hybridPdf()));
    assert.throws(() => execFileSync('python3', [python, 'validate', file('hybrid.pdf'), cert], { encoding: 'utf8', stdio: 'pipe' }), error => /do not permit validation of signatures in hybrid-reference files/.test(error.stderr));
    let check = expectValid('hybrid.pdf', cert, 'lenient');
    console.log(`PASS: hybrid-reference PDF (table + /XRefStm, font in an object stream): DSS ${check.dss.indication} ${check.dss.format}; pyHanko lenient ${check.hanko.coverage}/${check.hanko.modificationLevel}; pyHanko strict refuses hybrid files by policy`);
    writeFileSync(file('edited.pdf'), await signPades(signer, await appendInfoRevision(await document('Contract 100 KZT'))));
    check = expectValid('edited.pdf', cert);
    console.log(`PASS: unsigned incremental revision before signing: DSS ${check.dss.indication}; pyHanko ${check.hanko.coverage}/${check.hanko.modificationLevel}`);

    // A pyHanko signature whose field /Lock covers a text field: /P 1 forbids any later change, 2 and absent allow signing.
    writeFileSync(file('form.pdf'), await document('Contract 100 KZT', { field: true }));
    for (const permission of ['-', '2', '1']) {
      const locked = file(`locked-${permission}.pdf`);
      hanko('sign-locked', file('form.pdf'), locked, file('key.pem'), cert, 'customer', permission);
      if (permission === '1') {
        await assert.rejects(signPades(signer, new Uint8Array(readFileSync(locked))), error => error.code === 'PDF_LOCKED');
        console.log('PASS: earlier signature with /Lock /P 1 (no changes allowed): Tegin refuses, the document is not touched');
        continue;
      }
      writeFileSync(file(`locked-${permission}-tegin.pdf`), await signPades(signer, new Uint8Array(readFileSync(locked))));
      const lockedResult = expectTwo(`locked-${permission}-tegin.pdf`, cert, { foreignSecond: true });
      console.log(`PASS: Tegin signs after a pyHanko signature with a FieldMDP /Lock${permission === '-' ? '' : ` /P ${permission}`}: first ${lockedResult.first}; second ${lockedResult.second}`);
    }
    // Control: changing the locked field after that signature is caught by both validators.
    hanko('fill', file('locked---tegin.pdf'), file('locked-filled.pdf'), 'customer', 'Changed');
    const lockedHanko = runHanko(file('locked-filled.pdf'), cert), lockedDss = runDss(file('locked-filled.pdf'), cert);
    // The pyHanko signature locked the field; Tegin's signature locks nothing, so for it the change is form filling.
    assert.equal(lockedHanko[0].fieldName, 'Locked');
    assert.ok(lockedHanko[0].intact && !lockedHanko[0].docmdpOk && lockedHanko[0].bottomLine === false, JSON.stringify(lockedHanko[0]));
    assert.equal(lockedHanko[1].modificationLevel, 'FORM_FILLING', JSON.stringify(lockedHanko[1]));
    // DSS 6.5.1 classifies the change as form filling and does not apply the /Lock; recorded, not relied on.
    assert.ok(lockedDss[0].objectModifications && lockedDss[0].signatureOrFormFillChanges > 0, JSON.stringify(lockedDss[0]));
    console.log(`PASS: locked field changed after both signatures: pyHanko marks the locking signature (${lockedHanko[0].modificationLevel}, bottom line false) and sees form filling after Tegin's; DSS does not apply /Lock: ${lockedDss.map(item => `${item.indication}, form-fill changes ${item.signatureOrFormFillChanges}`).join(' / ')}`);
  }
} finally { rmSync(folder, { recursive: true, force: true }); }
