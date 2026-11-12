import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir, devNull } from 'node:os';
import { PDFDocument, PDFName, PDFString, PDFHexString, PDFDict, StandardFonts } from 'pdf-lib';
import { rsaFixture, gostFixture, PASSWORD } from './helpers/fixtures.js';
import { openContainer } from '../extension/crypto/signer.js';
import { signPades, inspectPdf, PADES_SUBFILTER } from '../extension/crypto/pades.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';
import { forge } from '../extension/crypto/encoding.js';

const fixture = rsaFixture({ purpose: 'emailProtection' });
const signer = await openContainer(fixture.container, PASSWORD);

async function syntheticPdf(build = () => {}, { objectStreams = false } = {}) {
  const doc = await PDFDocument.create();
  const page = doc.addPage([595, 842]);
  page.drawText('Tegin synthetic PAdES document', { x: 50, y: 780, size: 16, font: await doc.embedFont(StandardFonts.Helvetica) });
  doc.addPage([595, 842]);
  await build(doc);
  return doc.save({ useObjectStreams: objectStreams });
}

function parts(pdf) {
  const text = Buffer.from(pdf).toString('latin1');
  const match = /\/ByteRange \[(\d+) (\d+) (\d+) (\d+) *\]/.exec(text);
  const [start, first, second, rest] = match.slice(1).map(Number);
  const covered = Buffer.concat([Buffer.from(pdf.subarray(start, first)), Buffer.from(pdf.subarray(second, second + rest))]);
  const hex = text.slice(first + 1, second - 1);
  return { range: [start, first, second, rest], covered, cms: trimDer(Buffer.from(hex, 'hex')), hex };
}
function trimDer(padded) {
  const octets = padded[1] & 0x7f;
  let length = 0;
  for (let index = 0; index < octets; index++) length = length * 256 + padded[2 + index];
  return padded.subarray(0, 2 + octets + length);
}

async function refusal(promise, code) {
  await assert.rejects(promise, error => error.code === code && error.pdf === true);
}

test('PAdES-B-B: ByteRange covers the whole file except /Contents, CAdES detached with B-B attributes', async () => {
  const original = await syntheticPdf();
  const input = original.slice();
  const signed = await signPades(signer, input, { signingTime: new Date('2026-11-09T10:00:00Z') });
  assert.deepEqual(input, original, 'input bytes stay untouched');
  const { range, covered, cms, hex } = parts(signed);
  assert.equal(range[0], 0);
  assert.equal(range[2] + range[3], signed.length);
  assert.equal(signed[range[1]], 0x3c); assert.equal(signed[range[2] - 1], 0x3e);
  assert.equal(range[2] - range[1], hex.length + 2);
  assert.match(hex, /^[0-9a-f]+$/);

  const doc = await PDFDocument.load(signed);
  assert.equal(doc.getPageCount(), 2);
  const signatures = [...doc.context.enumerateIndirectObjects()].map(([, object]) => object).filter(object => object instanceof PDFDict && object.get(PDFName.of('Type')) === PDFName.of('Sig'));
  assert.equal(signatures.length, 1);
  const dict = signatures[0];
  assert.equal(dict.get(PDFName.of('SubFilter')), PDFName.of(PADES_SUBFILTER));
  assert.equal(dict.get(PDFName.of('Filter')), PDFName.of('Adobe.PPKLite'));
  assert.equal(dict.lookup(PDFName.of('M')).asString(), 'D:20261109100000Z');
  assert.ok(dict.lookup(PDFName.of('Contents')) instanceof PDFHexString);
  const form = doc.catalog.lookup(PDFName.of('AcroForm'));
  assert.equal(form.lookup(PDFName.of('SigFlags')).asNumber(), 3);

  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(cms.toString('binary')));
  const signedData = asn1.value[1].value[0];
  assert.equal(signedData.value[2].value.length, 1, 'detached: no eContent');
  const signerInfo = signedData.value[4].value[0];
  const attributes = signerInfo.value[3].value.map(attribute => forge.asn1.derToOid(attribute.value[0].value));
  assert.deepEqual(attributes.sort(), ['1.2.840.113549.1.9.16.2.47', '1.2.840.113549.1.9.3', '1.2.840.113549.1.9.4'].sort());
  assert.ok(!attributes.includes('1.2.840.113549.1.9.5'), 'PAdES-B-B keeps the time in /M, not signing-time');
  const digest = signerInfo.value[3].value.find(attribute => forge.asn1.derToOid(attribute.value[0].value) === '1.2.840.113549.1.9.4').value[1].value[0].value;
  assert.equal(Buffer.from(digest, 'binary').toString('hex'), createHash('sha256').update(covered).digest('hex'));

  const verified = await verifyCms(new Uint8Array(cms), { detached: new Uint8Array(covered) });
  assert.equal(verified.signers.length, 1); assert.ok(verified.signers[0].cades);

  const folder = mkdtempSync(join(tmpdir(), 'tegin-pades-'));
  try {
    writeFileSync(join(folder, 'covered'), covered); writeFileSync(join(folder, 'cms.der'), cms); writeFileSync(join(folder, 'cert.pem'), fixture.certificate);
    execFileSync('openssl', ['cms', '-verify', '-binary', '-inform', 'DER', '-in', join(folder, 'cms.der'), '-content', join(folder, 'covered'),
      '-CAfile', join(folder, 'cert.pem'), '-purpose', 'any', '-out', devNull], { stdio: 'pipe' });
    const tampered = Buffer.from(covered); tampered[Math.floor(tampered.length / 2)] ^= 1;
    writeFileSync(join(folder, 'covered'), tampered);
    assert.throws(() => execFileSync('openssl', ['cms', '-verify', '-binary', '-inform', 'DER', '-in', join(folder, 'cms.der'), '-content', join(folder, 'covered'),
      '-CAfile', join(folder, 'cert.pem'), '-purpose', 'any', '-out', devNull], { stdio: 'pipe' }));
    await assert.rejects(verifyCms(new Uint8Array(cms), { detached: new Uint8Array(tampered) }), /изменён/);
  } finally { rmSync(folder, { recursive: true, force: true }); }
});

test('PAdES keeps existing form fields and accepts object streams', async () => {
  const pdf = await syntheticPdf(async doc => {
    const field = doc.getForm().createTextField('customer');
    field.setText('Synthetic value'); field.addToPage(doc.getPage(0), { x: 50, y: 700, width: 200, height: 20 });
  }, { objectStreams: true });
  assert.deepEqual(await inspectPdf(pdf), { pages: 2 });
  const signed = await signPades(signer, pdf);
  const doc = await PDFDocument.load(signed);
  assert.equal(doc.getForm().getTextField('customer').getText(), 'Synthetic value');
  const { cms, covered } = parts(signed);
  await verifyCms(new Uint8Array(cms), { detached: new Uint8Array(covered) });
});

test('PAdES refuses unsupported, encrypted and already signed PDFs without touching them', async () => {
  await refusal(inspectPdf(new TextEncoder().encode('plain text, not a PDF')), 'PDF_NOTPDF');
  await refusal(inspectPdf(new TextEncoder().encode('%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 9 0 R >>\nendobj\n1 0 obj << /broken')), 'PDF_BROKEN');

  const plain = Buffer.from(await syntheticPdf());
  const encrypted = new Uint8Array(Buffer.from(plain.toString('latin1').replace('trailer\n<<', 'trailer\n<<\n/Encrypt << /Filter /Standard /V 1 /R 2 /O <00> /U <00> /P -4 >>'), 'latin1'));
  await refusal(inspectPdf(encrypted), 'PDF_ENCRYPTED');
  await refusal(signPades(signer, encrypted), 'PDF_ENCRYPTED');

  const signed = await signPades(signer, await syntheticPdf());
  const before = signed.slice();
  await refusal(inspectPdf(signed), 'PDF_SIGNED');
  await refusal(signPades(signer, signed), 'PDF_SIGNED');
  assert.deepEqual(signed, before, 'existing signature is not modified');

  const certified = await syntheticPdf(doc => doc.catalog.set(PDFName.of('Perms'), doc.context.obj({ DocMDP: doc.context.obj({}) })));
  await refusal(inspectPdf(certified), 'PDF_SIGNED');

  const withField = await syntheticPdf(doc => {
    const field = doc.context.register(doc.context.obj({ FT: 'Sig', T: PDFString.of('Approval') }));
    doc.catalog.set(PDFName.of('AcroForm'), doc.context.obj({ Fields: [field] }));
  });
  await refusal(inspectPdf(withField), 'PDF_FIELD');

  const xfa = await syntheticPdf(doc => doc.catalog.set(PDFName.of('AcroForm'), doc.context.obj({ Fields: [], XFA: [] })));
  await refusal(inspectPdf(xfa), 'PDF_XFA');
});

test('PAdES finds signature fields with an indirect or inherited /FT and keeps text fields', async () => {
  const indirect = await syntheticPdf(doc => {
    const field = doc.context.register(doc.context.obj({ FT: doc.context.register(PDFName.of('Sig')), T: PDFString.of('Approval') }));
    doc.catalog.set(PDFName.of('AcroForm'), doc.context.obj({ Fields: [field] }));
  });
  await refusal(inspectPdf(indirect), 'PDF_FIELD');
  await refusal(signPades(signer, indirect), 'PDF_FIELD');

  // Parent is a direct dictionary inside /Fields: only the tree walk sees the inherited type.
  const inheritedField = type => syntheticPdf(doc => {
    const widget = doc.context.register(doc.context.obj({ Type: 'Annot', Subtype: 'Widget', Rect: [50, 600, 250, 620], T: PDFString.of('kid'), P: doc.getPage(0).ref }));
    doc.getPage(0).node.set(PDFName.of('Annots'), doc.context.obj([widget]));
    doc.catalog.set(PDFName.of('AcroForm'), doc.context.obj({ Fields: [doc.context.obj({ FT: doc.context.register(PDFName.of(type)), T: PDFString.of('parent'), Kids: [widget] })] }));
  });
  await refusal(inspectPdf(await inheritedField('Sig')), 'PDF_FIELD');
  const viaParent = await syntheticPdf(doc => {
    const parent = doc.context.register(doc.context.obj({ FT: 'Sig', T: PDFString.of('parent') }));
    const widget = doc.context.register(doc.context.obj({ Type: 'Annot', Subtype: 'Widget', Rect: [0, 0, 0, 0], Parent: parent }));
    doc.getPage(0).node.set(PDFName.of('Annots'), doc.context.obj([widget]));
  });
  await refusal(inspectPdf(viaParent), 'PDF_FIELD');

  const cyclic = await syntheticPdf(doc => {
    const first = doc.context.nextRef(), second = doc.context.nextRef();
    doc.context.assign(first, doc.context.obj({ T: PDFString.of('a'), Kids: [second] }));
    doc.context.assign(second, doc.context.obj({ T: PDFString.of('b'), Kids: [first], Parent: first }));
    doc.catalog.set(PDFName.of('AcroForm'), doc.context.obj({ Fields: [first] }));
  });
  await refusal(inspectPdf(cyclic), 'PDF_BROKEN');

  assert.deepEqual(await inspectPdf(await inheritedField('Tx')), { pages: 2 });
  const text = await syntheticPdf(async doc => {
    const field = doc.getForm().createTextField('reference');
    field.setText('Synthetic 42'); field.addToPage(doc.getPage(1), { x: 50, y: 700, width: 200, height: 20 });
  });
  const signed = await signPades(signer, text);
  assert.equal((await PDFDocument.load(signed)).getForm().getTextField('reference').getText(), 'Synthetic 42');
});

test('PAdES is not offered for GOST keys until a profile is independently validated', async () => {
  const gost = gostFixture('256', { eku: ['1.3.6.1.5.5.7.3.4'] });
  const gostSigner = await openContainer(gost.container, PASSWORD);
  await refusal(signPades(gostSigner, await syntheticPdf()), 'PDF_ALGORITHM');
});
