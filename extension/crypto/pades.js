import { PDFDocument, PDFDict, PDFName, PDFArray, PDFNumber, PDFHexString, PDFRawStream, PDFString } from 'pdf-lib';
import { pdflibAddPlaceholder } from '@signpdf/placeholder-pdf-lib';
import { SignPdf, Signer } from '@signpdf/signpdf';
import { SUBFILTER_ETSI_CADES_DETACHED } from '@signpdf/utils';
import { signCms } from './cms.js';
import { verifyCms } from './cms-verify.js';
import { O, bytes as binaryBytes } from './encoding.js';

export const PADES_SUBFILTER = SUBFILTER_ETSI_CADES_DETACHED;
const SIGNATURE_LENGTH = 8192;
// Strict load: a lenient parser would silently drop objects it cannot read.
const LOAD = { updateMetadata: false, throwOnInvalidObject: true };
const name = PDFName.of;
const MESSAGES = {
  notPdf: 'Файл не является PDF-документом.',
  encrypted: 'PDF зашифрован или защищён паролем. Такой документ не подписывается: снимите защиту в программе, где он создан, и выберите файл снова.',
  signed: 'PDF уже содержит электронную подпись или сертификацию. Добавление второй подписи пока не поддерживается, существующие подписи не изменяются: подпись не создана.',
  field: 'PDF содержит поле для подписи. Подписание в существующие поля пока не поддерживается: подпись не создана.',
  xfa: 'PDF с формами XFA не поддерживается: подпись не создана.',
  empty: 'В PDF нет страниц.',
  broken: 'Не удалось разобрать PDF: документ повреждён или использует неподдерживаемые возможности. Подпись не создана.',
  algorithm: 'Подпись внутри PDF (PAdES) пока доступна только для ключей RSA: для ГОСТ нет независимо проверенного профиля PAdES.'
};
const refuse = (code, message = MESSAGES[code]) => Object.assign(new Error(message), { code: `PDF_${code.toUpperCase()}`, pdf: true });

function isPdf(data) {
  const head = new TextDecoder('latin1').decode(data.subarray(0, 1024));
  return head.includes('%PDF-');
}

async function load(data) {
  if (!isPdf(data)) throw refuse('notPdf');
  try { return await PDFDocument.load(data, LOAD); }
  catch {
    // pdf-lib's EncryptedPDFError does not survive instanceof (ES5 Error subclass).
    const encrypted = await PDFDocument.load(data, { ...LOAD, ignoreEncryption: true, throwOnInvalidObject: false }).then(doc => doc.isEncrypted, () => false);
    throw refuse(encrypted ? 'encrypted' : 'broken');
  }
}

const dictOf = object => object instanceof PDFDict ? object : object instanceof PDFRawStream ? object.dict : null;
function signatureDicts(doc) {
  const found = [];
  for (const [, object] of doc.context.enumerateIndirectObjects()) {
    const dict = dictOf(object);
    const type = dict?.get(name('Type'));
    if (dict && (type === name('Sig') || type === name('DocTimeStamp') || dict.has(name('ByteRange')))) found.push(dict);
  }
  return found;
}

function check(doc) {
  try {
    if (!doc.getPageCount()) throw refuse('empty');
    if (doc.catalog.has(name('Perms')) || signatureDicts(doc).length) throw refuse('signed');
    const form = doc.catalog.lookup(name('AcroForm'));
    if (form instanceof PDFDict && form.has(name('XFA'))) throw refuse('xfa');
    for (const [, object] of doc.context.enumerateIndirectObjects())
      if (dictOf(object)?.get(name('FT')) === name('Sig')) throw refuse('field');
    return { pages: doc.getPageCount() };
  } catch (error) { throw error.pdf ? error : refuse('broken'); }
}

// Runs before the key is opened so that unsupported documents are rejected up front.
export async function inspectPdf(data) {
  return check(await load(data));
}

class CmsSigner extends Signer {
  constructor(signer) { super(); this.signer = signer; }
  async sign(content) {
    const data = new Uint8Array(content);
    try { return await signCms(this.signer, data, { encapsulate: false, cades: true }); }
    finally { data.fill(0); }
  }
}

function derLength(data) {
  if (data[0] !== 0x30 || data.length < 2) return -1;
  if (!(data[1] & 0x80)) return 2 + data[1];
  const octets = data[1] & 0x7f;
  if (!octets || octets > 4 || data.length < 2 + octets) return -1;
  let length = 0;
  for (let index = 0; index < octets; index++) length = length * 256 + data[2 + index];
  return 2 + octets + length;
}

// Re-reads the result with the PDF parser: one signature, ByteRange over the whole file except
// /Contents, and a CMS that verifies against exactly those bytes.
async function checkSigned(pdf, signer) {
  const doc = await PDFDocument.load(pdf, LOAD);
  const signatures = signatureDicts(doc);
  if (signatures.length !== 1) throw new Error('Созданный PDF содержит неожиданное число подписей.');
  const dict = signatures[0];
  if (dict.get(name('Filter')) !== name('Adobe.PPKLite') || dict.get(name('SubFilter')) !== name(PADES_SUBFILTER) || !(dict.lookup(name('M')) instanceof PDFString)) throw new Error('Неверный словарь подписи PDF.');
  const range = dict.lookup(name('ByteRange'));
  const values = range instanceof PDFArray ? range.asArray().map(value => value instanceof PDFNumber ? value.asNumber() : NaN) : [];
  const [start, first, second, rest] = values;
  if (values.length !== 4 || start !== 0 || !(first > 0) || !(second > first + 1) || second + rest !== pdf.length || pdf[first] !== 0x3c || pdf[second - 1] !== 0x3e) throw new Error('ByteRange не покрывает весь PDF, кроме значения подписи.');
  const gap = new TextDecoder('latin1').decode(pdf.subarray(first + 1, second - 1));
  const contents = dict.lookup(name('Contents'));
  if (!/^[0-9a-f]+$/i.test(gap) || !(contents instanceof PDFHexString) || contents.asString().toLowerCase() !== gap.toLowerCase()) throw new Error('Значение /Contents не совпадает с промежутком ByteRange.');
  const padded = contents.asBytes();
  const length = derLength(padded);
  if (length < 0 || length > padded.length || padded.subarray(length).some(Boolean)) throw new Error('Значение /Contents не является CMS.');
  const covered = new Uint8Array(first + rest);
  covered.set(pdf.subarray(0, first)); covered.set(pdf.subarray(second), first);
  const verified = await verifyCms(padded.subarray(0, length), { detached: covered });
  const own = binaryBytes(signer.info.raw);
  const certificate = verified.signers.length === 1 && verified.signers[0].cades ? binaryBytes(verified.signers[0].certificate.raw) : '';
  if (certificate.length !== own.length || certificate.some((value, index) => value !== own[index])) throw new Error('Созданная подпись PDF не прошла проверку.');
}

export function checkPadesKey(signer) {
  if (signer.info.keyOid !== O.rsa) throw refuse('algorithm');
}

// PAdES-B-B (ETSI EN 319 142-1): CAdES detached over the ByteRange, signing time in /M only.
export async function signPades(signer, data, { signingTime = new Date() } = {}) {
  checkPadesKey(signer);
  const doc = await load(data);
  check(doc);
  pdflibAddPlaceholder({ pdfDoc: doc, reason: '', contactInfo: '', name: '', location: '', signingTime,
    signatureLength: SIGNATURE_LENGTH, subFilter: PADES_SUBFILTER, appName: 'Tegin' });
  const prepared = await doc.save({ useObjectStreams: false, updateFieldAppearances: false });
  const signed = new Uint8Array(await new SignPdf().sign(prepared, new CmsSigner(signer)));
  await checkSigned(signed, signer);
  return signed;
}
