import { PDFDocument, PDFDict, PDFName, PDFArray, PDFNumber, PDFHexString, PDFRawStream, PDFRef, PDFString, PDFObjectParser, decodePDFRawStream } from 'pdf-lib';
import { signCms } from './cms.js';
import { verifyCms } from './cms-verify.js';
import { O, bytes as binaryBytes } from './encoding.js';

export const PADES_SUBFILTER = 'ETSI.CAdES.detached';
const SIGNATURE_LENGTH = 8192;
// Strict load: a lenient parser would silently drop objects it cannot read.
const LOAD = { updateMetadata: false, throwOnInvalidObject: true };
const name = PDFName.of;
const MESSAGES = {
  notPdf: 'Файл не является PDF-документом.',
  encrypted: 'PDF зашифрован или защищён паролем. Такой документ не подписывается: снимите защиту в программе, где он создан, и выберите файл снова.',
  certified: 'PDF заверен сертификационной подписью (DocMDP), которая ограничивает изменения. Добавление подписи в такой документ пока не поддерживается: подпись не создана.',
  field: 'PDF содержит пустое поле для подписи. Подписание в существующие поля пока не поддерживается: подпись не создана.',
  xfa: 'PDF с формами XFA не поддерживается: подпись не создана.',
  empty: 'В PDF нет страниц.',
  broken: 'Не удалось разобрать PDF: документ повреждён или использует неподдерживаемые возможности. Подпись не создана.',
  algorithm: 'Подпись внутри PDF (PAdES) пока доступна только для ключей RSA: для ГОСТ нет независимо проверенного профиля PAdES.'
};
const refuse = (code, message = MESSAGES[code]) => Object.assign(new Error(message), { code: `PDF_${code.toUpperCase()}`, pdf: true });

const latin1 = data => new TextDecoder('latin1').decode(data);
function isPdf(data) {
  return latin1(data.subarray(0, 1024)).includes('%PDF-');
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
const MAX_DEPTH = 32;
// Values such as /FT and /Type may be references to separate objects; a reference chain is malformed.
function resolve(doc, value) {
  for (let step = 0; value instanceof PDFRef; step++) {
    if (step >= MAX_DEPTH) throw refuse('broken');
    value = doc.context.lookup(value);
  }
  return value;
}
const entry = (doc, dict, key) => resolve(doc, dict.get(name(key)));
const isSignatureDict = (doc, dict) => entry(doc, dict, 'Type') === name('Sig') || entry(doc, dict, 'Type') === name('DocTimeStamp') || dict.has(name('ByteRange'));
function signatureDicts(doc) {
  const found = [];
  for (const [, object] of doc.context.enumerateIndirectObjects()) {
    const dict = dictOf(object);
    if (dict && isSignatureDict(doc, dict)) found.push(dict);
  }
  return found;
}

// Inheritable field attribute, through /Parent (ISO 32000-1 §12.7.3.1).
function inherited(doc, dict, key) {
  const seen = new Set();
  for (let node = dict; node instanceof PDFDict; node = resolve(doc, node.get(name('Parent')))) {
    if (seen.has(node) || seen.size >= MAX_DEPTH) throw refuse('broken');
    seen.add(node);
    const value = entry(doc, node, key);
    if (value !== undefined) return value;
  }
  return undefined;
}
// A signature field is filled when its value is a signature dictionary.
const filled = (doc, dict) => { const value = inherited(doc, dict, 'V'); return value instanceof PDFDict && isSignatureDict(doc, value); };

// Every field in the AcroForm tree and every widget on pages, with the type and value each one inherits.
function hasEmptySignatureField(doc) {
  for (const [, object] of doc.context.enumerateIndirectObjects()) {
    const dict = dictOf(object);
    if (dict && inherited(doc, dict, 'FT') === name('Sig') && !filled(doc, dict)) return true;
  }
  const visited = new Set();
  const walk = (value, type, signed, depth) => {
    const node = resolve(doc, value);
    if (!(node instanceof PDFDict)) return false;
    if (visited.has(node) || depth > MAX_DEPTH) throw refuse('broken');
    visited.add(node);
    const own = entry(doc, node, 'FT') ?? type;
    const ownValue = entry(doc, node, 'V');
    const isSigned = ownValue !== undefined ? ownValue instanceof PDFDict && isSignatureDict(doc, ownValue) : signed;
    const kids = resolve(doc, node.get(name('Kids')));
    if (kids instanceof PDFArray && kids.size()) return kids.asArray().some(kid => walk(kid, own, isSigned, depth + 1));
    return own === name('Sig') && !isSigned;
  };
  const form = resolve(doc, doc.catalog.get(name('AcroForm')));
  const fields = form instanceof PDFDict ? resolve(doc, form.get(name('Fields'))) : undefined;
  if (fields instanceof PDFArray && fields.asArray().some(field => walk(field, undefined, false, 0))) return true;
  for (const page of doc.getPages()) {
    const annotations = resolve(doc, page.node.get(name('Annots')));
    if (annotations instanceof PDFArray && annotations.asArray().some(annotation => {
      const dict = resolve(doc, annotation);
      return dict instanceof PDFDict && inherited(doc, dict, 'FT') === name('Sig') && !filled(doc, dict);
    })) return true;
  }
  return false;
}

function check(doc, data) {
  try {
    crossReferences(doc, data);
    if (!doc.getPageCount()) throw refuse('empty');
    if (doc.catalog.has(name('Perms'))) throw refuse('certified');
    const form = resolve(doc, doc.catalog.get(name('AcroForm')));
    if (form instanceof PDFDict && form.has(name('XFA'))) throw refuse('xfa');
    if (hasEmptySignatureField(doc)) throw refuse('field');
    return { pages: doc.getPageCount(), signatures: signatureDicts(doc).length };
  } catch (error) { throw error.pdf ? error : refuse('broken'); }
}

// Runs before the key is opened so that unsupported documents are rejected up front.
export async function inspectPdf(data) {
  return check(await load(data), data);
}

const MAX_SECTIONS = 64;
const integer = value => value instanceof PDFNumber && Number.isSafeInteger(value.asNumber()) && value.asNumber() >= 0 ? value.asNumber() : NaN;
// The cross-reference chain from the last startxref, as a validator reads it (ISO 32000-1 §7.5.4, §7.5.8):
// every entry in use must point at the header of that very object. pdf-lib parses objects sequentially and
// repairs a damaged table silently; signing such a file would protect bytes that viewers may read differently.
// Returns the last section: its offset, kind (table or stream) and /Size.
function crossReferences(doc, data) {
  const text = latin1(data);
  const match = /startxref\s+(\d+)\s+%%EOF\s*$/.exec(text.slice(-2048));
  const seen = new Set(), visited = new Set(), used = new Set(), containers = new Set();
  const objectAt = (offset, number, generation) => {
    const header = /\s*(\d+)\s+(\d+)\s+obj\b/y; header.lastIndex = offset;
    const found = offset > 0 && offset < data.length && header.exec(text);
    if (!found || Number(found[1]) !== number || Number(found[2]) !== generation) throw refuse('broken');
  };
  const entry = (number, generation, offset, inUse) => {
    if (seen.has(number)) return;
    seen.add(number);
    if (inUse) { objectAt(offset, number, generation); used.add(number); }
  };
  let last;
  const pending = [match ? Number(match[1]) : NaN];
  while (pending.length) {
    const offset = pending.shift();
    if (!(offset > 0 && offset < data.length) || visited.has(offset) || visited.size >= MAX_SECTIONS) throw refuse('broken');
    visited.add(offset);
    let trailer, stream = false;
    if (text.startsWith('xref', offset)) {
      const read = pattern => { pattern.lastIndex = position; const found = pattern.exec(text); if (found) position = pattern.lastIndex; return found; };
      let position = offset + 4;
      for (;;) {
        read(/\s*/y);
        if (text.startsWith('trailer', position)) break;
        const subsection = read(/(\d+)[ \t]+(\d+)[ \t]*(?:\r\n|\r|\n)/y);
        if (!subsection) throw refuse('broken');
        for (let index = 0, start = Number(subsection[1]); index < Number(subsection[2]); index++) {
          const row = read(/(\d{10}) (\d{5}) ([nf])[ \t]*(?:\r\n|\r|\n)/y);
          if (!row) throw refuse('broken');
          entry(start + index, Number(row[2]), Number(row[1]), row[3] === 'n');
        }
      }
      const parsed = PDFObjectParser.forBytes(data.subarray(position + 7), doc.context).parseObject();
      if (!(parsed instanceof PDFDict)) throw refuse('broken');
      trailer = parsed;
      const hybrid = integer(trailer.get(name('XRefStm')));
      if (trailer.has(name('XRefStm'))) pending.unshift(hybrid);
    } else {
      const header = /(\d+)\s+(\d+)\s+obj\b/y; header.lastIndex = offset;
      if (!header.exec(text)) throw refuse('broken');
      const object = PDFObjectParser.forBytes(data.subarray(header.lastIndex), doc.context).parseObject();
      if (!(object instanceof PDFRawStream) || object.dict.get(name('Type')) !== name('XRef')) throw refuse('broken');
      trailer = object.dict; stream = true;
      const widths = trailer.lookup(name('W')), size = integer(trailer.get(name('Size')));
      const index = trailer.has(name('Index')) ? trailer.lookup(name('Index')) : PDFArray.withContext(doc.context);
      if (!trailer.has(name('Index'))) { index.push(PDFNumber.of(0)); index.push(PDFNumber.of(size)); }
      const w = widths instanceof PDFArray && widths.size() === 3 ? widths.asArray().map(integer) : [];
      const ranges = index instanceof PDFArray && index.size() % 2 === 0 ? index.asArray().map(integer) : [NaN];
      if (w.length !== 3 || w.some(width => !(width <= 8)) || ranges.some(Number.isNaN)) throw refuse('broken');
      const rows = decodePDFRawStream(object).decode();
      const width = w[0] + w[1] + w[2];
      let at = 0;
      const field = (length, fallback) => { if (!length) return fallback; let value = 0; for (let byte = 0; byte < length; byte++) value = value * 256 + rows[at++]; return value; };
      for (let range = 0; range < ranges.length; range += 2) for (let number = ranges[range]; number < ranges[range] + ranges[range + 1]; number++) {
        if (at + width > rows.length) throw refuse('broken');
        const type = field(w[0], 1), second = field(w[1], 0), third = field(w[2], 0);
        if (type === 1) entry(number, third, second, true);
        else if (type === 2) { entry(number, 0, 0, false); containers.add(second); }
        else entry(number, 0, 0, false);
      }
    }
    const size = integer(trailer.get(name('Size')));
    if (Number.isNaN(size)) throw refuse('broken');
    last ??= { offset, stream, size };
    if (trailer.has(name('Prev'))) pending.push(integer(trailer.get(name('Prev'))));
  }
  // Objects inside an object stream are found through that stream's own entry.
  for (const number of containers) if (!used.has(number)) throw refuse('broken');
  return last;
}

const ascii = text => {
  const out = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (code > 255) throw refuse('broken');
    out[index] = code;
  }
  return out;
};
const pdfDate = date => `D:${date.toISOString().replace(/[-:T]/g, '').slice(0, 14)}Z`;

function fieldNames(doc) {
  const names = new Set();
  for (const [, object] of doc.context.enumerateIndirectObjects()) {
    const value = dictOf(object)?.lookup(name('T'));
    if (value instanceof PDFString || value instanceof PDFHexString) names.add(value.decodeText());
  }
  return names;
}

const PLACEHOLDER = '0000000000';
// PAdES-B-B as an incremental update (ISO 32000-1 §7.5.6): the original bytes stay unchanged in front;
// appended are the signature dictionary, an invisible signature field on page 1, new revisions of the
// page (/Annots) and of the form (/AcroForm), and a cross-reference section of the original's kind.
function appendSignature(doc, data, signingTime) {
  const { context } = doc;
  const section = crossReferences(doc, data);
  let next = Math.max(section.size, context.largestObjectNumber + 1);
  const fresh = () => PDFRef.of(next++, 0);
  const objects = new Map();
  const sigRef = fresh(), widgetRef = fresh();
  const page = doc.getPage(0);
  const names = fieldNames(doc);
  let index = 1;
  while (names.has(`Signature${index}`)) index++;
  objects.set(widgetRef, `<<\n/Type /Annot\n/Subtype /Widget\n/FT /Sig\n/T ${PDFString.of(`Signature${index}`)}\n/V ${sigRef}\n/F 132\n/Rect [0 0 0 0]\n/P ${page.ref}\n>>`);
  const extend = (container, key) => {
    const value = container.get(name(key));
    if (value instanceof PDFRef) {
      const array = context.lookup(value);
      if (!(array instanceof PDFArray)) throw refuse('broken');
      const copy = array.clone(context); copy.push(widgetRef);
      objects.set(value, copy.toString());
      return container;
    }
    if (value !== undefined && !(value instanceof PDFArray)) throw refuse('broken');
    const copy = container.clone(context);
    const array = value ? value.clone(context) : context.obj([]);
    array.push(widgetRef);
    copy.set(name(key), array);
    return copy;
  };
  const pageNode = extend(page.node, 'Annots');
  if (pageNode !== page.node) objects.set(page.ref, pageNode.toString());
  const root = context.trailerInfo.Root;
  const formValue = doc.catalog.get(name('AcroForm'));
  const signedForm = form => { const copy = extend(form, 'Fields'); const result = copy === form ? form.clone(context) : copy; result.set(name('SigFlags'), PDFNumber.of(3)); return result; };
  if (formValue instanceof PDFRef) {
    const form = context.lookup(formValue);
    if (!(form instanceof PDFDict)) throw refuse('broken');
    objects.set(formValue, signedForm(form).toString());
  } else {
    if (formValue !== undefined && !(formValue instanceof PDFDict)) throw refuse('broken');
    const catalog = doc.catalog.clone(context);
    if (formValue) catalog.set(name('AcroForm'), signedForm(formValue));
    else { const formRef = fresh(); objects.set(formRef, `<<\n/Fields [${widgetRef}]\n/SigFlags 3\n>>`); catalog.set(name('AcroForm'), formRef); }
    objects.set(root, catalog.toString());
  }
  const range = `/ByteRange [0 ${PLACEHOLDER} ${PLACEHOLDER} ${PLACEHOLDER}]`;
  const contents = `<${'0'.repeat(SIGNATURE_LENGTH * 2)}>`;
  objects.set(sigRef, `<<\n/Type /Sig\n/Filter /Adobe.PPKLite\n/SubFilter /${PADES_SUBFILTER}\n/M ${PDFString.of(pdfDate(signingTime))}\n${range}\n/Contents ${contents}\n>>`);

  const last = data[data.length - 1];
  let text = last === 0x0a || last === 0x0d ? '' : '\n';
  const offsets = [];
  let rangeAt = -1, contentsAt = -1;
  const write = (ref, body) => {
    offsets.push([ref, data.length + text.length]);
    const start = text.length + `${ref.objectNumber} ${ref.generationNumber} obj\n`.length;
    if (ref === sigRef) { rangeAt = data.length + start + body.indexOf(range); contentsAt = data.length + start + body.indexOf(contents); }
    text += `${ref.objectNumber} ${ref.generationNumber} obj\n${body}\nendobj\n`;
  };
  for (const [ref, body] of [...objects].sort(([a], [b]) => a.objectNumber - b.objectNumber)) write(ref, body);
  const trailer = [`/Root ${root}`, context.trailerInfo.Info ? `/Info ${context.trailerInfo.Info}` : '', context.trailerInfo.ID ? `/ID ${context.trailerInfo.ID}` : '', `/Prev ${section.offset}`].filter(Boolean).join('\n');
  const runs = entries => {
    const sorted = entries.slice().sort(([a], [b]) => a.objectNumber - b.objectNumber), groups = [];
    for (const item of sorted) {
      const group = groups[groups.length - 1];
      if (group && group.start + group.items.length === item[0].objectNumber) group.items.push(item); else groups.push({ start: item[0].objectNumber, items: [item] });
    }
    return groups;
  };
  if (!section.stream) {
    const xrefAt = data.length + text.length;
    text += 'xref\n';
    for (const group of runs(offsets)) {
      text += `${group.start} ${group.items.length}\n`;
      for (const [ref, offset] of group.items) text += `${String(offset).padStart(10, '0')} ${String(ref.generationNumber).padStart(5, '0')} n \n`;
    }
    text += `trailer\n<<\n/Size ${next}\n${trailer}\n>>\nstartxref\n${xrefAt}\n%%EOF\n`;
  } else {
    const xrefRef = fresh();
    const xrefAt = data.length + text.length;
    const all = [...offsets, [xrefRef, xrefAt]];
    const groups = runs(all);
    let rows = '';
    for (const group of groups) for (const [ref, offset] of group.items) {
      rows += String.fromCharCode(1, (offset >>> 24) & 255, (offset >>> 16) & 255, (offset >>> 8) & 255, offset & 255, (ref.generationNumber >>> 8) & 255, ref.generationNumber & 255);
    }
    const indexes = groups.map(group => `${group.start} ${group.items.length}`).join(' ');
    text += `${xrefRef.objectNumber} 0 obj\n<<\n/Type /XRef\n/Size ${next}\n/W [1 4 2]\n/Index [${indexes}]\n${trailer}\n/Length ${rows.length}\n>>\nstream\n${rows}\nendstream\nendobj\nstartxref\n${xrefAt}\n%%EOF\n`;
  }
  const pdf = new Uint8Array(data.length + text.length);
  pdf.set(data); pdf.set(ascii(text), data.length);
  return { pdf, rangeAt, rangeLength: range.length, contentsAt, contentsLength: contents.length };
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
const rangeOf = dict => {
  const range = dict.lookup(name('ByteRange'));
  return range instanceof PDFArray ? range.asArray().map(value => value instanceof PDFNumber ? value.asNumber() : NaN) : [];
};

// Re-reads the result: the original bytes are an unchanged prefix, earlier signatures cover only that
// prefix, and the new signature has a ByteRange over the whole file except /Contents with a CMS that
// verifies against exactly those bytes.
async function checkSigned(pdf, signer, original, before) {
  if (pdf.length <= original.length || original.some((value, index) => pdf[index] !== value)) throw new Error('Исходные байты PDF изменились: подпись не выдаётся.');
  const doc = await PDFDocument.load(pdf, LOAD);
  const signatures = signatureDicts(doc);
  const own = signatures.filter(dict => { const [, , second, rest] = rangeOf(dict); return second + rest === pdf.length; });
  const earlier = signatures.filter(dict => !own.includes(dict));
  if (own.length !== 1 || earlier.length !== before) throw new Error('Созданный PDF содержит неожиданное число подписей.');
  if (earlier.some(dict => { const [start, , second, rest] = rangeOf(dict); return !(start >= 0 && second + rest <= original.length); })) throw new Error('Прежняя подпись PDF охватывает новые данные.');
  const dict = own[0];
  if (dict.get(name('Filter')) !== name('Adobe.PPKLite') || dict.get(name('SubFilter')) !== name(PADES_SUBFILTER) || !(dict.lookup(name('M')) instanceof PDFString)) throw new Error('Неверный словарь подписи PDF.');
  const values = rangeOf(dict);
  const [start, first, second, rest] = values;
  if (values.length !== 4 || start !== 0 || !(first > original.length) || !(second > first + 1) || second + rest !== pdf.length || pdf[first] !== 0x3c || pdf[second - 1] !== 0x3e) throw new Error('ByteRange не покрывает весь PDF, кроме значения подписи.');
  const gap = latin1(pdf.subarray(first + 1, second - 1));
  const contents = dict.lookup(name('Contents'));
  if (!/^[0-9a-f]+$/i.test(gap) || !(contents instanceof PDFHexString) || contents.asString().toLowerCase() !== gap.toLowerCase()) throw new Error('Значение /Contents не совпадает с промежутком ByteRange.');
  const padded = contents.asBytes();
  const length = derLength(padded);
  if (length < 0 || length > padded.length || padded.subarray(length).some(Boolean)) throw new Error('Значение /Contents не является CMS.');
  const covered = new Uint8Array(first + rest);
  covered.set(pdf.subarray(0, first)); covered.set(pdf.subarray(second), first);
  const verified = await verifyCms(padded.subarray(0, length), { detached: covered });
  const ownCert = binaryBytes(signer.info.raw);
  const certificate = verified.signers.length === 1 && verified.signers[0].cades ? binaryBytes(verified.signers[0].certificate.raw) : '';
  if (certificate.length !== ownCert.length || certificate.some((value, index) => value !== ownCert[index])) throw new Error('Созданная подпись PDF не прошла проверку.');
}

export function checkPadesKey(signer) {
  if (signer.info.keyOid !== O.rsa) throw refuse('algorithm');
}

// PAdES-B-B (ETSI EN 319 142-1): CAdES detached over the ByteRange, signing time in /M only.
// A PDF that already holds signatures gets the new one in a further revision; earlier ones stay valid.
export async function signPades(signer, data, { signingTime = new Date() } = {}) {
  checkPadesKey(signer);
  const doc = await load(data);
  const { signatures } = check(doc, data);
  let prepared;
  try { prepared = appendSignature(doc, data, signingTime); }
  catch (error) { throw error.pdf ? error : refuse('broken'); }
  const { pdf, rangeAt, rangeLength, contentsAt, contentsLength } = prepared;
  const range = [0, contentsAt, contentsAt + contentsLength, pdf.length - contentsAt - contentsLength];
  const rangeText = `/ByteRange [${range.join(' ')}]`;
  if (rangeText.length > rangeLength) throw refuse('broken');
  pdf.set(ascii(rangeText.padEnd(rangeLength, ' ')), rangeAt);
  const covered = new Uint8Array(range[1] + range[3]);
  covered.set(pdf.subarray(0, range[1])); covered.set(pdf.subarray(range[2]), range[1]);
  let cms;
  try { cms = await signCms(signer, covered, { encapsulate: false, cades: true }); }
  finally { covered.fill(0); }
  if (cms.length * 2 > contentsLength - 2) throw new Error('Подпись не помещается в отведённое в PDF место.');
  pdf.set(ascii([...cms].map(value => value.toString(16).padStart(2, '0')).join('')), contentsAt + 1);
  await checkSigned(pdf, signer, data, signatures);
  return pdf;
}
