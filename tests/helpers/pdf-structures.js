// Hand-built PDF structures that pdf-lib does not write: an unsigned incremental revision and a
// hybrid-reference file (ISO 32000-1 §7.5.6, §7.5.8.4). Synthetic content only.
import { PDFDocument } from 'pdf-lib';

const latin1 = data => Buffer.from(data).toString('latin1');

// Appends a revision with a new document information dictionary, as an editor does when it only
// updates metadata. The previous section must be a cross-reference table.
export async function appendInfoRevision(pdf, producer = 'Synthetic editor') {
  const text = latin1(pdf);
  const previous = Number(/startxref\s+(\d+)\s+%%EOF\s*$/.exec(text)[1]);
  const { context } = await PDFDocument.load(pdf, { updateMetadata: false });
  const number = context.largestObjectNumber + 1;
  const sizes = [...text.matchAll(/\/Size (\d+)/g)].map(match => Number(match[1]));
  const size = Math.max(number + 1, ...sizes);
  let tail = text.endsWith('\n') ? '' : '\n';
  const objectAt = pdf.length + tail.length;
  tail += `${number} 0 obj\n<< /Producer (${producer}) >>\nendobj\n`;
  const xrefAt = pdf.length + tail.length;
  tail += `xref\n${number} 1\n${String(objectAt).padStart(10, '0')} 00000 n \ntrailer\n<< /Size ${size} /Root ${context.trailerInfo.Root} /Info ${number} 0 R /Prev ${previous} >>\nstartxref\n${xrefAt}\n%%EOF\n`;
  return new Uint8Array(Buffer.concat([Buffer.from(pdf), Buffer.from(tail, 'latin1')]));
}

// One page; the font dictionary (object 4) lives in an object stream that only /XRefStm lists, and
// the table marks it free, as hybrid files written for older readers do.
export function hybridPdf(label = 'Hybrid reference synthetic document') {
  let text = '%PDF-1.5\n%\xe2\xe3\xcf\xd3\n';
  const offsets = {};
  const object = (number, body) => { offsets[number] = text.length; text += `${number} 0 obj\n${body}\nendobj\n`; };
  const stream = (dict, data) => `<< ${dict} /Length ${data.length} >>\nstream\n${data}\nendstream`;
  object(1, '<< /Type /Catalog /Pages 2 0 R >>');
  object(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>');
  object(3, '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 6 0 R >>');
  const header = '4 0 ', font = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
  object(5, stream(`/Type /ObjStm /N 1 /First ${header.length}`, header + font));
  object(6, stream('', `BT /F1 16 Tf 50 780 Td (${label}) Tj ET`));
  const row = [2, 0, 0, 0, 5, 0, 0].map(byte => String.fromCharCode(byte)).join('');
  object(7, stream('/Type /XRef /Size 8 /W [1 4 2] /Index [4 1]', row));
  const xrefAt = text.length;
  const entry = number => number === 0 ? '0000000000 65535 f \n' : number === 4 ? '0000000000 00000 f \n' : `${String(offsets[number]).padStart(10, '0')} 00000 n \n`;
  text += `xref\n0 8\n${[0, 1, 2, 3, 4, 5, 6, 7].map(entry).join('')}trailer\n<< /Size 8 /Root 1 0 R /XRefStm ${offsets[7]} >>\nstartxref\n${xrefAt}\n%%EOF\n`;
  return new Uint8Array(Buffer.from(text, 'latin1'));
}
