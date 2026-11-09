// Minimal strict DER reader over Uint8Array. Nodes keep exact byte ranges, so signed
// structures (TBSCertList, ResponseData) are verified over the received bytes, and a
// 20 MB CRL can be walked without building a forge tree.

export class DerError extends Error {}

export function read(buffer, offset = 0, end = buffer.length) {
  if (offset + 2 > end) throw new DerError('truncated');
  const first = buffer[offset];
  if ((first & 0x1f) === 0x1f) throw new DerError('high tag number');
  let length = buffer[offset + 1], header = 2;
  if (length === 0x80) throw new DerError('indefinite length');
  if (length > 0x80) {
    const count = length & 0x7f;
    if (count > 4 || offset + 2 + count > end) throw new DerError('length');
    length = 0;
    for (let index = 0; index < count; index++) length = length * 256 + buffer[offset + 2 + index];
    if (length < 0x80 || buffer[offset + 2] === 0) throw new DerError('non-minimal length');
    header += count;
  }
  const start = offset + header;
  if (start + length > end) throw new DerError('truncated');
  return { tag: first, cls: first >> 6, constructed: Boolean(first & 0x20), number: first & 0x1f, offset, start, end: start + length, buffer };
}

export function children(node) {
  if (!node.constructed) throw new DerError('primitive');
  const result = [];
  for (let offset = node.start; offset < node.end;) {
    const child = read(node.buffer, offset, node.end);
    result.push(child);
    offset = child.end;
  }
  return result;
}

export function* iterate(node) {
  if (!node.constructed) throw new DerError('primitive');
  for (let offset = node.start; offset < node.end;) {
    const child = read(node.buffer, offset, node.end);
    yield child;
    offset = child.end;
  }
}

export const TAG = { INTEGER: 0x02, BIT_STRING: 0x03, OCTET_STRING: 0x04, NULL: 0x05, OID: 0x06, ENUMERATED: 0x0a, SEQUENCE: 0x30, SET: 0x31,
  UTC_TIME: 0x17, GENERALIZED_TIME: 0x18, BOOLEAN: 0x01 };

export function root(buffer) {
  const node = read(buffer, 0, buffer.length);
  if (node.end !== buffer.length) throw new DerError('trailing data');
  return node;
}
export const content = node => node.buffer.subarray(node.start, node.end);
export const whole = node => node.buffer.subarray(node.offset, node.end);
export function expect(node, tag) {
  if (!node || node.tag !== tag) throw new DerError(`unexpected tag ${node?.tag}`);
  return node;
}

export function oid(node) {
  expect(node, TAG.OID);
  const bytes = content(node);
  if (!bytes.length || bytes[bytes.length - 1] & 0x80) throw new DerError('oid');
  const parts = [];
  let value = 0;
  for (let index = 0; index < bytes.length; index++) {
    if (value === 0 && bytes[index] === 0x80) throw new DerError('oid');
    value = value * 128 + (bytes[index] & 0x7f);
    if (value > Number.MAX_SAFE_INTEGER / 256) throw new DerError('oid');
    if (!(bytes[index] & 0x80)) { parts.push(value); value = 0; }
  }
  const head = parts.shift();
  const firstArc = head < 40 ? 0 : head < 80 ? 1 : 2;
  return [firstArc, head - firstArc * 40, ...parts].join('.');
}

export function integerBytes(node) {
  expect(node, TAG.INTEGER);
  const bytes = content(node);
  if (!bytes.length || (bytes.length > 1 && ((bytes[0] === 0 && !(bytes[1] & 0x80)) || (bytes[0] === 0xff && bytes[1] & 0x80)))) throw new DerError('integer');
  return bytes;
}

export function smallInteger(node) {
  const bytes = node.tag === TAG.ENUMERATED ? content(node) : integerBytes(node);
  if (!bytes.length || bytes.length > 6 || bytes[0] & 0x80) throw new DerError('integer range');
  return bytes.reduce((value, byte) => value * 256 + byte, 0);
}

export function boolean(node) {
  expect(node, TAG.BOOLEAN);
  const bytes = content(node);
  if (bytes.length !== 1 || (bytes[0] !== 0 && bytes[0] !== 0xff)) throw new DerError('boolean');
  return bytes[0] === 0xff;
}

export function bitStringBytes(node) {
  expect(node, TAG.BIT_STRING);
  const bytes = content(node);
  if (!bytes.length || bytes[0] !== 0) throw new DerError('bit string');
  return bytes.subarray(1);
}

const ascii = bytes => String.fromCharCode(...bytes);
export function time(node) {
  const text = ascii(content(node));
  let match;
  if (node.tag === TAG.UTC_TIME) {
    match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (!match) throw new DerError('utc time');
    const year = Number(match[1]);
    match = [match[0], String(year >= 50 ? 1900 + year : 2000 + year), ...match.slice(2), ''];
  } else if (node.tag === TAG.GENERALIZED_TIME) {
    match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d*[1-9])?Z$/.exec(text);
    if (!match) throw new DerError('generalized time');
  } else throw new DerError('time');
  const [, year, month, day, hour, minute, second, fraction = ''] = match;
  const value = Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second), fraction ? Math.floor(Number('0' + fraction) * 1000) : 0);
  const check = new Date(value);
  if (!Number.isFinite(value) || check.getUTCDate() !== Number(day) || check.getUTCMonth() !== Number(month) - 1 || check.getUTCHours() !== Number(hour) || check.getUTCMinutes() !== Number(minute)) throw new DerError('time value');
  return value;
}

export const equal = (left, right) => left.length === right.length && left.every((value, index) => value === right[index]);

// Extensions ::= SEQUENCE OF Extension. Returns [{ id, critical, value: Uint8Array }]; duplicates are rejected.
export function extensions(node) {
  const seen = new Set();
  return children(expect(node, TAG.SEQUENCE)).map(entry => {
    const parts = children(expect(entry, TAG.SEQUENCE));
    if (parts.length < 2 || parts.length > 3) throw new DerError('extension');
    const id = oid(parts[0]);
    if (seen.has(id)) throw new DerError('duplicate extension');
    seen.add(id);
    const critical = parts.length === 3 ? boolean(parts[1]) : false;
    return { id, critical, value: content(expect(parts.at(-1), TAG.OCTET_STRING)) };
  });
}
