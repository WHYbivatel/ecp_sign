// Structural inspection only. No decryption, certificate verification, or signing.
export const MAX_CONTAINER_BYTES = 4 * 1024 * 1024;
const DATA_OID = [42, 134, 72, 134, 247, 13, 1, 7, 1];
const ENCRYPTED_DATA_OID = [42, 134, 72, 134, 247, 13, 1, 7, 6];

export class ContainerError extends Error {
  constructor(message = 'Не удалось распознать структуру PKCS#12.') {
    super(message);
    this.name = 'ContainerError';
  }
}

export function inspectPkcs12(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) throw new ContainerError('Файл пуст или недоступен.');
  if (bytes.length > MAX_CONTAINER_BYTES) throw new ContainerError('Размер файла превышает 4 МБ.');

  let nodeCount = 0;
  function read(offset, limit, depth = 0) {
    if (depth > 32 || ++nodeCount > 50000) throw new ContainerError('Слишком сложная структура контейнера.');
    const start = offset;
    if (offset + 2 > limit) throw new ContainerError();
    const tag = bytes[offset++];
    if ((tag & 31) === 31 || tag === 0) throw new ContainerError();
    let length = bytes[offset++];
    const indefinite = length === 128;
    if (indefinite && !(tag & 32)) throw new ContainerError();
    if ((length & 128) && !indefinite) {
      const count = length & 127;
      if (count === 0 || count > 4 || offset + count > limit || bytes[offset] === 0) throw new ContainerError();
      length = 0;
      for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++];
      if (length < 128) throw new ContainerError();
    }
    let end = indefinite ? limit : offset + length;
    if (end > limit) throw new ContainerError();
    const body = offset;
    const nodes = [];
    if (tag & 32) {
      while (offset < end) {
        if (indefinite && offset + 2 <= end && bytes[offset] === 0 && bytes[offset + 1] === 0) {
          return { tag, start, body, end: offset, next: offset + 2, nodes };
        }
        const child = read(offset, end, depth + 1);
        nodes.push(child);
        offset = child.next;
      }
      if (indefinite) throw new ContainerError();
    }
    return { tag, start, body, end, next: end, nodes };
  }

  function children(node, tag) {
    if (node.tag !== tag) throw new ContainerError();
    if (node.nodes.length > 128) throw new ContainerError();
    return node.nodes;
  }

  function matchesOid(node, expected) {
    return node?.tag === 6 && node.end - node.body === expected.length
      && expected.every((value, i) => value === bytes[node.body + i]);
  }

  const root = read(0, bytes.length);
  if (root.next !== bytes.length) throw new ContainerError();
  const pfx = children(root, 48);
  if (pfx.length < 2 || pfx.length > 3) throw new ContainerError();
  if (pfx[0].tag !== 2 || pfx[0].end - pfx[0].body !== 1 || bytes[pfx[0].body] !== 3) throw new ContainerError();
  const contentInfo = children(pfx[1], 48);
  if (contentInfo.length !== 2 || !matchesOid(contentInfo[0], DATA_OID)) throw new ContainerError();
  const wrapped = children(contentInfo[1], 160);
  if (wrapped.length !== 1 || wrapped[0].tag !== 4) throw new ContainerError();
  const safeRoot = read(wrapped[0].body, wrapped[0].end);
  if (safeRoot.next !== wrapped[0].end) throw new ContainerError();
  const safes = children(safeRoot, 48);
  if (safes.length === 0) throw new ContainerError();
  for (const safe of safes) {
    const fields = children(safe, 48);
    if (fields.length !== 2 || (!matchesOid(fields[0], DATA_OID) && !matchesOid(fields[0], ENCRYPTED_DATA_OID))) throw new ContainerError();
    const value = children(fields[1], 160);
    if (value.length !== 1) throw new ContainerError();
    if (matchesOid(fields[0], DATA_OID) ? value[0].tag !== 4 : value[0].tag !== 48) throw new ContainerError();
  }
  if (pfx[2] && pfx[2].tag !== 48) throw new ContainerError();
  // A structurally valid envelope does not establish integrity, identity, or key validity.
  return Object.freeze({ format: 'PKCS#12', version: 3, size: bytes.length });
}
