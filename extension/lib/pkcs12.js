// Structural inspection only. No decryption, certificate verification, or signing.
export const MAX_CONTAINER_BYTES = 4 * 1024 * 1024;
const DATA_OID = [42, 134, 72, 134, 247, 13, 1, 7, 1];
const ENCRYPTED_DATA_OID = [42, 134, 72, 134, 247, 13, 1, 7, 6];

// Stable failure codes for opening a container. Messages are safe to show to the
// user; library exceptions are never forwarded.
export const CONTAINER_FAILURES = Object.freeze({
  CONTAINER_EMPTY: ['structure', 'Файл пуст или недоступен.'],
  CONTAINER_TOO_LARGE: ['structure', 'Размер файла превышает 4 МБ.'],
  CONTAINER_MALFORMED: ['structure', 'Не удалось распознать структуру PKCS#12.'],
  CONTAINER_LIMITS: ['limits', 'Параметры защиты контейнера превышают допустимые ограничения.'],
  CONTAINER_NO_INTEGRITY: ['integrity', 'Контейнер без проверки целостности не поддерживается.'],
  UNSUPPORTED_INTEGRITY_ALGORITHM: ['integrity', 'Алгоритм проверки целостности контейнера не поддерживается.'],
  PASSWORD_ENCODING: ['password', 'Пароль содержит недопустимую последовательность символов Unicode.'],
  PASSWORD_OR_DAMAGED: ['integrity', 'Пароль не подошёл или контейнер повреждён.'],
  UNSUPPORTED_ENCRYPTION_ALGORITHM: ['decryption', 'Алгоритм шифрования контейнера не поддерживается.'],
  DECRYPTION_FAILED: ['decryption', 'Проверка целостности пройдена, но содержимое контейнера не удалось расшифровать.'],
  UNSUPPORTED_KEY_ALGORITHM: ['key', 'Алгоритм ключа в контейнере не поддерживается.'],
  KEY_TOO_WEAK: ['key', 'RSA-ключи короче 2048 бит не поддерживаются.'],
  NO_KEY_PAIR: ['key-pair', 'В контейнере не найдена поддерживаемая пара ключа и сертификата.'],
  CERTIFICATE_NOT_VALID_NOW: ['certificate', 'Срок действия сертификата ещё не наступил или уже истёк.'],
  CERTIFICATE_NO_DIGITAL_SIGNATURE: ['certificate', 'Сертификат не разрешает цифровую подпись.'],
  INTERNAL: [null, 'Не удалось открыть контейнер из-за внутренней ошибки.']
});

export class ContainerError extends Error {
  constructor(message, code = 'CONTAINER_MALFORMED', stage) {
    const [defaultStage, defaultMessage] = CONTAINER_FAILURES[code] || CONTAINER_FAILURES.INTERNAL;
    super(message || defaultMessage);
    this.name = 'ContainerError';
    this.code = code;
    this.stage = stage || defaultStage;
  }
}

export function inspectPkcs12(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) throw new ContainerError(undefined, 'CONTAINER_EMPTY');
  if (bytes.length > MAX_CONTAINER_BYTES) throw new ContainerError(undefined, 'CONTAINER_TOO_LARGE');

  let nodeCount = 0;
  function read(offset, limit, depth = 0) {
    if (depth > 32 || ++nodeCount > 50000) throw new ContainerError('Слишком сложная структура контейнера.', 'CONTAINER_LIMITS');
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
