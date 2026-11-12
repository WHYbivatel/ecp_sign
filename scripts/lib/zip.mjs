// Minimal ZIP reader: central directory, stored and deflated entries. Development and CI only.
import { inflateRawSync } from 'node:zlib';

export function zipEntries(zip) {
  let end = zip.length - 22;
  while (end >= 0 && zip.readUInt32LE(end) !== 0x06054b50) end--;
  if (end < 0) throw new Error('Not a ZIP archive');
  const count = zip.readUInt16LE(end + 10);
  let offset = zip.readUInt32LE(end + 16);
  const result = new Map();
  for (let i = 0; i < count; i++) {
    if (zip.readUInt32LE(offset) !== 0x02014b50) throw new Error('Damaged ZIP directory');
    const method = zip.readUInt16LE(offset + 10), size = zip.readUInt32LE(offset + 20);
    const nameLength = zip.readUInt16LE(offset + 28), extra = zip.readUInt16LE(offset + 30), comment = zip.readUInt16LE(offset + 32);
    const local = zip.readUInt32LE(offset + 42);
    result.set(zip.toString('utf8', offset + 46, offset + 46 + nameLength), { method, size, local });
    offset += 46 + nameLength + extra + comment;
  }
  return {
    has: name => result.has(name),
    names: () => [...result.keys()],
    read(name) {
      const entry = result.get(name);
      if (!entry) throw new Error(`${name} is missing from the archive`);
      const start = entry.local + 30 + zip.readUInt16LE(entry.local + 26) + zip.readUInt16LE(entry.local + 28);
      const data = zip.subarray(start, start + entry.size);
      if (entry.method === 0) return data;
      if (entry.method === 8) return inflateRawSync(data);
      throw new Error(`Unsupported ZIP method ${entry.method}`);
    }
  };
}
