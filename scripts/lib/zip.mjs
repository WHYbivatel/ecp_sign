// Minimal ZIP reader and deterministic writer: central directory, stored and deflated entries. Development and CI only.
import { crc32, deflateRawSync, inflateRawSync } from 'node:zlib';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

// MS-DOS date of 1980-01-01 00:00, the earliest a ZIP entry can carry; every entry gets it.
export const ZIP_DATE = (0 << 9) | (1 << 5) | 1;
const UTF8_NAMES = 0x0800;
const FILE_MODE = (0o100644 << 16) >>> 0;

export async function filesIn(folder, prefix = '') {
  const files = [];
  for (const entry of await readdir(folder, { withFileTypes: true })) {
    const name = prefix + entry.name;
    if (entry.isDirectory()) files.push(...await filesIn(join(folder, entry.name), `${name}/`));
    else files.push(name);
  }
  return files.sort();
}

// The same folder gives the same bytes: sorted names, no directory entries, fixed time and mode, no extra fields.
// Deflate output depends on the zlib bundled with Node, so the archive is reproducible for one Node release line.
export async function zipFolder(folder) {
  const locals = [], central = [];
  let offset = 0;
  for (const name of await filesIn(folder)) {
    const data = await readFile(join(folder, name));
    const packed = deflateRawSync(data, { level: 9 });
    const [method, body] = packed.length < data.length ? [8, packed] : [0, data];
    const path = Buffer.from(name, 'utf8');
    const fields = header => {
      header.writeUInt16LE(20, 4); header.writeUInt16LE(UTF8_NAMES, 6); header.writeUInt16LE(method, 8);
      header.writeUInt16LE(0, 10); header.writeUInt16LE(ZIP_DATE, 12); header.writeUInt32LE(crc32(data), 14);
      header.writeUInt32LE(body.length, 18); header.writeUInt32LE(data.length, 22); header.writeUInt16LE(path.length, 26);
    };
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); fields(local);
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0); entry.writeUInt16LE((3 << 8) | 20, 4);
    fields(entry.subarray(2));
    entry.writeUInt32LE(FILE_MODE, 38); entry.writeUInt32LE(offset, 42);
    locals.push(local, path, body);
    central.push(entry, path);
    offset += local.length + path.length + body.length;
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22);
  const count = central.length / 2;
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(count, 8); end.writeUInt16LE(count, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

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
    const time = zip.readUInt16LE(offset + 12), date = zip.readUInt16LE(offset + 14);
    const nameLength = zip.readUInt16LE(offset + 28), extra = zip.readUInt16LE(offset + 30), comment = zip.readUInt16LE(offset + 32);
    const local = zip.readUInt32LE(offset + 42);
    result.set(zip.toString('utf8', offset + 46, offset + 46 + nameLength), { method, size, local, time, date });
    offset += 46 + nameLength + extra + comment;
  }
  return {
    has: name => result.has(name),
    names: () => [...result.keys()],
    stamp: name => ({ time: result.get(name).time, date: result.get(name).date }),
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
