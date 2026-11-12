// Development and CI only: fetches the official NCALayer archive and extracts the two Kalkan jars
// used by the independent checks (tests/kalkan-*.mjs, NCA_KALKAN_JARS in tests/e2e-issuance.mjs).
// The jars are pinned by SHA-256; a repackaged archive is fine, a changed jar fails the run.
// Usage: node scripts/fetch-kalkan.mjs <folder>  → prints the NCA_KALKAN_JARS value.
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { inflateRawSync } from 'node:zlib';
import { join, resolve, delimiter } from 'node:path';

const ARCHIVE = 'https://ncl.pki.gov.kz/images/NCALayer/ncalayer.zip';
const JARS = {
  'kalkancrypt-0.7.8.jar': '5588f9ae497f48f4a82ac43491376210b57fee39d33f2c0cf579eb1cedbbc4ab',
  'kalkancrypt_xmldsig-osgi-0.4.jar': '72c273d39254a14865a258846eb46e3c8593180b6c26fd583bc01fb40d56c238'
};
const folder = resolve(process.argv[2] || '.kalkan');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

// Minimal ZIP reader: central directory, stored and deflated entries.
function entries(zip) {
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

await mkdir(folder, { recursive: true });
const paths = Object.keys(JARS).map(name => join(folder, name));
const ready = async () => (await Promise.all(paths.map(async (path, i) => existsSync(path) && sha256(await readFile(path)) === Object.values(JARS)[i]))).every(Boolean);
if (!await ready()) {
  const response = await fetch(ARCHIVE, { headers: { 'User-Agent': 'Mozilla/5.0 (Tegin CI)' } });
  if (!response.ok) throw new Error(`${ARCHIVE}: HTTP ${response.status}`);
  const archive = Buffer.from(await response.arrayBuffer());
  console.error(`ncalayer.zip ${archive.length} bytes, SHA-256 ${sha256(archive)}`);
  // ncalayer.sh is a shell script with the NCALayer ZIP appended; its offsets start at that ZIP.
  const script = entries(archive).read('ncalayer.sh');
  const bundles = entries(script.subarray(script.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]))));
  for (const [name, hash] of Object.entries(JARS)) {
    const jar = bundles.read(`kncabundles/${name}`);
    if (sha256(jar) !== hash) throw new Error(`${name}: SHA-256 ${sha256(jar)} differs from the pinned ${hash}`);
    await writeFile(join(folder, name), jar);
  }
}
if (!await ready()) throw new Error('Kalkan jars failed verification');
console.log(paths.join(delimiter));
