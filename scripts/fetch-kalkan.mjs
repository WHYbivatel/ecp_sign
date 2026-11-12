// Development and CI only: fetches the official NCALayer archive and extracts the two Kalkan jars
// used by the independent checks (tests/kalkan-*.mjs, NCA_KALKAN_JARS in tests/e2e-issuance.mjs).
// The jars are pinned by SHA-256; a repackaged archive is fine, a changed jar fails the run.
// Usage: node scripts/fetch-kalkan.mjs <folder>  → prints the NCA_KALKAN_JARS value.
//        node scripts/fetch-kalkan.mjs <folder> --xml  → also knca_provider_util (the official XMLUtil) and the
//        slf4j API classes it loads; prints NCA_KALKAN_JARS, NCA_BUNDLES and NCA_CORE lines for $GITHUB_ENV
//        (tests/nursign-xml-crosscheck.mjs). NCA_ARCHIVE: a local copy of ncalayer.zip instead of the download.
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { zipEntries as entries } from './lib/zip.mjs';
import { join, resolve, delimiter, dirname } from 'node:path';

const ARCHIVE = 'https://ncl.pki.gov.kz/images/NCALayer/ncalayer.zip';
const JARS = {
  'kalkancrypt-0.7.8.jar': '5588f9ae497f48f4a82ac43491376210b57fee39d33f2c0cf579eb1cedbbc4ab',
  'kalkancrypt_xmldsig-osgi-0.4.jar': '72c273d39254a14865a258846eb46e3c8593180b6c26fd583bc01fb40d56c238'
};
// knca_provider_util logs through slf4j; the API classes come from the NCALayer core in ncalayer.sh, without the
// org/slf4j/impl binding (no logging backend is loaded). Pinned as one digest over the sorted entries.
const XML_JAR = ['knca_provider_util-0.8.8.jar', '613e8ecf564549e5ebcef6df5d0c03a027cbcbe4c19ead02f6d336e47cd9d1c5'];
const SLF4J = '49c4af31f3eacfb32cfe14ff38047f063b2928c23ea52591c650f1c6c220412d';
const xml = process.argv.includes('--xml');
const folder = resolve(process.argv.slice(2).find(arg => !arg.startsWith('--')) || '.kalkan');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const slf4jEntries = core => core.names().filter(name => name.startsWith('org/slf4j/') && name.endsWith('.class') && !name.startsWith('org/slf4j/impl/')).sort();
const slf4jDigest = (names, read) => sha256(names.map(name => `${name}\0${sha256(read(name))}\n`).join(''));

await mkdir(folder, { recursive: true });
const jars = xml ? { ...JARS, [XML_JAR[0]]: XML_JAR[1] } : JARS;
const paths = Object.keys(jars).map(name => join(folder, name));
const coreFolder = join(folder, 'core');
const coreReady = async () => {
  if (!xml) return true;
  const list = join(coreFolder, 'slf4j.list');
  if (!existsSync(list)) return false;
  const names = (await readFile(list, 'utf8')).split('\n').filter(Boolean);
  if (!names.every(name => existsSync(join(coreFolder, name)))) return false;
  const contents = new Map(await Promise.all(names.map(async name => [name, await readFile(join(coreFolder, name))])));
  return slf4jDigest(names, name => contents.get(name)) === SLF4J;
};
const ready = async () => (await Promise.all(paths.map(async (path, i) => existsSync(path) && sha256(await readFile(path)) === Object.values(jars)[i]))).every(Boolean) && await coreReady();
if (!await ready()) {
  let archive;
  if (process.env.NCA_ARCHIVE) archive = await readFile(process.env.NCA_ARCHIVE);
  else {
    const response = await fetch(ARCHIVE, { headers: { 'User-Agent': 'Mozilla/5.0 (Tegin CI)' } });
    if (!response.ok) throw new Error(`${ARCHIVE}: HTTP ${response.status}`);
    archive = Buffer.from(await response.arrayBuffer());
  }
  console.error(`ncalayer.zip ${archive.length} bytes, SHA-256 ${sha256(archive)}`);
  // ncalayer.sh is a shell script with the NCALayer ZIP appended; its offsets start at that ZIP.
  const script = entries(archive).read('ncalayer.sh');
  const bundles = entries(script.subarray(script.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]))));
  for (const [name, hash] of Object.entries(jars)) {
    const jar = bundles.read(`kncabundles/${name}`);
    if (sha256(jar) !== hash) throw new Error(`${name}: SHA-256 ${sha256(jar)} differs from the pinned ${hash}`);
    await writeFile(join(folder, name), jar);
  }
  if (xml) {
    const names = slf4jEntries(bundles);
    const digest = slf4jDigest(names, name => bundles.read(name));
    if (digest !== SLF4J) throw new Error(`slf4j classes: digest ${digest} differs from the pinned ${SLF4J}`);
    for (const name of names) {
      await mkdir(dirname(join(coreFolder, name)), { recursive: true });
      await writeFile(join(coreFolder, name), bundles.read(name));
    }
    await writeFile(join(coreFolder, 'slf4j.list'), names.join('\n') + '\n');
  }
}
if (!await ready()) throw new Error('Kalkan jars failed verification');
const kalkan = paths.slice(0, Object.keys(JARS).length).join(delimiter);
console.log(xml ? `NCA_KALKAN_JARS=${kalkan}\nNCA_BUNDLES=${folder}\nNCA_CORE=${coreFolder}` : kalkan);
