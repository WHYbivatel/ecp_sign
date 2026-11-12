// Checks the packaged archives themselves (dist/tegin-<target>-<version>.zip from `npm run package`), not the
// unpacked dist/ folders the E2E tests load: version, manifest, every referenced file present, no test build,
// no source maps, keys or development files, no remote scripts, contents byte-identical to dist/<target>, and
// SHA-256 equal to dist/checksums.json; packing again gives the same bytes; the AMO source archive is the committed
// tree without keys or build output. With --smoke the Chromium archive is unpacked into a temporary folder,
// loaded into Chromium, and every extension page must open without a script error or CSP violation.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname, posix } from 'node:path';
import { execFileSync } from 'node:child_process';
import { ZIP_DATE, filesIn, zipEntries, zipFolder } from './lib/zip.mjs';

const { version } = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const dist = resolve('dist');
const checksums = JSON.parse(await readFile(join(dist, 'checksums.json'), 'utf8'));
const FORBIDDEN = [/\.map$/, /(^|\/)\.[^/]+$/, /(^|\/)(node_modules|tests?|\.git)\//, /\.(p12|pfx|pem|key|der|crt|cer|p7s|env|log)$/i, /\.test\.js$/, /(^|\/)package(-lock)?\.json$/];
const PAGES = ['index.html', 'modules/index.html', 'keys/index.html', 'password/index.html', 'signing/approve.html', 'signing/issue.html'];
const MAX_BYTES = 4 * 1024 * 1024;

function referenced(manifest) {
  const files = new Set(['manifest.json', ...Object.values(manifest.icons || {}), ...Object.values(manifest.action?.default_icon || {})]);
  if (manifest.background?.service_worker) files.add(manifest.background.service_worker);
  for (const script of manifest.background?.scripts || []) files.add(script);
  for (const content of manifest.content_scripts || []) for (const file of [...(content.js || []), ...(content.css || [])]) files.add(file);
  for (const resource of manifest.web_accessible_resources || []) for (const file of resource.resources || []) files.add(file);
  if (manifest.action?.default_popup) files.add(manifest.action.default_popup);
  if (manifest.options_ui?.page) files.add(manifest.options_ui.page);
  return files;
}

const results = {};
for (const target of ['chromium', 'firefox']) {
  const name = `tegin-${target}-${version}.zip`;
  const bytes = await readFile(join(dist, name));
  assert.ok(bytes.length < MAX_BYTES, `${name}: ${bytes.length} bytes`);
  assert.equal(sha256(bytes), checksums[name], `${name}: SHA-256 differs from dist/checksums.json`);
  const zip = zipEntries(bytes);
  const names = zip.names().filter(entry => !entry.endsWith('/'));
  for (const entry of names) for (const pattern of FORBIDDEN) assert.ok(!pattern.test(entry), `${name}: ${entry} must not be packaged`);

  const manifest = JSON.parse(zip.read('manifest.json').toString('utf8'));
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.version, version, `${name}: manifest version differs from package.json`);
  assert.doesNotMatch(manifest.name, /test/i, `${name}: a test build was packaged`);
  const csp = Object.fromEntries(manifest.content_security_policy.extension_pages.split(';').map(part => part.trim().split(/\s+/)).map(([key, ...values]) => [key, values.join(' ')]));
  assert.equal(csp['script-src'], "'self'", `${name}: script-src`); assert.equal(csp['worker-src'], "'self'", `${name}: worker-src`);
  assert.equal(csp['object-src'], "'none'", `${name}: object-src`);
  if (target === 'chromium') {
    assert.equal(manifest.browser_specific_settings, undefined);
    assert.ok(manifest.background.service_worker);
  } else {
    assert.ok(manifest.browser_specific_settings?.gecko?.id, `${name}: gecko id`);
    assert.deepEqual(manifest.background.scripts, ['background.js']);
  }
  for (const file of referenced(manifest)) assert.ok(zip.has(file), `${name}: manifest references missing ${file}`);

  for (const page of PAGES) {
    assert.ok(zip.has(page), `${name}: ${page} missing`);
    const html = zip.read(page).toString('utf8');
    for (const [, attribute, value] of html.matchAll(/\b(src|href)="([^"]+)"/g)) {
      if (attribute === 'src') assert.doesNotMatch(value, /^(https?:)?\/\//, `${name}: ${page} loads a remote resource ${value}`);
      if (/^(https?:|mailto:|#)/.test(value)) continue;
      const file = posix.normalize(posix.join(posix.dirname(page), value.split(/[?#]/)[0]));
      assert.ok(zip.has(file), `${name}: ${page} references missing ${file}`);
    }
  }
  for (const entry of names.filter(file => file.endsWith('.js'))) {
    const code = zip.read(entry).toString('utf8');
    assert.doesNotMatch(code, /\(test (revocation|issuance) build\)|__TEGIN_TEST_/, `${name}: ${entry} carries test settings`);
    assert.doesNotMatch(code, /importScripts\(\s*["']https?:|import\(\s*["']https?:/, `${name}: ${entry} loads remote code`);
  }

  const built = await filesIn(join(dist, target));
  assert.deepEqual([...names].sort(), built, `${name}: file list differs from dist/${target}`);
  for (const entry of names) assert.ok(zip.read(entry).equals(await readFile(join(dist, target, entry))), `${name}: ${entry} differs from dist/${target}`);
  assert.deepEqual(names, [...names].sort(), `${name}: entries are not in sorted order`);
  for (const entry of names) assert.deepEqual(zip.stamp(entry), { time: 0, date: ZIP_DATE }, `${name}: ${entry} carries a file time`);
  assert.ok((await zipFolder(join(dist, target))).equals(bytes), `${name}: packing dist/${target} again gives different bytes`);
  results[target] = { name, bytes: bytes.length, files: names.length, sha256: checksums[name] };
  console.log(`PASS: ${name}: ${names.length} files, ${bytes.length} bytes, SHA-256 ${checksums[name].slice(0, 16)}…; manifest ${manifest.version}, every referenced file present, no test settings, development files or remote scripts, identical to dist/${target}; sorted entries with a fixed time, packing again gives the same bytes`);
}

// Source archive for AMO review: the committed tree of HEAD, reproducible with git archive, without keys or build output.
const sourceName = `tegin-source-${version}.zip`;
const sourceBytes = await readFile(join(dist, sourceName));
assert.equal(sha256(sourceBytes), checksums[sourceName], `${sourceName}: SHA-256 differs from dist/checksums.json`);
const sourcePrefix = `tegin-source-${version}/`;
const sourceFiles = zipEntries(sourceBytes).names().filter(entry => !entry.endsWith('/'));
for (const entry of sourceFiles) {
  assert.ok(entry.startsWith(sourcePrefix), `${sourceName}: ${entry} outside ${sourcePrefix}`);
  const path = entry.slice(sourcePrefix.length);
  assert.doesNotMatch(path, /\.(p12|pfx|env)$|(^|\/)\.env(\.|$)|^dist\/|(^|\/)node_modules\//i, `${sourceName}: ${path} must not be in the source archive`);
}
for (const required of ['package.json', 'package-lock.json', 'scripts/build.mjs', 'extension/manifest.json', 'README.md']) assert.ok(sourceFiles.includes(sourcePrefix + required), `${sourceName}: ${required} missing`);
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const again = execFileSync('git', ['archive', '--format=zip', `--prefix=${sourcePrefix}`, commit], { maxBuffer: 64 * 1024 * 1024 });
assert.ok(again.equals(sourceBytes), `${sourceName}: differs from git archive of ${commit.slice(0, 12)}`);
console.log(`PASS: ${sourceName}: ${sourceFiles.length} files of commit ${commit.slice(0, 12)}, SHA-256 ${checksums[sourceName].slice(0, 16)}…; no .p12/.pfx/.env, dist/ or node_modules/; git archive gives the same bytes`);

if (process.argv.includes('--smoke')) {
  const { launchExtension, extensionWorker } = await import('../tests/helpers/browser.js');
  const folder = await mkdtemp(join(tmpdir(), 'tegin-package-'));
  try {
    const extension = join(folder, 'chromium');
    const zip = zipEntries(await readFile(join(dist, results.chromium.name)));
    for (const entry of zip.names().filter(file => !file.endsWith('/'))) {
      await mkdir(dirname(join(extension, entry)), { recursive: true });
      await writeFile(join(extension, entry), zip.read(entry));
    }
    const context = await launchExtension(join(folder, 'profile'), extension);
    try {
      const worker = await extensionWorker(context);
      const id = new URL(worker.url()).host;
      assert.equal(await worker.evaluate(() => chrome.runtime.getManifest().version), version);
      for (const page of PAGES) {
        const tab = await context.newPage();
        const problems = [];
        tab.on('pageerror', error => problems.push(error.message));
        tab.on('console', message => { if (message.type() === 'error') problems.push(message.text()); });
        await tab.goto(`chrome-extension://${id}/${page}`, { waitUntil: 'load' });
        await tab.waitForTimeout(300);
        assert.deepEqual(problems, [], `${page}: errors in the packaged build`);
        await tab.close();
      }
      console.log(`PASS: the packaged Chromium archive, unpacked, loads in Chromium: service worker ${version} runs, ${PAGES.length} extension pages open without script errors or CSP violations`);
    } finally {
      await context.close();
    }
  } finally {
    await rm(folder, { recursive: true, force: true });
  }
}
