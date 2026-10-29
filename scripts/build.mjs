import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
const source = new URL('../extension/', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('manifest.json', source), 'utf8'));
const shim = fileURLToPath(new URL('crypto/browser-node-shim.js', source));
for (const target of ['chromium', 'firefox']) {
  const destination = new URL(`../dist/${target}/`, import.meta.url);
  await rm(destination, { recursive: true, force: true });
  await mkdir(destination, { recursive: true });
  for (const asset of ['index.html', 'styles.css', 'theme.css', 'assets', 'modules/index.html', 'modules/modules.css', 'signing/approve.html', 'signing/approve.css', 'content/inject.js', 'content/bridge.js']) {
    await cp(new URL(asset, source), new URL(asset, destination), { recursive: true });
  }
  const output = structuredClone(manifest);
  if (target === 'firefox') {
    delete output.minimum_chrome_version;
    output.background = { scripts: ['background.js'] };
    output.browser_specific_settings = { gecko: { id: 'ncabrowser@local.invalid', strict_min_version: '140.0', data_collection_permissions: { required: ['none'] } } };
  }
  await writeFile(new URL('manifest.json', destination), JSON.stringify(output, null, 2) + '\n');
  await build({
    entryPoints: {
      'modules/modules': fileURLToPath(new URL('modules/modules.js', source)),
      'popup': fileURLToPath(new URL('popup/popup.js', source)),
      'background': fileURLToPath(new URL('background/background.js', source)),
      'signing/approve': fileURLToPath(new URL('signing/approve.js', source)),
      'crypto/worker': fileURLToPath(new URL('crypto/worker.js', source))
    },
    outdir: fileURLToPath(destination), bundle: true, platform: 'browser', format: 'iife', target: 'chrome111',
    minify: true, legalComments: 'eof', metafile: true,
    plugins: [{ name: 'xml-canonicalization-only', setup(plugin) {
      plugin.onResolve({ filter: /^(crypto|util)$/ }, args => {
        if (args.importer.includes('xml-crypto')) return { path: shim };
      });
    } }]
  });
  await cp(new URL('../INSTALL.md', import.meta.url), new URL('INSTALL.md', destination));
  const licenses = new URL('licenses/', destination);
  await mkdir(licenses, { recursive: true });
  await cp(new URL('vendor/gost/LICENSE.txt', source), new URL('gost-apache-2.0.txt', licenses));
  await cp(new URL('../THIRD_PARTY_NOTICES.md', import.meta.url), new URL('THIRD_PARTY_NOTICES.md', destination));
  for (const [name, file] of [['node-forge', 'LICENSE'], ['@xmldom/xmldom', 'LICENSE'], ['xml-crypto', 'LICENSE'], ['xpath', 'LICENSE'], ['@xmldom/is-dom-node', 'LICENSE.md']]) {
    await cp(new URL(`../node_modules/${name}/${file}`, import.meta.url), new URL(`${name.replaceAll('/', '-')}.txt`, licenses));
  }
}
console.log('Built local signing extensions: dist/chromium and dist/firefox.');
