import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
const source = new URL('../extension/', import.meta.url);

test('extension uses no native host, no externally callable API, and allows only fixed NUC timestamp and revocation services in extension pages', async () => {
  const manifest = JSON.parse(await readFile(new URL('manifest.json', source), 'utf8'));
  assert.ok(!manifest.permissions.includes('nativeMessaging'));
  assert.equal(manifest.externally_connectable, undefined);
  assert.equal(manifest.web_accessible_resources, undefined);
  assert.deepEqual(manifest.optional_host_permissions, ['https://*/*']);
  assert.match(manifest.content_security_policy.extension_pages, /connect-src http:\/\/tsp\.pki\.gov\.kz http:\/\/ocsp\.pki\.gov\.kz https:\/\/crl\.pki\.gov\.kz https:\/\/crl1\.pki\.gov\.kz https:\/\/crl\.root\.gov\.kz;/);
  for (const file of await readdir(new URL('crypto/', source))) {
    if (!file.endsWith('.js')) continue;
    const text = await readFile(new URL(`crypto/${file}`, source), 'utf8');
    if (/\bfetch\b/.test(text)) assert.ok(['timestamp.js', 'revocation.js'].includes(file), `${file} must not use the network`);
  }
  assert.match(manifest.content_security_policy.extension_pages, /worker-src 'self'/);
  assert.doesNotMatch(manifest.content_security_policy.extension_pages, /unsafe-eval|unsafe-inline/);
});

test('keys are confined to the signing worker and never stored or sent over runtime messages', async () => {
  const background = await readFile(new URL('background/background.js', source), 'utf8');
  assert.doesNotMatch(background, /storage\.local\.(set|remove|clear)|password|privateKey|container/);
  assert.ok([...background.matchAll(/storage\.local\.get\(([^)]*)\)/g)].every(match => match[1] === "'moduleSettings'"));
  const worker = await readFile(new URL('crypto/worker.js', source), 'utf8');
  assert.doesNotMatch(worker, /chrome\.|browser\.|\bfetch\(|XMLHttpRequest|WebSocket|localStorage|indexedDB/);
  const approval = await readFile(new URL('signing/approve.js', source), 'utf8');
  assert.doesNotMatch(approval, /storage\.local|localStorage|indexedDB|\bfetch\(/);
  assert.match(approval, /worker\.postMessage\(\{ kind: 'open', container, password, request \}, \[container\]\)/);
  assert.match(approval, /worker\?\.terminate\(\)/);
});
