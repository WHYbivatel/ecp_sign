import test from 'node:test';
import assert from 'node:assert/strict';
import { connectedOrigins, forgetSites, registerSite, restoreSites, scriptIds } from '../extension/lib/connected-sites.js';

function fakeApi(granted) {
  let scripts = [];
  return {
    get scripts() { return scripts; },
    runtime: { getManifest: () => ({ host_permissions: ['https://*.kz/*', 'http://localhost/*', 'http://127.0.0.1/*', 'http://ocsp.pki.gov.kz/*'] }) },
    permissions: { getAll: async () => ({ origins: ['https://*.kz/*', 'http://localhost/*', 'http://127.0.0.1/*', 'http://ocsp.pki.gov.kz/*', ...granted] }) },
    scripting: {
      getRegisteredContentScripts: async () => structuredClone(scripts),
      registerContentScripts: async items => { for (const item of items) { if (scripts.some(script => script.id === item.id)) throw new Error(`duplicate ${item.id}`); scripts.push(item); } },
      unregisterContentScripts: async ({ ids }) => { scripts = scripts.filter(script => !ids.includes(script.id)); }
    }
  };
}

test('connected sites are the granted single-site HTTPS origins outside the manifest', async () => {
  const api = fakeApi(['https://edo.example.org/*', 'https://*/*', 'https://portal.example.com:8443/*', 'http://plain.example.org/*']);
  assert.deepEqual(await connectedOrigins(api), ['https://edo.example.org/*', 'https://portal.example.com:8443/*']);
});

test('scripts lost on reload are registered again, once, with the ids the popup uses', async () => {
  const api = fakeApi(['https://edo.example.org/*']);
  assert.deepEqual(await restoreSites(api), ['https://edo.example.org/*']);
  const [main, bridge] = await scriptIds('https://edo.example.org/*');
  assert.deepEqual(api.scripts.map(script => script.id), [main, bridge]);
  assert.equal(api.scripts[0].world, 'MAIN'); assert.deepEqual(api.scripts[0].matches, ['https://edo.example.org/*']);
  assert.deepEqual(api.scripts[1].js, ['content/bridge.js']);
  assert.deepEqual(await restoreSites(api), [], 'nothing to do when both scripts are there');
  // One script missing (an interrupted registration): both are replaced.
  await api.scripting.unregisterContentScripts({ ids: [bridge] });
  assert.equal(await registerSite(api, 'https://edo.example.org/*'), true);
  assert.equal(api.scripts.length, 2);
});

test('revoking a site removes only its scripts', async () => {
  const api = fakeApi(['https://edo.example.org/*', 'https://other.example.org/*']);
  await restoreSites(api);
  await forgetSites(api, ['https://edo.example.org/*', 'https://*/*']);
  const other = await scriptIds('https://other.example.org/*');
  assert.deepEqual(api.scripts.map(script => script.id), other);
});
