// Sites outside .kz that the user connected: the browser keeps the granted origin, the adapter scripts are
// registered per origin. Chromium drops registered scripts when an unpacked extension is loaded again (update,
// reload, restart of a browser that loads it from a folder), so they are rebuilt from the granted origins.
const SITE = /^https:\/\/[^*/]+\/\*$/;

export async function scriptIds(origin) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(origin)));
  const id = [...digest.slice(0, 12)].map(byte => byte.toString(16).padStart(2, '0')).join('');
  return [`main-${id}`, `bridge-${id}`];
}

export async function registerSite(api, origin) {
  const [main, bridge] = await scriptIds(origin);
  const existing = (await api.scripting.getRegisteredContentScripts()).filter(script => [main, bridge].includes(script.id));
  if (existing.length === 2) return false;
  if (existing.length) await api.scripting.unregisterContentScripts({ ids: existing.map(script => script.id) });
  await api.scripting.registerContentScripts([
    { id: main, matches: [origin], js: ['content/inject.js'], world: 'MAIN', runAt: 'document_start', allFrames: true },
    { id: bridge, matches: [origin], js: ['content/bridge.js'], runAt: 'document_start', allFrames: true }
  ]);
  return true;
}

export async function connectedOrigins(api) {
  const declared = new Set(api.runtime.getManifest().host_permissions || []);
  const { origins = [] } = await api.permissions.getAll();
  return origins.filter(origin => SITE.test(origin) && !declared.has(origin));
}

export async function restoreSites(api) {
  const restored = [];
  for (const origin of await connectedOrigins(api)) if (await registerSite(api, origin)) restored.push(origin);
  return restored;
}

export async function forgetSites(api, origins) {
  const ids = (await Promise.all(origins.filter(origin => SITE.test(origin)).map(scriptIds))).flat();
  const registered = new Set((await api.scripting.getRegisteredContentScripts()).map(script => script.id));
  const stale = ids.filter(id => registered.has(id));
  if (stale.length) await api.scripting.unregisterContentScripts({ ids: stale });
}
