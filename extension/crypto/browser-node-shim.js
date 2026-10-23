// Only canonicalization is bundled from xml-crypto. Node-only crypto operations
// must never silently run through a browser polyfill.
export const deprecate = callback => callback;
export function createPrivateKey() { throw new Error('Node crypto is unavailable'); }
export class X509Certificate { constructor() { throw new Error('Node crypto is unavailable'); } }
