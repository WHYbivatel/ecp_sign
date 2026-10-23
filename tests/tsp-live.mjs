// Explicit opt-in live test. Sends only the digest of synthetic public data.
import assert from 'node:assert/strict';
import { makeTimestampRequest, verifyTimestampResponse, verifyEmbeddedTimestamp, TSA_URL } from '../extension/crypto/timestamp.js';
const signature = new TextEncoder().encode('Tegin public interoperability test; no user documents or keys.');
const request = await makeTimestampRequest(signature);
const response = await fetch(TSA_URL, { method: 'POST', headers: { 'Content-Type': 'application/timestamp-query', Accept: 'application/timestamp-reply' },
  credentials: 'omit', redirect: 'error', body: request.body, signal: AbortSignal.timeout(20000) });
if (!response.ok) throw new Error(`TSP HTTP ${response.status}`);
const raw = new Uint8Array(await response.arrayBuffer());
const token = await verifyTimestampResponse(raw, request);
assert.equal((await verifyEmbeddedTimestamp(token.token, signature)).time, token.time);
const wrong = request.imprint.slice(); wrong[0] ^= 1;
await assert.rejects(verifyTimestampResponse(raw, { ...request, imprint: wrong }), /другой подписи/);
await assert.rejects(verifyTimestampResponse(raw, { ...request, policy: '1.2.3' }), /политике/);
await assert.rejects(verifyTimestampResponse(raw, { ...request, nonce: new Uint8Array(16) }), /nonce/);
await assert.rejects(verifyTimestampResponse(raw, request, { anchors: [] }), /Сертификат/);
await assert.rejects(verifyTimestampResponse(raw, request, { now: Date.now() + 3600000 }), /Время/);
console.log(JSON.stringify({ verified: true, time: token.time, authority: token.authority, revocation: token.revocation }));
