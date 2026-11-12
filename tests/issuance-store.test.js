import test from 'node:test';
import assert from 'node:assert/strict';
import { listRecords, removeRecord, STORE } from '../extension/lib/issuance-store.js';

function fakeApi(initial) {
  const data = structuredClone(initial), writes = [];
  const local = {
    async get(key) { return key === null ? structuredClone(data) : { [key]: structuredClone(data[key]) }; },
    async set(items) { writes.push(Object.keys(items)); Object.assign(data, structuredClone(items)); },
    async remove(keys) { for (const key of [keys].flat()) delete data[key]; }
  };
  return { api: { storage: { local } }, data, writes };
}
const identity = 'a'.repeat(64);
const record = (id, extra = {}) => ({ v: 1, id, origin: 'https://did.pki.gov.kz', created: '2026-11-12T10:00:00.000Z', algorithms: ['ГОСТ 34.10-2015 · 512 бит'],
  identities: [identity], status: 'requested', sealed: { version: 1, cipher: 'AES-256-GCM', data: 'c2VhbGVk' }, ...extra });
const ID1 = '11111111-1111-4111-8111-111111111111', ID2 = '22222222-2222-4222-8222-222222222222';

test('a stored subject CN is dropped from the record itself; keys, identities and status stay', async () => {
  const legacy = record(ID1, { holder: 'ТЕСТОВ ТЕСТ', status: 'installed', installed: '2026-11-12T11:00:00.000Z' });
  const { api, data, writes } = fakeApi({ [STORE + ID1]: legacy, [STORE + ID2]: record(ID2), moduleSettings: { x: 1 } });
  const listed = await listRecords(api);
  assert.deepEqual(listed.map(item => item.slot).sort(), [ID1, ID2]);
  assert.equal('holder' in data[STORE + ID1], false);
  const { holder, ...rest } = legacy;
  assert.equal(holder, 'ТЕСТОВ ТЕСТ');
  assert.deepEqual(data[STORE + ID1], rest);
  assert.deepEqual(writes, [[STORE + ID1]], 'only the record with the retired field is rewritten');
  assert.deepEqual(data.moduleSettings, { x: 1 });
  assert.ok(!JSON.stringify(data).includes('ТЕСТОВ'));
});

test('only valid issuance records are listed; a backup slot keeps its own key', async () => {
  const { api } = fakeApi({ [STORE + ID1]: record(ID1), [`${STORE}${ID1}~0a1b2c3d`]: record(ID1, { sealed: { data: 'b3RoZXI=' } }), [STORE + 'broken']: { v: 1 }, other: record(ID2) });
  assert.deepEqual((await listRecords(api)).map(item => item.slot).sort(), [ID1, `${ID1}~0a1b2c3d`]);
});

test('removing one slot leaves every other record untouched', async () => {
  const initial = { [STORE + ID1]: record(ID1), [`${STORE}${ID1}~0a1b2c3d`]: record(ID1, { sealed: { data: 'b3RoZXI=' } }), [STORE + ID2]: record(ID2) };
  const { api, data } = fakeApi(initial);
  await removeRecord(api, ID1);
  assert.deepEqual(Object.keys(data).sort(), [`${STORE}${ID1}~0a1b2c3d`, STORE + ID2].sort());
  assert.deepEqual(data[STORE + ID2], initial[STORE + ID2]);
});
