// Application keys for NUC requests in storage.local, one record per slot: the encrypted key,
// public key identities and labels. A slot is the record id, or id~hash for a differing backup.
export const STORE = 'issuance:';
// Earlier records also kept the subject CN. Nothing reads it, so it is dropped.
const RETIRED = ['holder'];

export const validRecord = value => value && value.v === 1 && /^[0-9a-f-]{36}$/.test(value.id) && Array.isArray(value.identities) && value.identities.length >= 1 && value.identities.length <= 4 &&
  value.identities.every(item => typeof item === 'string' && /^[0-9a-f]{64}$/.test(item)) && value.sealed && typeof value.sealed === 'object' && typeof value.sealed.data === 'string';

export const withoutRetired = record => Object.fromEntries(Object.entries(record).filter(([field]) => !RETIRED.includes(field)));

export async function listRecords(api) {
  const result = [];
  for (const [key, value] of Object.entries(await api.storage.local.get(null))) {
    if (!key.startsWith(STORE) || !validRecord(value)) continue;
    let record = value;
    if (RETIRED.some(field => Object.hasOwn(value, field))) {
      record = withoutRetired(value);
      await api.storage.local.set({ [key]: record });
    }
    result.push({ ...record, slot: key.slice(STORE.length) });
  }
  return result;
}

export const removeRecord = (api, slot) => api.storage.local.remove(STORE + slot);

// The backup file restores installation on any browser, so it carries the record as it was right after the request.
export const backupName = record => `tegin-nuc-${String(record.created).slice(0, 10)}-${record.id.slice(0, 8)}.tegin-request.json`;
export const backupJson = ({ v, id, origin, created, algorithms, identities, sealed }) =>
  JSON.stringify({ v, id, origin, created, algorithms, identities, status: 'requested', sealed });
