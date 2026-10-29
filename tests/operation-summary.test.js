import test from 'node:test';
import assert from 'node:assert/strict';
import { serviceOperation } from '../extension/lib/operation-summary.js';
const auth = { operation: 'sign', format: 'xml', documents: ['<login><client-type>PORTAL</client-type></login>'], signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'] } };
test('only complete known service requests can replace the default XML preview', () => {
  assert.equal(serviceOperation(auth, 'https://egov.kz').title, 'Вход на сайт');
  const nuc = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><key_settings_digi_sign><uuid>70fea973-f64c-41b5-958f-9da1547c7d15</uuid><date>2026-10-29T16:46:03.956+05:00</date></key_settings_digi_sign>';
  assert.equal(serviceOperation({ ...auth, documents: [nuc] }, 'https://nca.pki.gov.kz').title, 'Подтверждение на сайте НУЦ');
  for (const origin of ['https://example.kz', 'https://egov.kz.example.kz', 'http://egov.kz', 'https://nca.pki.gov.kz']) assert.equal(serviceOperation(auth, origin), null);
  for (const change of [{ signerParams: {} }, { decode: true }, { digested: true }, { format: 'cms' }, { documents: [...auth.documents, '<other/>'] }, { documents: ['<login><client-type>PORTAL</client-type><amount>500</amount></login>'] }, { documents: ['<!DOCTYPE login><login><client-type>PORTAL</client-type></login>'] }, { documents: ['<login purpose="payment"><client-type>PORTAL</client-type></login>'] }]) assert.equal(serviceOperation({ ...auth, ...change }, 'https://egov.kz'), null);
  assert.equal(serviceOperation({ ...auth, documents: [nuc.replace('</key_settings_digi_sign>', '<amount>500</amount></key_settings_digi_sign>')] }, 'https://nca.pki.gov.kz'), null);
});
