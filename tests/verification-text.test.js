import test from 'node:test';
import assert from 'node:assert/strict';
import { longTermHarness } from './helpers/long-term.js';
import { signLongTerm, verifyLongTerm, embeddedValidationData, longTermReport } from '../extension/crypto/cades-lt.js';
import { signCms } from '../extension/crypto/cms.js';
import { longTermText, verificationText, HISTORICAL_NOT_COMPUTED } from '../extension/lib/verification-text.js';

const h = await longTermHarness();
test.after(() => h.destroy());
const data = new TextEncoder().encode('Tegin synthetic verification text');
const sign = level => signLongTerm(h.signer, data, { level, signerPath: h.signerPath, evidence: h.evidence, requester: h.requester });
const good = { state: 'good', checkedAt: Date.now(), certificates: [] };
const notRequested = { state: 'not-checked', reason: 'not-requested', certificates: [] };
// Wording that would present a status at the time of a stamp as established.
const CONFIRMED = /(не отозван|действителен|был действителен|подтвержд[её]н)[^.\n]*(на момент|в момент)|(на момент|в момент)[^.\n]*(не отозван|подтвержд[её]н|действителен)|исторически/i;
const SHA256 = '2.16.840.1.101.3.4.2.1';

const verifyResult = (longTerm, history = { basis: 'timestamp', relation: 'not-revoked-now' }) => ({
  signers: [{ name: 'Синтетический подписант', algorithm: 'RSA', trust: { trusted: true, revocation: good }, history }],
  timestamps: [{ kind: 'signature', time: Date.now(), revocation: good }, ...(longTerm?.archives || []).map(archive => ({ kind: 'archive', time: archive.time, revocation: archive.revocation }))],
  longTerm
});

test('CAdES-LTA report lists each verified archive time-stamp with its coverage and hash', async () => {
  const { cms, stamp, archive } = await sign('lta');
  const verified = await verifyLongTerm(cms, { anchors: h.anchors });
  const report = longTermReport(verified, { signatureTimestamp: stamp, archiveRevocations: [good] });
  assert.equal(report.level, 'LTA');
  assert.deepEqual(report.embedded, embeddedValidationData(cms));
  assert.deepEqual(report.embedded, { certificates: 4, crls: 1, ocsp: 2 });
  assert.equal(report.archives.length, 1);
  assert.deepEqual({ ...report.archives[0], time: undefined }, { index: 1, time: undefined, authority: verified.archives[0].authority, hashAlgorithm: SHA256,
    covers: { certificates: 4, revocation: 3, attributes: 1 }, revocation: good });
  assert.equal(report.archives[0].time, archive.time);
  assert.deepEqual(report.historical, { computed: false });
  assert.equal(report.renewal, false);

  const text = longTermText(report);
  assert.match(text, /^CAdES-LTA: в подпись встроены сертификаты \(4\), ответы OCSP \(2\) и списки отзыва \(1\)\./);
  assert.match(text, /Архивная метка 1 из 1: .+ · SHA-256/);
  assert.match(text, /сертификаты \(4\), данные отзыва \(3\) и атрибуты \(1\)/);
  assert.match(text, /Сертификат службы меток сейчас: не отозван по актуальным данным/);
  assert.ok(text.includes(HISTORICAL_NOT_COMPUTED));
  assert.match(text, /Продлить архивную метку в Tegin пока нельзя\./);
  assert.doesNotMatch(text, CONFIRMED);
});

test('CAdES-LT report has no archive time-stamps and still says the historical status was not computed', async () => {
  const { cms, stamp } = await sign('lt');
  const report = longTermReport(await verifyLongTerm(cms, { anchors: h.anchors }), { signatureTimestamp: stamp });
  assert.equal(report.level, 'LT');
  assert.deepEqual(report.archives, []);
  const text = longTermText(report);
  assert.match(text, /^CAdES-LT: /);
  assert.match(text, /Архивных меток нет\./);
  assert.ok(text.includes(HISTORICAL_NOT_COMPUTED));
  assert.doesNotMatch(text, /Продлить/);
});

test('a CMS without long-term data gets no long-term block', async () => {
  const cms = await signCms(h.signer, data, { cades: true });
  assert.deepEqual(embeddedValidationData(cms), { certificates: 1, crls: 0, ocsp: 0 });
  assert.equal(longTermReport({ ...embeddedValidationData(cms), archives: [] }, { signatureTimestamp: null }).level, null);
  assert.equal(longTermText(null), '');
  assert.equal(longTermText({ level: null }), '');
});

test('verify screen never shows a confirmed historical revocation status when it was not computed', async () => {
  const { cms, stamp } = await sign('lta');
  const report = longTermReport(await verifyLongTerm(cms, { anchors: h.anchors }), { signatureTimestamp: stamp, archiveRevocations: [notRequested] });
  // Fields a future producer might add by mistake must not turn into a confirmation.
  const misleading = [
    report,
    { ...report, historical: { computed: false, state: 'good' } },
    { ...report, historical: { computed: false, state: 'good', at: Date.now() } },
    { ...report, historical: undefined },
    { ...report, archives: report.archives.map(archive => ({ ...archive, historical: { state: 'good' } })) }
  ];
  for (const longTerm of misleading) {
    for (const history of [{ basis: 'timestamp', relation: 'not-revoked-now' }, { basis: 'timestamp', relation: 'not-revoked-at-timestamp' }, { basis: 'none', relation: 'undetermined' }]) {
      for (const revocationRequested of [true, false]) {
        const { details, title } = verificationText(verifyResult(longTerm, history), { revocationRequested });
        assert.ok(details.includes(HISTORICAL_NOT_COMPUTED), details);
        assert.doesNotMatch(details, CONFIRMED, details);
        assert.equal(title, 'Подпись верна');
      }
    }
  }
  const { details } = verificationText(verifyResult(report), { revocationRequested: false });
  assert.equal(details.match(/Архивная метка/g).length, 1, 'archive stamps are listed once, inside the long-term block');
  assert.match(details, /Сертификат службы меток сейчас: не проверялся/);
});

test('revocation relative to a time-stamp keeps its existing wording', () => {
  const revokedAt = Date.UTC(2026, 0, 2), stampedAt = Date.UTC(2026, 0, 1);
  const revoked = { state: 'revoked', certificates: [{ state: 'revoked', role: 'leaf', revocationTime: revokedAt }] };
  const result = verifyResult(null, { basis: 'timestamp', relation: 'revoked-after-timestamp', revocationTime: revokedAt, timestamp: stampedAt });
  result.signers[0].trust.revocation = revoked;
  const text = verificationText(result, { revocationRequested: true });
  assert.equal(text.title, 'Подпись соответствует документу');
  assert.ok(text.revoked && text.warning);
  assert.match(text.details, /позже метки времени .+: метка подтверждает, что подпись существовала до отзыва\./);
  assert.match(text.details, /Текущий статус отзыва сам по себе не определяет действительность подписи в прошлом\./);
  assert.doesNotMatch(text.details, /CAdES-/);
});
