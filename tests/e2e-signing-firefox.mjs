// Local signing window of the regular Firefox build (dist/firefox) over WebDriver BiDi: CMS with the document
// inside and detached, XMLDSig and PAdES-B-B with a synthetic RSA key, then the verify screen. Every result is
// checked outside the extension: OpenSSL for CMS and the PAdES CMS over its ByteRange; the official Kalkan
// XMLUtil.verifyXmlSignature for XML (NCA_BUNDLES from scripts/fetch-kalkan.mjs --xml, otherwise xml-crypto); EU DSS and pyHanko for the PDF
// when DSS_VALIDATOR is set. Synthetic key and documents only.
import { arch, platform, tmpdir } from 'node:os';
import { mkdtempSync, mkdirSync, readdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { delimiter, join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { PDFDocument } from 'pdf-lib';
import { SignedXml } from 'xml-crypto';
import { DOMParser } from '@xmldom/xmldom';
import { rsaFixture, PASSWORD } from './helpers/fixtures.js';
import { launchFirefox, pause } from './helpers/firefox.js';
import { longTermHarness } from './helpers/long-term.js';
import { signLongTerm } from '../extension/crypto/cades-lt.js';
import { requestTimestamp, TSA_PROFILES } from '../extension/crypto/timestamp.js';
import { RevocationChecker, memoryStore } from '../extension/crypto/revocation.js';

const folder = mkdtempSync(join(tmpdir(), 'tegin-signing-firefox-'));
execFileSync('node', ['scripts/build.mjs'], { stdio: 'pipe' });
const key = rsaFixture({ keyUsage: 'digitalSignature,nonRepudiation' });
const file = name => join(folder, name);
writeFileSync(file('cert.pem'), key.certificate);
const text = Buffer.from('Синтетический документ Tegin для Firefox');
const xml = '<?xml version="1.0" encoding="UTF-8"?>\n<order xmlns="urn:tegin:synthetic"><number>FF-1</number><title>Синтетический заказ</title></order>\n';
const pdfSource = await PDFDocument.create(); pdfSource.addPage().drawText('Tegin synthetic PDF for Firefox');
const pdf = Buffer.from(await pdfSource.save({ useObjectStreams: false }));
const PYTHON = platform() === 'win32' ? 'python' : 'python3';

const site = createServer((req, res) => { res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end('<!doctype html><title>Tegin Firefox fixture</title>'); });
await new Promise(done => site.listen(0, '127.0.0.1', done));
const ff = await launchFirefox(folder, resolve('dist/firefox'));
const { browser } = ff;
const visible = (page, selector, timeout = 60000) => page.waitForSelector(selector, { visible: true, timeout });
const textOf = (page, selector) => page.$eval(selector, node => node.textContent);
async function waitText(page, selector, pattern, timeout = 60000) {
  for (let i = 0; i < timeout / 100; i++) { if (pattern.test(await textOf(page, selector).catch(() => ''))) return; await pause(100); }
  throw new Error(`${selector}: no ${pattern} in "${await textOf(page, selector).catch(() => '')}"; page errors: ${JSON.stringify(ff.errors)}`);
}

try {
  console.log(`ENV: firefox on ${platform()} ${arch()}: ${await browser.version()}`);
  mkdirSync(file('downloads'), { recursive: true });
  // A site call opens an extension window; it opens the local signing window in a tab and is cancelled.
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${site.address().port}/`);
  await page.waitForFunction(() => window.WebSocket.__ncaBrowserAdapter === true);
  await page.evaluate(() => new Promise((done, fail) => { window.socket = new WebSocket('wss://127.0.0.1:13579'); window.socket.onopen = done; window.socket.onerror = fail; }));
  let known = new Set(await browser.pages());
  const pending = page.evaluate(() => new Promise(done => { window.socket.onmessage = event => done(JSON.parse(event.data));
    window.socket.send(JSON.stringify({ module: 'kz.gov.pki.knca.basics', method: 'sign', args: { allowedStorages: ['PKCS12'], format: 'xml', data: '<a/>', signingParams: {}, signerParams: { extKeyUsageOids: [] } } })); }));
  const approval = await ff.extensionPage('signing/approve.html#', known);
  known = new Set(await browser.pages());
  await approval.evaluate(() => browser.tabs.create({ url: browser.runtime.getURL('signing/approve.html'), active: true }));
  const tool = await ff.extensionPage('signing/approve.html', known);
  await approval.click('#cancel');
  assert.deepEqual(await pending, { status: true, body: {} });

  // Status and result texts stay in the DOM while hidden, so each step waits for the result screen itself.
  const result = async pattern => {
    await visible(tool, '#result-screen', 90000).catch(async error => { throw new Error(`no result screen; status "${await textOf(tool, '#status')}"; page errors: ${JSON.stringify(ff.errors)}`, { cause: error }); });
    await waitText(tool, '#result-title', pattern);
  };
  const again = async () => {
    await tool.click('#again'); await tool.waitForSelector('#result-screen', { hidden: true });
    await tool.$eval('#status', node => { node.textContent = ''; });
  };
  const sign = async (format, name, bytes, type) => {
    await tool.$eval('#advanced-settings', node => { node.open = true; });
    await tool.select('#format', format);
    await ff.choose(tool, '#document', bytes, name, type);
    await waitText(tool, '#status', format === 'pades' ? /PDF готов к подписи/ : /Документ загружен/);
    await ff.choose(tool, '#key-file', key.container, 'synthetic.p12', 'application/x-pkcs12');
    await tool.type('#password', PASSWORD);
    await tool.click('#unlock');
    await visible(tool, '#certificate');
    await tool.waitForFunction(() => !document.querySelector('#approve').disabled);
    await tool.click('#approve');
    await result(format === 'pades' ? /PDF подписан/ : /Документ подписан/);
    return ff.download(tool);
  };

  const attached = await sign('cms', 'document.txt', text, 'text/plain');
  execFileSync('openssl', ['cms', '-verify', '-binary', '-inform', 'DER', '-in', attached.path, '-CAfile', file('cert.pem'), '-purpose', 'any', '-out', file('attached.out')], { stdio: 'pipe' });
  assert.deepEqual(readFileSync(file('attached.out')), text);
  console.log('PASS: Firefox local CMS with the document inside, verified by OpenSSL');

  await again();
  const detached = await sign('cms-detached', 'document.txt', text, 'text/plain');
  writeFileSync(file('document.txt'), text);
  // OpenSSL takes -content even when the document is inside, so the absence of eContent is checked on its own.
  assert.match(execFileSync('openssl', ['cms', '-cmsout', '-print', '-inform', 'DER', '-in', detached.path], { encoding: 'utf8' }), /eContent: <ABSENT>/);
  execFileSync('openssl', ['cms', '-verify', '-binary', '-inform', 'DER', '-in', detached.path, '-content', file('document.txt'), '-CAfile', file('cert.pem'), '-purpose', 'any', '-out', file('detached.out')], { stdio: 'pipe' });
  console.log('PASS: Firefox local detached CMS, verified by OpenSSL against the original');

  await again();
  const signedXml = await sign('xml', 'order.xml', Buffer.from(xml), 'application/xml');
  if (process.env.NCA_BUNDLES) {
    const jar = prefix => join(process.env.NCA_BUNDLES, readdirSync(process.env.NCA_BUNDLES).find(name => name.startsWith(prefix) && name.endsWith('.jar')));
    const classpath = [jar('kalkancrypt-'), jar('kalkancrypt_xmldsig'), jar('knca_provider_util'), ...(process.env.NCA_CORE ? [process.env.NCA_CORE] : [])].join(delimiter);
    const classes = file('kalkan'); mkdirSync(classes);
    execFileSync(process.env.NCA_JAVAC || 'javac', ['--release', '17', '-cp', classpath, '-d', classes, resolve('tests/interop/XmlReference.java')], { stdio: 'pipe' });
    const official = execFileSync(process.env.NCA_JAVA || 'java', ['-cp', `${classpath}${delimiter}${classes}`, 'XmlReference', 'official', signedXml.path], { encoding: 'utf8', stdio: 'pipe' });
    assert.match(official, /OFFICIAL VALID/);
    console.log('PASS: Firefox local XMLDSig (RSA), accepted by the official Kalkan XMLUtil.verifyXmlSignature');
  } else {
    const value = signedXml.bytes.toString('utf8');
    const verifier = new SignedXml({ publicCert: key.certificate, getCertFromKeyInfo: () => null });
    verifier.loadSignature(new DOMParser().parseFromString(value, 'application/xml').getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0]);
    assert.ok(verifier.checkSignature(value));
    console.log('PASS: Firefox local XMLDSig (RSA), verified by xml-crypto (set NCA_BUNDLES for the official Kalkan check)');
  }

  await again();
  const signedPdf = await sign('pades', 'contract.pdf', pdf, 'application/pdf');
  const pdfText = signedPdf.bytes.toString('latin1');
  const [, , first, second, rest] = /\/ByteRange \[(\d+) (\d+) (\d+) (\d+) *\]/.exec(pdfText).map(Number);
  assert.equal(second + rest, signedPdf.bytes.length);
  assert.deepEqual(signedPdf.bytes.subarray(0, pdf.length), pdf, 'incremental update keeps the original bytes');
  const contents = Buffer.from(pdfText.slice(first + 1, second - 1), 'hex');
  const lengthOctets = contents[1] & 0x7f; let cmsLength = 0;
  for (let index = 0; index < lengthOctets; index++) cmsLength = cmsLength * 256 + contents[2 + index];
  writeFileSync(file('pades.der'), contents.subarray(0, 2 + lengthOctets + cmsLength));
  writeFileSync(file('pades-covered'), Buffer.concat([signedPdf.bytes.subarray(0, first), signedPdf.bytes.subarray(second)]));
  execFileSync('openssl', ['cms', '-verify', '-binary', '-inform', 'DER', '-in', file('pades.der'), '-content', file('pades-covered'), '-CAfile', file('cert.pem'), '-purpose', 'any', '-out', file('pades.out')], { stdio: 'pipe' });
  let independent = 'OpenSSL over the ByteRange';
  if (process.env.DSS_VALIDATOR) {
    const classpath = [`${process.env.DSS_VALIDATOR}/classes`, `${process.env.DSS_VALIDATOR}/lib/*`].join(delimiter);
    const [dss] = JSON.parse(execFileSync('java', ['-cp', classpath, 'Validate', signedPdf.path, file('cert.pem')], { encoding: 'utf8' })).signatures;
    assert.equal(dss.indication, 'TOTAL_PASSED', JSON.stringify(dss)); assert.equal(dss.format, 'PAdES-BASELINE-B');
    const [hanko] = JSON.parse(execFileSync(PYTHON, [resolve('tests/independent_pades.py'), 'validate', signedPdf.path, file('cert.pem')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })).signatures;
    assert.ok(hanko.bottomLine && hanko.coverage === 'ENTIRE_FILE' && hanko.modificationLevel === 'NONE', JSON.stringify(hanko));
    independent += ', EU DSS TOTAL_PASSED PAdES-BASELINE-B and pyHanko ENTIRE_FILE';
  }
  console.log(`PASS: Firefox local PAdES-B-B (RSA), original bytes kept; ${independent}`);

  // Verify screen: the attached CMS and the detached one with its original.
  await ff.go(tool, 'signing/approve.html?mode=verify');
  await ff.choose(tool, '#document', attached.bytes, 'document.txt.p7s', 'application/pkcs7-mime');
  await waitText(tool, '#status', /Файл готов к проверке/);
  await tool.click('#verify-submit');
  await result(/Подпись верна/);
  await again();
  await ff.choose(tool, '#document', detached.bytes, 'document.txt.p7s', 'application/pkcs7-signature');
  await waitText(tool, '#status', /Добавьте исходный документ ниже/);
  await visible(tool, '#original-controls');
  await ff.choose(tool, '#original', text, 'document.txt', 'text/plain');
  await tool.waitForFunction(() => !document.querySelector('#verify-submit').disabled);
  await tool.click('#verify-submit');
  await result(/Подпись верна/);
  console.log('PASS: Firefox verify screen: CMS with the document inside and detached CMS with its original are valid');

  if (process.env.NCA_LIVE_TSP === '1') {
    // Explicit only: a synthetic signer with real NCA RSA time-stamps, built in Node, then the archive renewed in Firefox.
    const lt = await longTermHarness();
    const ncaChecker = new RevocationChecker({ store: memoryStore() });
    let archive;
    try {
      ({ cms: archive } = await signLongTerm(lt.signer, Buffer.from('Tegin synthetic CAdES-LTA for Firefox'), { level: 'lta', signerPath: lt.signerPath,
        evidence: (path, role) => role === 'timestamp' ? ncaChecker.checkPath(path, { fresh: true }) : lt.evidence(path), requester: value => requestTimestamp(value, TSA_PROFILES.rsa) }));
      writeFileSync(file('archive-root.pem'), lt.pki.root.pem);
    } finally { lt.destroy(); }
    await again();
    await ff.choose(tool, '#document', archive, 'archive.p7s', 'application/pkcs7-mime');
    await waitText(tool, '#status', /Файл готов к проверке/);
    await tool.click('#verify-submit');
    await result(/Подпись верна/);
    const details = await textOf(tool, '#result-details');
    assert.match(details, /Архивная метка 1 из 1: .+ · SHA-256\nПроверена: подпись службы меток и её цепочка НУЦ/);
    assert.match(details, /Статус отзыва на момент метки: не вычислялся\./);
    await visible(tool, '#renew-archive');
    await tool.click('#renew-archive');
    await visible(tool, '#renew-download', 120000).catch(async error => { throw new Error(`no renewal; "${await textOf(tool, '#renew-status')}"`, { cause: error }); });
    assert.match(await textOf(tool, '#renew-status'), /Архивных меток в подписи: 2\. Прежние подписи, метки и данные проверки сохранены/);
    const renewed = await ff.download(tool, '#renew-download');
    assert.ok(renewed.bytes.length > archive.length);
    await again();
    await ff.choose(tool, '#document', renewed.bytes, 'archive.renewed.p7s', 'application/pkcs7-mime');
    await waitText(tool, '#status', /Файл готов к проверке/);
    await tool.click('#verify-submit');
    await result(/Подпись верна/);
    assert.match(await textOf(tool, '#result-details'), /Архивная метка 1 из 2: [^\n]+\n[^\n]+\n[^\n]+\nАрхивная метка 2 из 2: /);
    let dss = '';
    if (process.env.DSS_VALIDATOR) {
      const classpath = [`${process.env.DSS_VALIDATOR}/classes`, `${process.env.DSS_VALIDATOR}/lib/*`].join(delimiter);
      const [result] = JSON.parse(execFileSync('java', ['-cp', classpath, 'Validate', renewed.path, file('archive-root.pem')], { encoding: 'utf8' })).signatures;
      const archives = result.timestamps.filter(item => item.type === 'ARCHIVE_TIMESTAMP');
      assert.ok(archives.length === 2 && archives.every(item => item.archiveType === 'CAdES_V3' && item.imprintIntact && item.atsHashIndexValid) && result.intact, JSON.stringify(result.timestamps));
      dss = '; EU DSS: two archive-time-stamp-v3, imprints and ats-hash-index-v3 valid';
    }
    console.log(`PASS: Firefox CAdES-LTA with live NUC RSA time-stamps verified, archive renewed from the verify screen and re-verified${dss}`);
  } else console.log('SKIP: CAdES-LTA verification and renewal in Firefox (set NCA_LIVE_TSP=1, contacts the NUC TSA)');
  assert.deepEqual(ff.errors, []);
  console.log('Firefox signing E2E completed.');
} finally {
  await browser.close().catch(() => {});
  site.close();
  rmSync(folder, { recursive: true, force: true });
}
