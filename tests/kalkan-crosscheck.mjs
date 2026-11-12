// Development-only interop check. Never starts NCALayer or installs Java.
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { rsaFixture, gostFixture, PASSWORD } from './helpers/fixtures.js';
import { openContainer } from '../extension/crypto/signer.js';
import { signCms } from '../extension/crypto/cms.js';
import { signXml } from '../extension/crypto/xml.js';

const jars = process.env.NCA_KALKAN_JARS;
if (!jars) throw new Error('Set NCA_KALKAN_JARS to the provider and XMLDSig jars (separated by the OS classpath delimiter).');
const java = process.env.NCA_JAVA || 'java';
const javac = process.env.NCA_JAVAC || 'javac';
const delimiter = process.platform === 'win32' ? ';' : ':';
const folder = mkdtempSync(join(tmpdir(), 'ncabrowser-kalkan-check-'));
try {
  execFileSync(javac, ['-cp', jars, '-d', folder, resolve('tests/interop/Verify.java')], { stdio: 'pipe' });
  for (const [family, fixture] of [['RSA', rsaFixture()], ['GOST512', gostFixture()], ['GOST256', gostFixture('256')], ['GOST2004', gostFixture('2004')]]) {
    const signer = await openContainer(fixture.container, PASSWORD);
    try {
      const data = new TextEncoder().encode('Kalkan independent check: Привет');
      const documentPath = join(folder, 'document.bin');
      writeFileSync(documentPath, data);
      for (const [encapsulate, cades, digested] of [[true, false, false], [false, false, false], [true, true, false], [false, true, false], [false, false, true], [false, true, true]]) {
        const path = join(folder, 'signature.p7s');
        writeFileSync(path, await signCms(signer, digested ? await signer.digest(data) : data, { encapsulate, cades, digested }));
        const args = ['-cp', `${jars}${delimiter}${folder}`, 'Verify', 'cms', path];
        if (!encapsulate) args.push(documentPath);
        const output = execFileSync(java, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
        if (!output.includes('KALKAN CMS VALID')) throw new Error(`${family} CMS failed`);
        console.log(`PASS Kalkan ${family} ${cades ? 'CAdES-BES' : 'CMS'} ${encapsulate ? 'attached' : 'detached'}${digested ? ' prehashed' : ''}`);
      }
      if (family === 'RSA' && process.env.NCA_LIVE_TSP === '1') {
        const path = join(folder, 'timestamped.p7s');
        writeFileSync(path, await signCms(signer, data, { timestamp: true }));
        const output = execFileSync(java, ['-cp', `${jars}${delimiter}${folder}`, 'Verify', 'cms', path], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
        if (!output.includes('KALKAN TIMESTAMP VALID')) throw new Error('Kalkan timestamp failed');
        console.log('PASS Kalkan CAdES-T: main signature, real TSA signature, certificate binding and signature imprint');
      }
      if (family === 'GOST256') {
        try { await signXml(signer, '<test/>'); throw new Error('Unsupported XML accepted'); }
        catch (error) { if (!error.message.includes('ГОСТ-256')) throw error; }
        console.log('PASS GOST256 XML explicitly refused: official XMLDSig has no matching algorithm');
        continue;
      }
      const path = join(folder, 'signed.xml');
      writeFileSync(path, await signXml(signer, '<request xmlns="urn:ncabrowser:test"><text>Привет &amp; мир</text></request>'));
      const output = execFileSync(java, ['-cp', `${jars}${delimiter}${folder}`, 'Verify', 'xml', path], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      if (!output.includes('KALKAN XML VALID')) throw new Error(`${family} XML failed`);
      console.log(`PASS Kalkan ${family} XMLDSig`);
      // XPath (Common Utils 0.3.4 profile) and co-signing: Kalkan checks every signature on its own.
      const each = xml => {
        writeFileSync(path, xml);
        return execFileSync(java, ['-cp', `${jars}${delimiter}${folder}`, 'Verify', 'xml-each', path], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
          .split('\n').filter(line => line.startsWith('KALKAN XML SIGNATURE')).map(line => line.split(' ').pop());
      };
      const reference = JSON.parse(readFileSync(resolve('tests/fixtures/ncalayer-xml-reference.json'), 'utf8'));
      const xpath = { tbsXPath: reference.tbsElementXPath, parentXPath: reference.signatureParentElementXPath };
      const expect = (actual, expected, what) => { if (actual.join() !== expected.join()) throw new Error(`${family} ${what}: ${actual.join()}`); };
      const once = await signXml(signer, reference.input, xpath);
      expect(each(once), ['VALID'], 'XPath signature');
      const twice = await signXml(signer, once, xpath);
      expect(each(twice), ['VALID', 'VALID'], 'XPath co-signature');
      expect(each(twice.replace('Привет', 'Пока')), ['INVALID', 'INVALID'], 'changed element');
      expect(each(await signXml(signer, reference.cosigned, xpath)), ['VALID', 'VALID', 'VALID'], 'co-signature of the NCALayer reference');
      expect(each(await signXml(signer, once)), ['VALID', 'VALID'], 'whole-document signature after an element signature');
      console.log(`PASS Kalkan ${family} XPath signature and co-signatures (own, after NCALayer's two, whole document after element); changed element rejected for all`);
      for (const name of ['egov-login', 'egov-service-sign', 'nuc-cabinet-login']) {
        const xml = JSON.parse(readFileSync(resolve(`tests/fixtures/portals/${name}.json`), 'utf8')).request.args.data;
        const signed = await signXml(signer, xml);
        writeFileSync(path, signed);
        const verified = execFileSync(java, ['-cp', `${jars}${delimiter}${folder}`, 'Verify', 'xml', path], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
        if (!verified.includes('KALKAN XML VALID')) throw new Error(`${family} ${name} XML failed`);
        writeFileSync(path, signed.replace(/PORTAL|00000000-0000-4000-8000-000000000000|SYNTH-0001/, 'CHANGED'));
        let rejected = false;
        try { execFileSync(java, ['-cp', `${jars}${delimiter}${folder}`, 'Verify', 'xml', path], { stdio: 'pipe' }); } catch { rejected = true; }
        if (!rejected) throw new Error(`${family} ${name} changed XML accepted`);
        console.log(`PASS Kalkan ${family} XMLDSig of the ${name} portal payload; changed payload rejected`);
      }
    } finally { signer.destroy(); fixture.container.fill(0); }
  }
} finally { rmSync(folder, { recursive: true, force: true }); }
