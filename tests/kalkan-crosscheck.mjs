// Development-only interop check. Never starts NCALayer or installs Java.
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
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
    } finally { signer.destroy(); fixture.container.fill(0); }
  }
} finally { rmSync(folder, { recursive: true, force: true }); }
