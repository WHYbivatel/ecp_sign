// Disposable extension-producer CMS vectors for Kalkan's independent verifier.
// Keys are generated in memory and never written; output is test payload + CMS only.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { rsaFixture, gostFixture, PASSWORD } from './helpers/fixtures.js';
import { openContainer } from '../extension/crypto/signer.js';
import { signCms } from '../extension/crypto/cms.js';

const output = process.argv[2];
if (!output) throw new Error('Pass a temporary output directory');
mkdirSync(output, { recursive: true });
const document = new TextEncoder().encode('Tegin C1 public synthetic document vector v1');
const challenge = new TextEncoder().encode('tegin-c1-auth-challenge-v1-synthetic');
writeFileSync(join(output, 'extension-document.bin'), document);
writeFileSync(join(output, 'extension-challenge.bin'), challenge);

for (const [profile, makeFixture] of [
  ['rsa', () => rsaFixture()],
  ['gost2004', () => gostFixture('2004')],
  ['gost256', () => gostFixture('256')],
  ['gost512', () => gostFixture('512')],
]) {
  const fixture = makeFixture();
  const signer = await openContainer(fixture.container, PASSWORD);
  try {
    writeFileSync(join(output, `extension-${profile}.cms`), await signCms(signer, document, { encapsulate: false }));
    console.log(`generated extension detached ${profile}`);
  } finally {
    signer.destroy();
    fixture.container.fill(0);
  }
}

const authFixture = rsaFixture({ purpose: 'clientAuth' });
const authSigner = await openContainer(authFixture.container, PASSWORD);
try {
  writeFileSync(join(output, 'extension-auth-attached.cms'), await signCms(authSigner, challenge, { encapsulate: true }));
  console.log('generated extension attached auth challenge');
} finally {
  authSigner.destroy();
  authFixture.container.fill(0);
}
