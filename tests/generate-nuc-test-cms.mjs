// Generate extension CMS with the public NUC test PKCS#12 fixture.
// Never writes the container/private key; output contains only payloads and CMS.
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { openContainer } from '../extension/crypto/signer.js';
import { signCms } from '../extension/crypto/cms.js';
import { verifyCms } from '../extension/crypto/cms-verify.js';

const [containerPath, output] = process.argv.slice(2);
const password = process.env.CMS_E2E_TEST_P12_PASSWORD;
if (!containerPath || !output || !password) {
  throw new Error('Pass public test PKCS#12 path, output directory and CMS_E2E_TEST_P12_PASSWORD');
}
mkdirSync(output, { recursive: true });
const container = new Uint8Array(readFileSync(containerPath));
const document = new TextEncoder().encode('%PDF-1.4\nTegin public NUC test document vector\n%%EOF\n');
const challenge = new TextEncoder().encode(`Tegin public NUC auth challenge ${randomUUID()}`);
let signer;
try {
  signer = await openContainer(container, password);
} catch (error) {
  const notAfter = error?.certificate?.notAfter;
  throw new Error(notAfter
    ? `The public NUC test PKCS#12 cannot sign: its certificate is expired or not yet valid (notAfter=${notAfter}).`
    : 'The public NUC test PKCS#12 could not be opened by the extension crypto provider.');
}
try {
  const detached = await signCms(signer, document, { encapsulate: false });
  const attached = await signCms(signer, challenge, { encapsulate: true });
  if (!(await verifyCms(detached, { detached: document })).valid) throw new Error('Local detached CMS verification failed');
  if (!(await verifyCms(attached)).valid) throw new Error('Local attached CMS verification failed');
  writeFileSync(join(output, 'extension-document.bin'), document);
  writeFileSync(join(output, 'extension-document.cms'), detached);
  writeFileSync(join(output, 'extension-auth-challenge.bin'), challenge);
  writeFileSync(join(output, 'extension-auth-challenge.cms'), attached);
  console.log('Generated and locally verified extension CMS using public NUC test certificate (detached document + attached challenge).');
} finally {
  signer.destroy();
  container.fill(0);
}
