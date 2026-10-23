// Outputs public verification material only, never a private key or container.
import { gostFixture, PASSWORD } from './helpers/fixtures.js';
import { openContainer } from '../extension/crypto/signer.js';
const fixture = gostFixture();
const signer = await openContainer(fixture.container, PASSWORD);
try {
  const data = new TextEncoder().encode('Tegin independent GOST verification');
  console.log(JSON.stringify({ data: Buffer.from(data).toString('hex'),
    public: Buffer.from(fixture.publicKey).toString('hex'),
    hash: Buffer.from(await signer.digest(data)).toString('hex'),
    signature: Buffer.from(await signer.sign(data)).toString('hex') }));
} finally { signer.destroy(); fixture.container.fill(0); }
