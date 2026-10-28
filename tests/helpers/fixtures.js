import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { forge, A, O, seq, set, oid, octet, context, integer, algorithm, bytes, binary, der } from '../../extension/crypto/encoding.js';
import { nca256 } from '../../extension/crypto/nca-curves.js';
import GostSign from '../../extension/vendor/gost/sign.cjs';
import GostDigest from '../../extension/vendor/gost/digest.cjs';

export const PASSWORD = 'public-test-password';
export function rsaFixture({ purpose } = {}) {
  if (purpose && !['clientAuth', 'emailProtection'].includes(purpose)) throw new Error('Unsupported fixture purpose');
  const folder = mkdtempSync(join(tmpdir(), 'ncabrowser-rsa-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(folder, 'key.pem'),
      '-out', join(folder, 'cert.pem'), '-days', '2', '-subj', '/CN=Tegin disposable test', ...(purpose ? ['-addext', 'extendedKeyUsage=' + purpose] : [])], { stdio: 'ignore' });
    execFileSync('openssl', ['pkcs12', '-export', '-inkey', join(folder, 'key.pem'), '-in', join(folder, 'cert.pem'),
      '-out', join(folder, 'key.p12'), '-passout', `pass:${PASSWORD}`], { stdio: 'ignore' });
    return { container: new Uint8Array(readFileSync(join(folder, 'key.p12'))),
      certificate: readFileSync(join(folder, 'cert.pem'), 'utf8'), publicKey: readFileSync(join(folder, 'key.pem'), 'utf8') };
  } finally { rmSync(folder, { recursive: true, force: true }); }
}

export function gostFixture(family = '512') {
  const scheme = family === '2004' ? { version: 2001, length: 256, namedCurve: 'S-256-A', oid: O.gost2004, curveOid: '1.2.398.3.10.1.1.1.1.1', hash: O.hash2004, sig: O.sig2004 } : family === '256' ? { version: 2012, length: 256, curve: nca256, oid: O.gost256, curveOid: '1.2.398.3.10.1.1.2.1.1', hash: O.hash256, sig: O.sig256 } : { version: 2012, length: 512, namedCurve: 'T-512-A', oid: O.gost512, curveOid: '1.2.398.3.10.1.1.2.2.1', hash: O.hash512, sig: O.sig512 };
  const engine = new GostSign(scheme);
  const pair = engine.generateKey();
  const name = seq(set(seq(oid('2.5.4.3'), A.create(0, A.Type.UTF8, false, 'Tegin GOST disposable test'))));
  const pkcs8 = seq(integer(0), seq(oid(scheme.oid), seq(oid(scheme.curveOid), oid(scheme.hash))), octet(new Uint8Array(pair.privateKey)));
  const spki = seq(pkcs8.value[1], A.create(0, A.Type.BITSTRING, false, '\0' + der(octet(new Uint8Array(pair.publicKey)))));
  const date = value => A.create(0, A.Type.GENERALIZEDTIME, false, A.dateToGeneralizedTime(value));
  const tbs = seq(context(0, [integer(2)]), integer(1), algorithm(scheme.sig), name,
    seq(date(new Date(Date.now() - 86400000)), date(new Date(Date.now() + 86400000))), name, spki);
  const hash = new GostDigest({ version: scheme.version === 2001 ? 1994 : 2012, length: scheme.length, sBox: 'D-TEST' }).digest(bytes(der(tbs)));
  const signature = new Uint8Array(engine.sign(pair.privateKey, hash));
  const cert = seq(tbs, algorithm(scheme.sig), A.create(0, A.Type.BITSTRING, false, '\0' + binary(signature)));
  const encrypted = forge.pki.encryptPrivateKeyInfo(pkcs8, PASSWORD, { algorithm: '3des', count: 2048 });
  const safe = seq(seq(oid(forge.pki.oids.pkcs8ShroudedKeyBag), context(0, [encrypted])),
    seq(oid(forge.pki.oids.certBag), context(0, [seq(oid(forge.pki.oids.x509Certificate), context(0, [octet(der(cert))]))])));
  const authSafe = der(seq(seq(oid(O.data), context(0, [octet(der(safe))]))));
  const salt = forge.random.getBytesSync(16);
  const key = forge.pkcs12.generateKey(PASSWORD, forge.util.createBuffer(salt), 3, 2048, 20).getBytes();
  const mac = forge.hmac.create(); mac.start('sha1', key); mac.update(authSafe);
  const macData = seq(seq(algorithm(forge.pki.oids.sha1), octet(mac.digest().getBytes())), octet(salt), A.create(0, A.Type.INTEGER, false, '\x08\x00'));
  const container = bytes(der(seq(integer(3), seq(oid(O.data), context(0, [octet(authSafe)])), macData)));
  new Uint8Array(pair.privateKey).fill(0);
  return { container, certificate: forge.util.encode64(der(cert)), publicKey: new Uint8Array(pair.publicKey) };
}
