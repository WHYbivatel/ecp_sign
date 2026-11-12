import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { A, seq, oid, integer, der, bytes, parse, oidValue, forge } from '../../extension/crypto/encoding.js';
import { issue } from './pki.js';

const TST_INFO = '1.2.840.113549.1.9.16.1.4';

// Disposable RFC 3161 service. The request's own imprint (GOST 34.11-2015 under
// the Kazakhstan OID, which OpenSSL cannot compute) is copied into TSTInfo; OpenSSL
// signs the token as CAdES with SigningCertificateV2. Its self-signed certificate is
// trusted only where a test passes `anchor`; the extension trusts bundled NUC roots.
// With `issuer` (a tests/helpers/pki.js CA) the TSA certificate is issued by that CA instead, so its
// path has revocation evidence; the token then carries the CA certificate too.
export function syntheticTsa({ issuer } = {}) {
  const folder = mkdtempSync(join(tmpdir(), 'ncabrowser-tsa-'));
  let certificate = null;
  if (issuer) {
    certificate = issue({ name: 'Tegin synthetic TSA', issuer, eku: ['timeStamping'], ekuCritical: true });
    writeFileSync(join(folder, 'key.pem'), forge.pki.privateKeyToPem(certificate.privateKey));
    writeFileSync(join(folder, 'cert.pem'), certificate.pem);
    writeFileSync(join(folder, 'chain.pem'), issuer.pem);
  } else execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(folder, 'key.pem'), '-out', join(folder, 'cert.pem'),
    '-days', '2', '-subj', '/CN=Tegin synthetic TSA', '-addext', 'extendedKeyUsage=critical,timeStamping', '-addext', 'keyUsage=critical,digitalSignature'], { stdio: 'ignore' });
  const pem = readFileSync(join(folder, 'cert.pem'), 'utf8');
  let serial = 0;
  return {
    certificate,
    anchor: new Uint8Array(Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ''), 'base64')),
    reply(query, { time = new Date() } = {}) {
      const fields = parse(new Uint8Array(query)).value;
      if (fields[0].value !== '\x01' || fields.length < 3) throw new Error('Not a TimeStampReq');
      const policy = fields.find(node => node.type === A.Type.OID);
      const nonce = fields.find((node, index) => index > 1 && node.type === A.Type.INTEGER);
      const info = seq(integer(1), oid(oidValue(policy)), fields[1], integer(++serial),
        A.create(0, A.Type.GENERALIZEDTIME, false, A.dateToGeneralizedTime(time)), ...(nonce ? [nonce] : []));
      writeFileSync(join(folder, 'tstinfo.der'), Buffer.from(der(info), 'binary'));
      execFileSync('openssl', ['cms', '-sign', '-binary', '-nodetach', '-cades', '-nosmimecap', '-md', 'sha256', '-econtent_type', TST_INFO,
        '-in', join(folder, 'tstinfo.der'), '-signer', join(folder, 'cert.pem'), '-inkey', join(folder, 'key.pem'), ...(issuer ? ['-certfile', join(folder, 'chain.pem')] : []),
        '-outform', 'DER', '-out', join(folder, 'token.der')], { stdio: 'ignore' });
      const token = parse(new Uint8Array(readFileSync(join(folder, 'token.der'))));
      return bytes(der(seq(seq(integer(0)), token)));
    },
    destroy() { rmSync(folder, { recursive: true, force: true }); }
  };
}
