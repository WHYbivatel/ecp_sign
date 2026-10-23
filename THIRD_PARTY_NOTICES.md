# Third-party notices

## WebCrypto GOST

Source: https://github.com/rudonick/crypto
Pinned upstream commit: `a8caf28ad35eb6500ebdefa93320e597f6e58c3d`.
Copyright 2014–2016 Rudolf Nickolaev. Apache License 2.0.
The digest implementation also credits Alexey Degtyarev (2013), and the
elliptic-curve implementation credits Tom Wu / JSBN (2003–2005).
Original copyright and license headers are retained in the source and bundles.

Files adapted: `gostSign.js`, `gostDigest.js`, `gostCipher.js` in
`extension/vendor/gost/`. Local changes: relative CommonJS imports, an explicit
globalThis factory context, replacement of the random adapter by mandatory
Web Crypto getRandomValues, rejection of zero signature components, and a
boolean check fix for the zero-digest verification case. The latter follows
GOST verification step 3 and prevents attempting to invert zero.
A copy-only public curve-parameter accessor is exposed for point validation.
Modern Kazakhstan GOST-256 parameters are supplied explicitly because the
old upstream T-256-A alias refers to CryptoPro-A.
The full Apache 2.0 license is distributed with the extension.

## Other bundled packages

- node-forge 1.4.0, Digital Bazaar, BSD-3-Clause option of the dual license.
- @xmldom/xmldom 0.9.12, MIT.
- xml-crypto 6.4.0, MIT. Only canonicalization and its dependencies are used in
  the browser; Node crypto entry points are replaced by throwing stubs.
- xpath 0.0.33, MIT (version resolved in package-lock.json).
- @xmldom/is-dom-node 1.0.1, MIT (version resolved in package-lock.json).

The exact installed dependency graph is pinned in package-lock.json.
License files are included in each build's licenses directory.
Playwright and esbuild are development tools, not runtime dependencies.

## Dependency advisory

The registry audit on 2026-10-22 reported GHSA-86w9-cpqp-85rv for node-forge
<=1.4.0 (RSA signature verification accepting malformed DigestAlgorithm).
This application does not use forge's RSA signature verifier or trust
verification. RSA data signing and all RSA certificate/CMS verification use
native Web Crypto. Prehashed RSA signing uses forge's private-key operation,
then strictly compares the entire recovered PKCS#1 v1.5 block against the
expected SHA-256 DigestInfo and padding using the public RSA exponent.
Independent tests use Node crypto, OpenSSL and official Kalkan. Keep this dependency under review and update when a fix is
available. This mitigation does not constitute an independent security audit.
