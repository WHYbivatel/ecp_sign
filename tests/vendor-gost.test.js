import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import vm from 'node:vm';

// vendor/gost/sign.cjs keeps its big-number helpers private; the test exposes them from a copy of the source.
const file = resolve('extension/vendor/gost/sign.cjs');
function internals() {
  const source = readFileSync(file, 'utf8');
  const marker = '    function testBit(x, n) {';
  assert.ok(source.includes(marker));
  const exposed = source.replace(marker, `    globalThis.__gostInternals = { invMod, nbv, compare, mod, mul, htobi };\n${marker}`);
  const context = { module: { exports: {} }, require: createRequire(file), globalThis: {}, crypto: globalThis.crypto };
  context.globalThis = context;
  context.exports = context.module.exports;
  vm.runInNewContext(exposed, context, { filename: file });
  return context.__gostInternals;
}

test('modular inverse is correct on every path, including the final reduction (subtract was undefined)', () => {
  const { invMod, nbv, compare, mod, mul } = internals();
  const gcd = (a, b) => b ? gcd(b, a % b) : a;
  let checked = 0;
  for (let m = 3; m < 400; m += 2) {
    for (let x = 1; x < m; x++) {
      if (gcd(x, m) !== 1) continue;
      const inverse = invMod(nbv(x), nbv(m));
      assert.ok(compare(inverse, nbv(0)) >= 0 && compare(inverse, nbv(m)) < 0, `${x}^-1 mod ${m} out of range`);
      assert.equal(compare(mod(mul(nbv(x), inverse), nbv(m)), nbv(1)), 0, `${x}^-1 mod ${m}`);
      checked++;
    }
  }
  assert.ok(checked > 30000);
  // Values that reach `compare(d, m) >= 0` at the end, found by search on the GOST 256-bit field prime
  // (about 1 in 17 000 random inputs): before the fix they threw ReferenceError inside signing and verification.
  const { htobi } = internals();
  const p = htobi('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97');
  for (const hex of ['1a59a1cc17cfbd759275e2e657cb710198401a2044546d60ff081562d3471dd6', '19ea02f3c7c0bfec65ccc4f255b980d838108e2d6cbcf621ac45237fa9c4364d',
    '878a5a4d197253889c99fbbae3764049e00eb03b89766719ae4ada867f28be8a']) {
    const x = mod(htobi(hex), p);
    const inverse = invMod(x, p);
    assert.ok(compare(inverse, nbv(0)) >= 0 && compare(inverse, p) < 0);
    assert.equal(compare(mod(mul(x, inverse), p), nbv(1)), 0, hex);
  }
});

test('the vendored GOST files reference only names they define or import', () => {
  for (const name of ['sign.cjs', 'digest.cjs', 'cipher.cjs', 'random.cjs']) {
    const source = readFileSync(resolve(dirname(file), name), 'utf8');
    assert.ok(!/\bsubtract\s*\(/.test(source), `${name}: subtract() is not defined in jsbn's functional port`);
  }
});
