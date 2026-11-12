import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ZIP_DATE, zipEntries, zipFolder } from '../scripts/lib/zip.mjs';

function tree(folder, files, time) {
  for (const [name, content] of files) {
    mkdirSync(join(folder, name, '..'), { recursive: true });
    writeFileSync(join(folder, name), content);
    utimesSync(join(folder, name), time, time);
  }
}

test('extension archives do not depend on file times or creation order', async () => {
  const folder = mkdtempSync(join(tmpdir(), 'tegin-zip-'));
  try {
    const files = [['manifest.json', '{"name":"Тегін"}'], ['b/ü.js', 'x'.repeat(4096)], ['a/empty.txt', ''], ['b/a.png', Buffer.from([137, 80, 78, 71])]];
    tree(join(folder, 'one'), files, new Date('2026-01-02T03:04:05Z'));
    tree(join(folder, 'two'), [...files].reverse(), new Date('2031-06-07T08:09:10Z'));
    const one = await zipFolder(join(folder, 'one')), two = await zipFolder(join(folder, 'two'));
    assert.ok(one.equals(two));
    const zip = zipEntries(one);
    assert.deepEqual(zip.names(), ['a/empty.txt', 'b/a.png', 'b/ü.js', 'manifest.json']);
    for (const [name, content] of files) {
      assert.ok(zip.read(name).equals(Buffer.from(content)), name);
      assert.deepEqual(zip.stamp(name), { time: 0, date: ZIP_DATE });
    }
    writeFileSync(join(folder, 'two', 'b/ü.js'), 'y'.repeat(4096));
    assert.ok(!(await zipFolder(join(folder, 'two'))).equals(one));
  } finally { rmSync(folder, { recursive: true, force: true }); }
});
