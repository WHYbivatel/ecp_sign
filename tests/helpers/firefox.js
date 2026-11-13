// Firefox with the built extension over WebDriver BiDi (puppeteer-core), for E2E tests of extension pages.
// FIREFOX_EXECUTABLE selects an installed Firefox; otherwise the current stable release is cached in .browsers/.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import puppeteer from 'puppeteer-core';
import { Browser, detectBrowserPlatform, install, resolveBuildId } from '@puppeteer/browsers';

async function executable() {
  if (process.env.FIREFOX_EXECUTABLE) return process.env.FIREFOX_EXECUTABLE;
  const target = detectBrowserPlatform();
  const buildId = await resolveBuildId(Browser.FIREFOX, target, 'stable');
  return (await install({ browser: Browser.FIREFOX, buildId, platform: target, cacheDir: resolve('.browsers') })).executablePath;
}
export const pause = ms => new Promise(done => setTimeout(done, ms));

export async function launchFirefox(folder, extension) {
  const executablePath = await executable();
  if (!existsSync(executablePath)) throw new Error(`Firefox not found: ${executablePath}`);
  const addonId = JSON.parse(readFileSync(join(extension, 'manifest.json'), 'utf8')).browser_specific_settings.gecko.id;
  const uuid = randomUUID(), base = `moz-extension://${uuid}`, downloads = join(folder, 'downloads');
  // Extension windows are privileged browsing contexts: WebDriver BiDi reaches them only with system access (test profile only).
  const browser = await puppeteer.launch({ browser: 'firefox', executablePath, headless: true, userDataDir: join(folder, 'profile'),
    env: { ...process.env, MOZ_REMOTE_ALLOW_SYSTEM_ACCESS: '1' },
    extraPrefsFirefox: { 'extensions.webextensions.uuids': JSON.stringify({ [addonId]: uuid }), 'browser.download.folderList': 2, 'browser.download.dir': downloads, 'browser.download.useDownloadDir': true,
      // A downloaded PDF would open in a new tab; the hidden test tab then stops animation frames that waits rely on.
      'pdfjs.disabled': true } });
  assert.equal(await browser.installExtension(extension), addonId);
  const errors = [];
  const hrefOf = page => page.evaluate(() => location.href).catch(() => '');
  async function extensionPage(prefix, known) {
    for (let i = 0; i < 300; i++) {
      for (const candidate of await browser.pages()) {
        if (known.has(candidate)) continue;
        if ((await hrefOf(candidate)).startsWith(`${base}/${prefix}`)) { candidate.on('pageerror', error => errors.push(error.message)); return candidate; }
      }
      await pause(50);
    }
    throw new Error(`no extension page ${prefix}`);
  }
  // WebDriver BiDi cannot open moz-extension:// itself; extension pages navigate themselves.
  async function go(page, path) {
    await page.evaluate(target => location.assign(browser.runtime.getURL(target)), path);
    for (let i = 0; i < 200; i++) {
      if ((await hrefOf(page)) === `${base}/${path}` && await page.evaluate(() => document.readyState === 'complete').catch(() => false)) return;
      await pause(50);
    }
    throw new Error(`did not reach ${path}`);
  }
  // input.setFiles is refused in privileged contexts; the same File reaches the input through DataTransfer.
  async function choose(page, selector, bytes, name, type = 'application/octet-stream') {
    await page.evaluate((selector, bytes, name, type) => {
      const transfer = new DataTransfer();
      if (bytes) transfer.items.add(new File([Uint8Array.from(bytes)], name, { type }));
      const input = document.querySelector(selector); input.files = transfer.files; input.dispatchEvent(new Event('change', { bubbles: true }));
    }, selector, bytes ? Array.from(bytes) : null, name, type);
  }
  // A repeated name is saved as "name(1).ext", so the result is the file that was not there before the click.
  async function download(page, selector = '#download') {
    const name = await page.$eval(selector, node => node.download);
    const before = new Set(existsSync(downloads) ? readdirSync(downloads) : []);
    await page.click(selector);
    // Firefox first creates an empty placeholder next to a .part file.
    const saved = () => {
      if (!existsSync(downloads)) return null;
      const files = readdirSync(downloads);
      const found = files.find(item => !before.has(item) && !item.endsWith('.part'));
      return found && !files.includes(`${found}.part`) && statSync(join(downloads, found)).size > 0 ? found : null;
    };
    for (let i = 0; i < 400 && !saved(); i++) await pause(50);
    const file = saved();
    assert.ok(file, `${name} was not saved`);
    return { name, file, path: join(downloads, file), bytes: readFileSync(join(downloads, file)) };
  }
  return { browser, base, errors, hrefOf, extensionPage, go, choose, download };
}
