import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, mkdirSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';

// Browser under test: TEGIN_BROWSER=chromium (Playwright build, default) | chrome | msedge.
// Branded Chrome ignores --load-extension since 137, so the extension is installed with
// Extensions.loadUnpacked over --remote-debugging-pipe and Playwright attaches to that profile.
export const browserName = process.env.TEGIN_BROWSER || 'chromium';
if (!['chromium', 'chrome', 'msedge'].includes(browserName)) throw new Error(`Unknown TEGIN_BROWSER: ${browserName}`);

const CHROME_PATHS = {
  linux: ['/opt/google/chrome/chrome'],
  darwin: ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'],
  win32: [`${process.env.PROGRAMFILES}\\Google\\Chrome\\Application\\chrome.exe`, `${process.env['PROGRAMFILES(X86)']}\\Google\\Chrome\\Application\\chrome.exe`, `${process.env.LOCALAPPDATA}\\Google\\Chrome\\Application\\chrome.exe`]
};
function chromePath() {
  const found = [process.env.CHROME_EXECUTABLE, ...(CHROME_PATHS[process.platform] || [])].find(path => path && existsSync(path));
  if (!found) throw new Error('Google Chrome not found; set CHROME_EXECUTABLE.');
  return found;
}

// One CDP call over the pipe (fd 3 in, fd 4 out, NUL-delimited JSON).
function pipeCall(child, method, params) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const timer = setTimeout(() => reject(new Error(`${method} timed out`)), 30000);
    child.stdio[4].on('data', chunk => {
      buffer += chunk.toString('utf8');
      for (let end = buffer.indexOf('\0'); end >= 0; end = buffer.indexOf('\0')) {
        const message = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1);
        if (message.id !== 1) continue;
        clearTimeout(timer);
        if (message.error) reject(new Error(`${method}: ${message.error.message}`)); else resolve(message.result);
      }
    });
    child.stdio[3].write(JSON.stringify({ id: 1, method, params }) + '\0');
  });
}

async function launchBrandedChrome(profile, extension, { args = [], viewport, headless = true }) {
  mkdirSync(profile, { recursive: true });
  const child = spawn(chromePath(), [
    `--user-data-dir=${profile}`, '--remote-debugging-pipe', '--remote-debugging-port=0', '--enable-unsafe-extension-debugging',
    '--no-first-run', '--no-default-browser-check', '--disable-search-engine-choice-screen', '--disable-component-extensions-with-background-pages', '--password-store=basic', '--use-mock-keychain',
    ...(process.getuid?.() === 0 ? ['--no-sandbox'] : []), ...(headless ? ['--headless=new'] : []), ...(viewport ? [`--window-size=${viewport.width},${viewport.height}`] : []), ...args, 'about:blank'
  ], { stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'] });
  let stderr = ''; child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-4000); });
  // The pipe resets when the browser exits; that is the normal end of a session.
  for (const stream of [child.stdio[3], child.stdio[4]]) stream.on('error', () => {});
  const exited = new Promise(resolve => child.once('exit', resolve));
  try {
    const { id } = await Promise.race([pipeCall(child, 'Extensions.loadUnpacked', { path: extension }),
      exited.then(code => { throw new Error(`Chrome exited with ${code}`); })]);
    let port;
    for (let i = 0; i < 300 && !port; i++) {
      const file = `${profile}/DevToolsActivePort`;
      if (existsSync(file)) port = readFileSync(file, 'utf8').split('\n')[0].trim();
      if (!port) await delay(100);
    }
    if (!port) throw new Error('DevToolsActivePort was not written');
    const browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
    const context = browser.contexts()[0];
    const close = context.close.bind(context);
    // The default profile cannot be closed by Playwright: stop the process and wait for it.
    context.close = async () => { await close().catch(() => {}); await browser.close().catch(() => {}); child.kill(); await exited; };
    return { context, extensionId: id };
  } catch (error) {
    child.kill();
    throw new Error(`${error.message}\n${stderr}`);
  }
}

// Returns a persistent context with the unpacked extension loaded.
export async function launchExtension(profile, extension, { args = [], viewport, acceptDownloads = true, headless = true } = {}) {
  if (browserName === 'chrome') return (await launchBrandedChrome(profile, extension, { args, viewport, headless })).context;
  const context = await chromium.launchPersistentContext(profile, {
    ...(browserName === 'msedge' ? { channel: 'msedge' } : { executablePath: process.env.CHROMIUM_EXECUTABLE || chromium.executablePath() }),
    headless, viewport, acceptDownloads,
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`, '--no-first-run', ...args]
  });
  return context;
}

// Branded browsers run component extensions too: pick Tegin's service worker by its manifest.
export async function extensionWorker(context, timeout = 15000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    for (const worker of context.serviceWorkers()) {
      if (!worker.url().endsWith('/background.js')) continue;
      if (/Tegin/.test(await worker.evaluate(() => chrome.runtime.getManifest().name).catch(() => ''))) return worker;
    }
    await context.waitForEvent('serviceworker', { timeout: 500 }).catch(() => {});
  }
  throw new Error('Tegin service worker did not start');
}

export async function browserVersion(context) {
  const page = await context.newPage();
  try { return await page.evaluate(() => navigator.userAgent); } finally { await page.close(); }
}
