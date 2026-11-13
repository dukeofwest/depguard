// Captures README screenshots from the built application in real Chrome.
//
//   npm run build -- --configuration github-pages
//   node tools/screenshot.mjs dist/depguard/browser docs/screenshots owner/repo
//
// Capturing the dashboard runs a real analysis, so it spends about 8 of the 60
// unauthenticated GitHub requests available per hour. The landing and mobile shots cost
// nothing.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { findChrome } from './chrome.mjs';
import { chromeArguments, findChrome } from './chrome.mjs';

const DIST = path.resolve(process.argv[2] ?? 'dist/depguard/browser');
const OUT = path.resolve(process.argv[3] ?? 'docs/screenshots');
const TARGET = process.argv[4] ?? 'expressjs/express';
const PORT = 8103;
const CHROME = findChrome();

fs.mkdirSync(OUT, { recursive: true });

const types = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.ico': 'image/x-icon',
};

const server = http.createServer((req, res) => {
  let rel = decodeURIComponent((req.url ?? '/').split('?')[0]);
  rel = rel.startsWith('/depguard/') ? rel.slice('/depguard/'.length) : rel.slice(1);
  if (rel === '') rel = 'index.html';
  const file = path.join(DIST, rel);
  if (!file.startsWith(DIST) || !fs.existsSync(file)) {
    res.writeHead(404);
    res.end('not found');
    return;
  }
  res.writeHead(200, { 'Content-Type': types[path.extname(file)] ?? 'application/octet-stream' });
  res.end(fs.readFileSync(file));
});
await new Promise((resolve) => server.listen(PORT, '127.0.0.1', resolve));

const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'dg-shot-'));
const chrome = spawn(
  CHROME,
  [
    '--headless=new',
    '--remote-debugging-port=9251',
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--hide-scrollbars',
    'about:blank',
  ],
  { stdio: 'ignore' },
);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let target = null;
for (let i = 0; i < 40 && target === null; i++) {
  await sleep(250);
  try {
    const res = await fetch('http://127.0.0.1:9251/json/new?url=about:blank', { method: 'PUT' });
    if (res.ok) target = await res.json();
  } catch {
    // still starting
  }
}
if (target === null) {
  console.error('could not reach Chrome DevTools');
  chrome.kill();
  server.close();
  process.exit(1);
}

const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve) => ws.addEventListener('open', resolve, { once: true }));

let id = 0;
const pending = new Map();
ws.addEventListener('message', (event) => {
  const message = JSON.parse(event.data);
  if (message.id !== undefined && pending.has(message.id)) {
    pending.get(message.id)(message);
    pending.delete(message.id);
  }
});
const send = (method, params = {}) =>
  new Promise((resolve) => {
    const myId = ++id;
    pending.set(myId, resolve);
    ws.send(JSON.stringify({ id: myId, method, params }));
  });
const evaluate = async (expression) => {
  const result = await send('Runtime.evaluate', { expression, returnByValue: true });
  return result.result?.result?.value;
};

async function capture(name, { width, height, mobile = false, fullPage = false }) {
  await send('Emulation.setDeviceMetricsOverride', {
    width,
    height,
    deviceScaleFactor: 2,
    mobile,
  });
  await sleep(700);

  const options = { format: 'png' };
  if (fullPage) {
    options.captureBeyondViewport = true;
    const metrics = await send('Page.getLayoutMetrics');
    const content = metrics.result?.cssContentSize;
    if (content) {
      options.clip = {
        x: 0,
        y: 0,
        width,
        height: Math.min(content.height, 4000),
        scale: 1,
      };
    }
  }

  const shot = await send('Page.captureScreenshot', options);
  const data = shot.result?.data;
  if (typeof data !== 'string') {
    console.log(`  FAILED: ${name}`);
    return;
  }
  const file = path.join(OUT, `${name}.png`);
  fs.writeFileSync(file, Buffer.from(data, 'base64'));
  const kb = Math.round(fs.statSync(file).size / 1024);
  console.log(`  ${name}.png (${kb} kB)`);
}

await send('Runtime.enable');
await send('Page.enable');
await send('Page.navigate', { url: `http://127.0.0.1:${PORT}/depguard/` });

await sleep(2500);

console.log('\nCapturing screenshots...');
await capture('landing', { width: 1280, height: 860 });

// Run a real analysis for the dashboard shot.
const canScan = await evaluate('!document.querySelector(".search__button")?.disabled');
if (!canScan) {
  console.log('\nSkipping dashboard screenshots: the GitHub request budget is exhausted.');
} else {
  await evaluate(`
    (() => {
      const input = document.querySelector('#repository-url');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(input, ${JSON.stringify(TARGET)});
      input.dispatchEvent(new Event('input', { bubbles: true }));
    })()
  `);
  await evaluate('document.querySelector(".search__button").click()');
  await sleep(500);
  await capture('progress', { width: 1280, height: 620 });

  let ready = false;
  for (let i = 0; i < 60 && !ready; i++) {
    await sleep(1000);
    ready = await evaluate('!!document.querySelector("dg-dashboard")');
  }

  if (!ready) {
    console.log('  analysis did not complete; skipping dashboard shots');
  } else {
    await capture('dashboard', { width: 1280, height: 900 });

    // The vulnerabilities tab, which carries the honesty messaging.
    await evaluate(`
      (() => {
        const tabs = Array.from(document.querySelectorAll('.tabs__tab'));
        tabs.find((t) => t.textContent.includes('Vulnerabilities'))?.click();
      })()
    `);
    await sleep(500);
    await evaluate('document.querySelector(".detail")?.scrollIntoView({ block: "start" })');
    await sleep(400);
    await capture('vulnerabilities', { width: 1280, height: 760 });

    // The dependency inventory with its "Checked" column.
    await evaluate(`
      (() => {
        const tabs = Array.from(document.querySelectorAll('.tabs__tab'));
        tabs.find((t) => t.textContent.includes('Dependencies'))?.click();
      })()
    `);
    await sleep(500);
    await evaluate('document.querySelector(".detail")?.scrollIntoView({ block: "start" })');
    await sleep(400);
    await capture('dependencies', { width: 1280, height: 860 });

    // Mobile, to show the table becomes cards rather than shrinking.
    await evaluate('window.scrollTo(0, 0)');
    await capture('mobile', { width: 390, height: 844, mobile: true });
  }
}

ws.close();
chrome.kill();
server.close();
console.log(`\nSaved to ${OUT}`);
