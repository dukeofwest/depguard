// Runs the CORS proof in real Chrome, at origin https://dukeofwest.github.io
// (hostname mapped to a local HTTPS server via --host-resolver-rules).
import https from 'node:https';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';

const DIR = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const PORT = 8443;
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const ORIGIN = 'https://dukeofwest.github.io';
const PAGE = `${ORIGIN}/depguard/`;

const html = fs.readFileSync(path.join(DIR, 'index.html'));
const server = https.createServer(
  {
    key: fs.readFileSync(path.join(DIR, 'key.pem')),
    cert: fs.readFileSync(path.join(DIR, 'cert.pem')),
  },
  (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  },
);
await new Promise((r) => server.listen(PORT, '127.0.0.1', r));
console.log(`local https server on ${PORT}, impersonating ${ORIGIN}`);

const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'dg-chrome-'));
const chrome = spawn(
  CHROME,
  [
    '--headless=new',
    '--remote-debugging-port=9222',
    `--host-resolver-rules=MAP dukeofwest.github.io 127.0.0.1:${PORT}`,
    '--ignore-certificate-errors',
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    'about:blank',
  ],
  { stdio: 'ignore' },
);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// wait for the devtools endpoint
let wsUrl = null;
for (let i = 0; i < 40 && !wsUrl; i++) {
  await sleep(250);
  try {
    const r = await fetch(`http://127.0.0.1:9222/json/new?url=${encodeURIComponent(PAGE)}`, {
      method: 'PUT',
    });
    if (r.ok) wsUrl = (await r.json()).webSocketDebuggerUrl;
  } catch {}
}
if (!wsUrl) {
  console.error('could not reach Chrome DevTools');
  chrome.kill();
  server.close();
  process.exit(1);
}
console.log(
  'chrome version:',
  await (await fetch('http://127.0.0.1:9222/json/version')).json().then((v) => v.Browser),
);

const ws = new WebSocket(wsUrl);
await new Promise((r) => ws.addEventListener('open', r, { once: true }));
let id = 0;
const pending = new Map();
ws.addEventListener('message', (e) => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) {
    pending.get(m.id)(m);
    pending.delete(m.id);
  }
});
const send = (method, params = {}) =>
  new Promise((res) => {
    const myId = ++id;
    pending.set(myId, res);
    ws.send(JSON.stringify({ id: myId, method, params }));
  });

await send('Page.enable');
await send('Page.navigate', { url: PAGE });

// poll until the page publishes its results
let results = null;
for (let i = 0; i < 80 && !results; i++) {
  await sleep(500);
  const r = await send('Runtime.evaluate', {
    expression: 'window.__RESULTS__ ? JSON.stringify(window.__RESULTS__) : null',
    returnByValue: true,
  });
  const v = r.result?.result?.value;
  if (v) results = JSON.parse(v);
}

ws.close();
chrome.kill();
server.close();

if (!results) {
  console.error('TIMED OUT - no results');
  process.exit(1);
}
fs.writeFileSync(path.join(DIR, 'results.json'), JSON.stringify(results, null, 2));

console.log('\n================ REAL BROWSER RESULTS ================');
for (const r of results) {
  if (r.note) {
    console.log(`page origin: ${r.origin}  (${r.href})\n`);
    continue;
  }
  if (r.label?.includes('JSON.parse')) {
    console.log(`  ${r.label}: ${r.packages} packages, ${r.bytes} bytes, parse ${r.parseMs} ms`);
    continue;
  }
  const mark = r.outcome === 'OK' ? 'OK  ' : 'FAIL';
  console.log(`[${mark}] ${r.label}`);
  if (r.outcome === 'OK') {
    console.log(
      `        status=${r.status} type=${r.type} bytes=${r.bodyBytes} ${r.ms}ms redirected=${r.redirected}`,
    );
    console.log(`        x-ratelimit-remaining readable: ${r.rateLimitRemaining ?? 'NOT EXPOSED'}`);
    if (
      r.finalUrl &&
      !r.finalUrl.startsWith('https://api.github.com/repos/expressjs/express/depend')
    )
      console.log(`        finalUrl=${r.finalUrl}`);
  } else {
    console.log(`        ${r.error}`);
  }
}
console.log('======================================================');
