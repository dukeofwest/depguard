// Loads the built GitHub Pages bundle in real Chrome and reports console errors,
// rendered content and a mobile-width layout check.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';

const DIST = path.resolve(process.argv[2]);
const PORT = 8099;
const types = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.ico': 'image/x-icon',
};

const server = http.createServer((req, res) => {
  let rel = decodeURIComponent(req.url.split('?')[0]);
  rel = rel.startsWith('/depguard/') ? rel.slice('/depguard/'.length) : rel.slice(1);
  if (rel === '') rel = 'index.html';
  const file = path.join(DIST, rel);
  if (!file.startsWith(DIST) || !fs.existsSync(file)) {
    res.writeHead(404);
    res.end('nf');
    return;
  }
  res.writeHead(200, { 'Content-Type': types[path.extname(file)] ?? 'application/octet-stream' });
  res.end(fs.readFileSync(file));
});
await new Promise((r) => server.listen(PORT, '127.0.0.1', r));

const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'dg-smoke-'));
const chrome = spawn(
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  [
    '--headless=new',
    '--remote-debugging-port=9224',
    '--user-data-dir=' + profile,
    '--no-first-run',
    '--no-default-browser-check',
    'about:blank',
  ],
  { stdio: 'ignore' },
);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let t = null;
for (let i = 0; i < 40 && !t; i++) {
  await sleep(250);
  try {
    const r = await fetch('http://127.0.0.1:9224/json/new?url=about:blank', { method: 'PUT' });
    if (r.ok) t = await r.json();
  } catch {}
}
const ws = new WebSocket(t.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r, { once: true }));
let id = 0;
const pend = new Map();
const consoleErrors = [];
const failedRequests = [];
ws.addEventListener('message', (e) => {
  const m = JSON.parse(e.data);
  if (m.method === 'Runtime.consoleAPICalled' && ['error', 'warning'].includes(m.params.type))
    consoleErrors.push(
      m.params.type + ': ' + m.params.args.map((a) => a.value ?? a.description).join(' '),
    );
  if (m.method === 'Runtime.exceptionThrown')
    consoleErrors.push('uncaught: ' + m.params.exceptionDetails.text);
  if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error')
    failedRequests.push(m.params.entry.text);
  if (m.id && pend.has(m.id)) {
    pend.get(m.id)(m);
    pend.delete(m.id);
  }
});
const send = (method, params = {}) =>
  new Promise((res) => {
    const i = ++id;
    pend.set(i, res);
    ws.send(JSON.stringify({ id: i, method, params }));
  });
const ev = async (expr) =>
  (await send('Runtime.evaluate', { expression: expr, returnByValue: true })).result?.result?.value;

await send('Runtime.enable');
await send('Log.enable');
await send('Page.enable');
await send('Page.navigate', { url: `http://127.0.0.1:${PORT}/depguard/` });
await sleep(3500);

console.log('--- desktop (1280px) ---');
console.log('title      :', await ev('document.title'));
console.log('h1         :', await ev('document.querySelector("h1")?.textContent?.trim()'));
console.log('app mounted:', await ev('!!document.querySelector("dg-root .shell")'));
console.log('footer     :', await ev('!!document.querySelector("footer")'));
console.log(
  'skip link  :',
  await ev('document.querySelector(".dg-skip-link")?.textContent?.trim()'),
);
console.log('bg colour  :', await ev('getComputedStyle(document.body).backgroundColor'));
console.log(
  'tokens live:',
  await ev('getComputedStyle(document.documentElement).getPropertyValue("--color-accent").trim()'),
);

// Mobile: 375px wide, assert no horizontal overflow (spec §11.5).
await send('Emulation.setDeviceMetricsOverride', {
  width: 375,
  height: 812,
  deviceScaleFactor: 2,
  mobile: true,
});
await sleep(600);
console.log('--- mobile (375px) ---');
console.log(
  'scrollWidth:',
  await ev('document.documentElement.scrollWidth'),
  'clientWidth:',
  await ev('document.documentElement.clientWidth'),
);
console.log(
  'no h-overflow:',
  await ev('document.documentElement.scrollWidth <= document.documentElement.clientWidth'),
);

console.log('--- diagnostics ---');
console.log('console errors/warnings:', consoleErrors.length ? consoleErrors : 'none');
console.log('failed requests:', failedRequests.length ? failedRequests : 'none');

ws.close();
chrome.kill();
server.close();
