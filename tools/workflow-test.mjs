// Drives the full user workflow in real Chrome against the live GitHub and OSV APIs:
// type a repository, run the analysis, and verify the dashboard renders real data.
//
//   npm run build -- --configuration github-pages
//   node tools/workflow-test.mjs dist/depguard/browser owner/repo
//
// Spends roughly 8 of the 60 unauthenticated GitHub requests available per hour.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { findChrome } from './chrome.mjs';

const DIST = path.resolve(process.argv[2] ?? 'dist/depguard/browser');
const TARGET = process.argv[3] ?? 'expressjs/express';
const PORT = 8101;
const CHROME = findChrome();

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

const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'dg-workflow-'));
const chrome = spawn(
  CHROME,
  [
    '--headless=new',
    '--remote-debugging-port=9231',
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    'about:blank',
  ],
  { stdio: 'ignore' },
);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let target = null;
for (let i = 0; i < 40 && target === null; i++) {
  await sleep(250);
  try {
    const res = await fetch('http://127.0.0.1:9231/json/new?url=about:blank', { method: 'PUT' });
    if (res.ok) target = await res.json();
  } catch {
    // Chrome is still starting.
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
const consoleIssues = [];
ws.addEventListener('message', (event) => {
  const message = JSON.parse(event.data);
  if (
    message.method === 'Runtime.consoleAPICalled' &&
    ['error', 'warning'].includes(message.params.type)
  ) {
    consoleIssues.push(
      `${message.params.type}: ${message.params.args.map((a) => a.value ?? a.description).join(' ')}`,
    );
  }
  if (message.method === 'Runtime.exceptionThrown') {
    consoleIssues.push(`uncaught: ${message.params.exceptionDetails.text}`);
  }
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
  const result = await send('Runtime.evaluate', {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  return result.result?.result?.value;
};

await send('Runtime.enable');
await send('Page.enable');
await send('Page.navigate', { url: `http://127.0.0.1:${PORT}/depguard/` });
await sleep(2500);

console.log(`\n=== Workflow: analysing ${TARGET} ===`);
console.log('landing rendered    :', await evaluate('!!document.querySelector("#repository-url")'));

const budget = await evaluate(
  'document.querySelector(".budget__value")?.textContent ?? "(not yet known)"',
);
console.log('budget shown        :', budget);

// Each run of this test spends about 8 of the 60 unauthenticated GitHub requests
// available per hour. When the budget is gone the Analyse button is correctly disabled,
// and the app stays on the landing page — so bail out loudly rather than reporting
// landing-page elements as if they were a dashboard.
const canScan = await evaluate('!document.querySelector(".search__button")?.disabled');
if (!canScan) {
  console.log('\nSTOPPED: the GitHub hourly request budget is exhausted, so no analysis can run.');
  console.log(
    'landing message     :',
    await evaluate('document.querySelector(".search__error strong")?.textContent?.trim()'),
  );
  console.log('This is the intended behaviour (ADR-0004), not a failure of the application.');
  ws.close();
  chrome.kill();
  server.close();
  process.exit(0);
}

// Type into the input the way a user would, so Angular's (input) handler fires.
await evaluate(`
  (() => {
    const input = document.querySelector('#repository-url');
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, ${JSON.stringify(TARGET)});
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return input.value;
  })()
`);

await evaluate('document.querySelector(".search__button").click()');
await sleep(600);

const stage = await evaluate(
  'document.querySelector(".stage--active .stage__label")?.textContent?.trim()',
);
console.log('progress stage      :', stage ?? '(already finished)');

// Wait for the dashboard, or a reported failure.
let settled = false;
for (let i = 0; i < 60 && !settled; i++) {
  await sleep(1000);
  settled = await evaluate(
    '!!document.querySelector("dg-dashboard") || !!document.querySelector(".message")',
  );
}

const failure = await evaluate('document.querySelector(".message__title")?.textContent?.trim()');
if (failure) {
  console.log('\nRESULT: analysis reported a failure:', failure);
  console.log(
    'detail:',
    await evaluate('document.querySelector(".message__body")?.textContent?.trim()'),
  );
} else {
  console.log('\n--- dashboard ---');
  console.log(
    'repository     :',
    await evaluate('document.querySelector(".repo__name")?.textContent?.trim()'),
  );
  console.log(
    'score          :',
    await evaluate('document.querySelector(".ring__score")?.textContent?.trim() ?? "(no score)"'),
  );
  console.log(
    'band           :',
    await evaluate('document.querySelector(".overall__band")?.textContent?.trim() ?? "-"'),
  );
  console.log(
    'coverage       :',
    await evaluate('document.querySelector(".coverage__value")?.textContent?.trim()'),
  );
  console.log('category cards :', await evaluate('document.querySelectorAll(".category").length'));
  console.log(
    'unscored cards :',
    await evaluate('document.querySelectorAll(".category--unscored").length'),
  );
  console.log(
    'recommendations:',
    await evaluate('document.querySelectorAll(".recommendation").length'),
  );
  console.log(
    'disclaimer     :',
    await evaluate('!!document.querySelector(".overall__disclaimer")'),
  );

  // The wording matters as much as the number: a headline score next to an unassessed
  // security category must be accompanied by an explicit statement of what is unknown.
  console.log('\n--- what the user is actually told ---');
  console.log(
    'explanation    :',
    await evaluate('document.querySelector(".overall__explanation")?.textContent?.trim()'),
  );
  console.log(
    'needs attention:',
    await evaluate(
      'Array.from(document.querySelectorAll(".findings__title")).map((n) => n.textContent.trim())',
    ),
  );

  console.log('\n--- category scores ---');
  const categories = await evaluate(`
    Array.from(document.querySelectorAll('.category')).map((card) => ({
      label: card.querySelector('.category__label')?.textContent?.trim(),
      score: card.querySelector('.category__score')?.textContent?.trim()
        ?? card.querySelector('.category__insufficient')?.textContent?.trim(),
    }))
  `);
  for (const category of categories ?? []) {
    console.log(`  ${(category.label ?? '').padEnd(34)} ${category.score ?? ''}`);
  }

  // Exercise each tab, so a template error in any panel surfaces here.
  console.log('\n--- tabs ---');
  const tabCount = await evaluate('document.querySelectorAll(".tabs__tab").length');
  for (let i = 0; i < tabCount; i++) {
    const label = await evaluate(
      `document.querySelectorAll('.tabs__tab')[${i}].textContent.trim()`,
    );
    await evaluate(`document.querySelectorAll('.tabs__tab')[${i}].click()`);
    await sleep(350);
    const populated = await evaluate(
      '(document.querySelector(".panel")?.textContent ?? "").trim().length > 40',
    );
    console.log(`  ${label.padEnd(16)} renders content: ${populated}`);
  }

  // Mobile layout must not overflow horizontally (§11.5).
  await send('Emulation.setDeviceMetricsOverride', {
    width: 375,
    height: 812,
    deviceScaleFactor: 2,
    mobile: true,
  });
  await sleep(600);
  console.log('\n--- mobile (375px) ---');
  console.log(
    'no h-overflow  :',
    await evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth'),
  );
}

console.log('\n--- diagnostics ---');
console.log('console errors/warnings:', consoleIssues.length === 0 ? 'none' : consoleIssues);

ws.close();
chrome.kill();
server.close();
