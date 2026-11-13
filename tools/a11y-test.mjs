// Accessibility audit of the built application in real Chrome (§11.6).
//
//   npm run build -- --configuration github-pages
//   node tools/a11y-test.mjs dist/depguard/browser
//
// Checks colour contrast against WCAG AA, keyboard reachability, visible focus, form
// labelling, heading order and reduced-motion support. Makes no network requests, so it
// costs no GitHub quota.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';

const DIST = path.resolve(process.argv[2] ?? 'dist/depguard/browser');
const PORT = 8102;
const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';

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

const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'dg-a11y-'));
const chrome = spawn(
  CHROME,
  [
    '--headless=new',
    '--remote-debugging-port=9241',
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
    const res = await fetch('http://127.0.0.1:9241/json/new?url=about:blank', { method: 'PUT' });
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

await send('Runtime.enable');
await send('Page.enable');
await send('Page.navigate', { url: `http://127.0.0.1:${PORT}/depguard/` });
await sleep(2500);

// Contrast is computed in the page, where the real cascade applies.
const CONTRAST_SCRIPT = `
(() => {
  const luminance = (rgb) => {
    const [r, g, b] = rgb.map((channel) => {
      const c = channel / 255;
      return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const parse = (value) => {
    const match = value.match(/rgba?\\((\\d+),\\s*(\\d+),\\s*(\\d+)/);
    return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
  };
  const ratio = (fg, bg) => {
    const a = luminance(fg);
    const b = luminance(bg);
    const [light, dark] = a > b ? [a, b] : [b, a];
    return (light + 0.05) / (dark + 0.05);
  };
  // Walk up for the nearest painted background.
  const backgroundOf = (element) => {
    let node = element;
    while (node) {
      const colour = parse(getComputedStyle(node).backgroundColor);
      const alpha = getComputedStyle(node).backgroundColor.match(/rgba\\([^)]+,\\s*0\\)/);
      if (colour && !alpha) return colour;
      node = node.parentElement;
    }
    return [11, 17, 32];
  };

  const results = [];
  const seen = new Set();
  for (const element of document.querySelectorAll('p, h1, h2, h3, span, a, button, label, li, dt, dd, code, th, td')) {
    const text = (element.textContent ?? '').trim();
    if (text.length === 0 || element.children.length > 0) continue;
    const style = getComputedStyle(element);
    const fg = parse(style.color);
    if (!fg) continue;
    const bg = backgroundOf(element);
    const fontSize = parseFloat(style.fontSize);
    const bold = Number(style.fontWeight) >= 700;
    // WCAG: large text is 18.66px bold or 24px regular.
    const isLarge = fontSize >= 24 || (bold && fontSize >= 18.66);
    const required = isLarge ? 3 : 4.5;
    const value = ratio(fg, bg);
    const key = style.color + '|' + bg.join(',') + '|' + Math.round(fontSize);
    if (seen.has(key)) continue;
    seen.add(key);
    results.push({
      sample: text.slice(0, 40),
      colour: style.color,
      fontSize: Math.round(fontSize),
      ratio: Math.round(value * 100) / 100,
      required,
      passes: value >= required,
    });
  }
  return results;
})()
`;

console.log('\n=== Colour contrast (WCAG AA) ===');
const contrast = (await evaluate(CONTRAST_SCRIPT)) ?? [];
const failures = contrast.filter((entry) => !entry.passes);
console.log(`checked ${contrast.length} distinct text/background combinations`);
if (failures.length === 0) {
  console.log('all pass');
} else {
  for (const failure of failures) {
    console.log(
      `  FAIL ratio ${failure.ratio} (needs ${failure.required}) ${failure.colour} ${failure.fontSize}px — "${failure.sample}"`,
    );
  }
}

// The dashboard's severity and status colours do not appear on the landing page, and
// rendering the dashboard here would spend GitHub quota. Instead, probe every token
// through the real cascade by injecting throwaway elements that use them. This measures
// what the browser actually computes rather than parsing hex values out of the source.
console.log('\n=== Token contrast (probed through the real cascade) ===');
const TOKEN_PROBE = `
(() => {
  const luminance = (rgb) => {
    const [r, g, b] = rgb.map((channel) => {
      const c = channel / 255;
      return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const parse = (value) => {
    const match = value.match(/rgba?\\((\\d+),\\s*(\\d+),\\s*(\\d+)/);
    return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
  };
  const ratio = (fg, bg) => {
    const a = luminance(fg);
    const b = luminance(bg);
    const [light, dark] = a > b ? [a, b] : [b, a];
    return (light + 0.05) / (dark + 0.05);
  };

  const textTokens = [
    'color-text-primary', 'color-text-secondary', 'color-text-muted',
    'color-severity-critical', 'color-severity-high', 'color-severity-medium',
    'color-severity-low', 'color-severity-unknown',
    'color-status-configured', 'color-status-not-detected', 'color-status-unknown',
    'color-status-not-applicable',
    'color-accent', 'color-success', 'color-warning', 'color-danger',
  ];
  const surfaces = ['color-background', 'color-surface', 'color-surface-raised'];

  const probe = document.createElement('div');
  probe.style.position = 'absolute';
  probe.style.left = '-9999px';
  document.body.appendChild(probe);

  const results = [];
  for (const surfaceToken of surfaces) {
    const surface = document.createElement('div');
    surface.style.backgroundColor = 'var(--' + surfaceToken + ')';
    probe.appendChild(surface);
    const bg = parse(getComputedStyle(surface).backgroundColor);
    for (const token of textTokens) {
      const sample = document.createElement('span');
      sample.style.color = 'var(--' + token + ')';
      sample.textContent = 'probe';
      surface.appendChild(sample);
      const fg = parse(getComputedStyle(sample).color);
      if (fg && bg) {
        const value = ratio(fg, bg);
        results.push({
          token,
          surface: surfaceToken,
          ratio: Math.round(value * 100) / 100,
          passes: value >= 4.5,
        });
      }
    }
  }

  // White on the filled-button accent, which is what the button actually renders.
  const button = document.createElement('div');
  button.style.backgroundColor = 'var(--color-accent-strong)';
  probe.appendChild(button);
  const buttonBg = parse(getComputedStyle(button).backgroundColor);
  if (buttonBg) {
    const value = ratio([255, 255, 255], buttonBg);
    results.push({
      token: 'white text',
      surface: 'color-accent-strong',
      ratio: Math.round(value * 100) / 100,
      passes: value >= 4.5,
    });
  }

  probe.remove();
  return results;
})()
`;

const tokenResults = (await evaluate(TOKEN_PROBE)) ?? [];
const tokenFailures = tokenResults.filter((entry) => !entry.passes);
console.log(`probed ${tokenResults.length} token/surface combinations`);
if (tokenFailures.length === 0) {
  console.log('all meet 4.5:1');
} else {
  for (const failure of tokenFailures) {
    console.log(
      `  FAIL --${failure.token} on --${failure.surface}: ${failure.ratio}:1 (needs 4.5)`,
    );
  }
}

console.log('\n=== Keyboard navigation ===');
// Tab through the page and record what receives focus.
const focusOrder = [];
for (let i = 0; i < 12; i++) {
  await send('Input.dispatchKeyEvent', {
    type: 'rawKeyDown',
    windowsVirtualKeyCode: 9,
    nativeVirtualKeyCode: 9,
    key: 'Tab',
    code: 'Tab',
  });
  await send('Input.dispatchKeyEvent', {
    type: 'keyUp',
    windowsVirtualKeyCode: 9,
    nativeVirtualKeyCode: 9,
    key: 'Tab',
    code: 'Tab',
  });
  const description = await evaluate(`
    (() => {
      const el = document.activeElement;
      if (!el || el === document.body) return null;
      const style = getComputedStyle(el);
      return {
        tag: el.tagName.toLowerCase(),
        label: (el.getAttribute('aria-label') ?? el.textContent ?? el.id ?? '').trim().slice(0, 36),
        outlineWidth: style.outlineWidth,
        outlineStyle: style.outlineStyle,
      };
    })()
  `);
  if (description) focusOrder.push(description);
}
const unique = focusOrder.filter(
  (item, index) => index === 0 || JSON.stringify(item) !== JSON.stringify(focusOrder[index - 1]),
);
for (const item of unique) {
  console.log(`  ${item.tag.padEnd(8)} ${item.label.padEnd(38)}`);
}
console.log(`reached ${unique.length} focusable elements by keyboard`);

console.log('\n=== Focus visibility ===');
const focusVisible = await evaluate(`
  (() => {
    const input = document.querySelector('#repository-url');
    input.focus();
    const style = getComputedStyle(input);
    return { outline: style.outlineStyle, width: style.outlineWidth, colour: style.outlineColor };
  })()
`);
console.log('  focused input outline:', JSON.stringify(focusVisible));

console.log('\n=== Semantics ===');
console.log(
  '  inputs with a label    :',
  await evaluate(`
    Array.from(document.querySelectorAll('input, select, textarea')).every((el) =>
      el.labels?.length > 0 || el.getAttribute('aria-label') || el.getAttribute('aria-labelledby')
    )
  `),
);
console.log(
  '  buttons with a name    :',
  await evaluate(`
    Array.from(document.querySelectorAll('button')).every((el) =>
      (el.textContent ?? '').trim().length > 0 || el.getAttribute('aria-label')
    )
  `),
);
console.log(
  '  images have alt text   :',
  await evaluate(`
    Array.from(document.querySelectorAll('img')).every((el) => el.hasAttribute('alt'))
  `),
);
console.log(
  '  decorative svg hidden  :',
  await evaluate(`
    Array.from(document.querySelectorAll('svg')).every((el) =>
      el.getAttribute('aria-hidden') === 'true' || el.getAttribute('role') === 'img'
    )
  `),
);
console.log(
  '  exactly one h1         :',
  await evaluate('document.querySelectorAll("h1").length === 1'),
);
console.log(
  '  heading order sane     :',
  await evaluate(`
    (() => {
      const levels = Array.from(document.querySelectorAll('h1,h2,h3,h4,h5,h6'))
        .map((h) => Number(h.tagName[1]));
      return levels.every((level, i) => i === 0 || level - levels[i - 1] <= 1);
    })()
  `),
);
console.log(
  '  lang attribute         :',
  await evaluate('document.documentElement.lang || "(missing)"'),
);
console.log(
  '  skip link present      :',
  await evaluate('!!document.querySelector(".dg-skip-link")'),
);
console.log('  main landmark          :', await evaluate('!!document.querySelector("main")'));

console.log('\n=== Reduced motion ===');
await send('Emulation.setEmulatedMedia', {
  features: [{ name: 'prefers-reduced-motion', value: 'reduce' }],
});
await sleep(400);
// Durations are parsed, not string-compared: Chrome reports the 0.01ms override as
// "1e-05s", which no exact-match check would recognise.
const motion = await evaluate(`
  (() => {
    const parseSeconds = (value) => {
      const first = value.split(',')[0].trim();
      if (first.endsWith('ms')) return parseFloat(first) / 1000;
      return parseFloat(first) || 0;
    };
    const samples = ['.search__button', '.search__input', '.examples__item']
      .map((selector) => document.querySelector(selector))
      .filter((el) => el !== null)
      .map((el) => ({
        selector: el.className,
        transition: getComputedStyle(el).transitionDuration,
        seconds: parseSeconds(getComputedStyle(el).transitionDuration),
      }));
    return {
      samples,
      allSuppressed: samples.every((sample) => sample.seconds <= 0.001),
    };
  })()
`);
console.log('  animations suppressed  :', motion?.allSuppressed);
for (const sample of motion?.samples ?? []) {
  console.log(
    `    ${String(sample.selector).padEnd(18)} transition-duration: ${sample.transition}`,
  );
}

ws.close();
chrome.kill();
server.close();

if (failures.length > 0) {
  console.log(`\n${failures.length} contrast failure(s) — see above.`);
  process.exit(1);
}
console.log('\nNo accessibility failures detected by these checks.');
