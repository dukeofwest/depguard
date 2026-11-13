// Reviews the built artifact for the production security properties in
// MANDATORY_SECURITY_REQUIREMENT.md section I.
//
// Everything here is a property of the files that will actually be published, checked
// against those files - not against the configuration that was supposed to produce them.
// The distinction matters: a build option can be set correctly and still not take effect.
//
//   node tools/release-review.cjs dist/depguard/browser
const fs = require('fs');
const path = require('path');

const DIST = path.resolve(process.argv[2] ?? 'dist/depguard/browser');

let problems = 0;
const fail = (msg) => {
  console.log('  FAIL ' + msg);
  problems++;
};
const pass = (msg) => console.log('  ok   ' + msg);

if (!fs.existsSync(DIST)) {
  console.error(`No build found at ${DIST}. Run the production build first.`);
  process.exit(1);
}

function walk(dir, acc = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, acc);
    else acc.push(full);
  }
  return acc;
}

const files = walk(DIST);
const rel = (f) => path.relative(DIST, f).replace(/\\/g, '/');
const indexPath = path.join(DIST, 'index.html');
const index = fs.readFileSync(indexPath, 'utf8');
const scripts = files.filter((f) => f.endsWith('.js'));
const scriptText = scripts.map((f) => fs.readFileSync(f, 'utf8')).join('\n');

console.log(`=== Artifact: ${rel(indexPath)} and ${files.length - 1} other files ===`);

// ---- 1. No debug information ------------------------------------------------
console.log('\n=== Source maps and debug information ===');
const maps = files.filter((f) => f.endsWith('.map'));
if (maps.length > 0) {
  fail(`${maps.length} source map(s) would be published: ${maps.map(rel).join(', ')}`);
} else {
  pass('no source maps in the artifact');
}

const mapRefs = scripts.filter((f) =>
  /\/\/[#@]\s*sourceMappingURL=/.test(fs.readFileSync(f, 'utf8')),
);
if (mapRefs.length > 0) {
  fail(`source map reference left in ${mapRefs.map(rel).join(', ')}`);
} else {
  pass('no sourceMappingURL references');
}

// ---- 2. No development-only code -------------------------------------------
console.log('\n=== Development-only code ===');
// Angular's development-mode assertions are stripped by the production build; their
// presence means a development configuration was published by mistake.
for (const [marker, what] of [
  ['NG_DEV_MODE', 'Angular development-mode flag'],
  ['ngDevMode', 'Angular development-mode assertions'],
  ['@angular/compiler/src/jit', 'the JIT compiler'],
]) {
  if (scriptText.includes(marker)) {
    fail(`${what} is present in the bundle (${marker})`);
  } else {
    pass(`the bundle is free of ${what}`);
  }
}

// The live tests spend real API quota and must never be reachable from the bundle.
if (scriptText.includes('DEPGUARD_LIVE')) {
  fail('the live-test switch DEPGUARD_LIVE is present in the bundle');
} else {
  pass('no live-test switch in the bundle');
}

// ---- 3. No dangerous sinks or dynamic evaluation ---------------------------
console.log('\n=== Dynamic evaluation ===');
for (const [pattern, what] of [
  [/[^.\w]eval\s*\(/, 'a direct eval call'],
  [/new\s+Function\s*\(/, 'construction of a function from a string'],
  [/document\s*\.\s*write\s*\(/, 'document.write'],
]) {
  if (pattern.test(scriptText)) {
    fail(`the bundle contains ${what}`);
  } else {
    pass(`the bundle contains no ${what}`);
  }
}

// ---- 4. Content Security Policy ---------------------------------------------
console.log('\n=== Content Security Policy ===');
const cspMatch = /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i.exec(index);
if (cspMatch === null) {
  fail('no Content Security Policy is delivered by index.html');
} else {
  const policy = cspMatch[1];
  pass('a policy is delivered in index.html');

  const required = [
    "default-src 'none'",
    "script-src 'self'",
    "object-src 'none'",
    "form-action 'none'",
    "require-trusted-types-for 'script'",
  ];
  for (const directive of required) {
    if (policy.includes(directive)) pass(`declares ${directive}`);
    else fail(`policy is missing ${directive}`);
  }

  if (/script-src[^;]*'unsafe-(inline|eval)'/.test(policy)) {
    fail("script-src grants 'unsafe-inline' or 'unsafe-eval'");
  } else {
    pass('script-src grants no unsafe keyword');
  }

  if (/trusted-types[^;]*angular#unsafe-bypass/.test(policy)) {
    fail('the Trusted Types policy allows angular#unsafe-bypass');
  } else {
    pass('no Trusted Types bypass policy is allowed');
  }

  // connect-src must be exactly the three documented hosts.
  const connect = /connect-src ([^;]+)/.exec(policy);
  if (connect === null) {
    fail('policy declares no connect-src');
  } else {
    const sources = connect[1].trim().split(/\s+/);
    const expected = [
      "'self'",
      'https://api.github.com',
      'https://raw.githubusercontent.com',
      'https://api.osv.dev',
    ];
    const unexpected = sources.filter((s) => !expected.includes(s));
    if (unexpected.length > 0)
      fail(`connect-src allows unexpected sources: ${unexpected.join(', ')}`);
    else pass('connect-src is exactly the approved origins');
  }
}

// ---- 5. No inline script, and no external origins in the markup ------------
console.log('\n=== Markup ===');
const inlineScript = /<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/i.exec(index);
if (inlineScript !== null && inlineScript[0].replace(/<[^>]+>/g, '').trim().length > 0) {
  fail('index.html contains an inline script, which the policy would block');
} else {
  pass('no inline script in index.html');
}

// Every script and stylesheet must be a same-origin relative path.
for (const attr of [...index.matchAll(/<(?:script|link)[^>]*(?:src|href)="([^"]+)"/gi)]) {
  const url = attr[1];
  if (/^https?:\/\//i.test(url)) {
    fail(`index.html loads a cross-origin asset: ${url}`);
  } else if (url.startsWith('/')) {
    // An absolute path breaks the /depguard/ base href on a project page.
    fail(`index.html references an absolute path, which breaks the base href: ${url}`);
  }
}
pass('all assets are same-origin relative paths');

const baseHref = /<base href="([^"]*)"/.exec(index);
if (baseHref === null) fail('no base href');
else if (baseHref[1] !== '/depguard/') fail(`base href is "${baseHref[1]}", expected /depguard/`);
else pass('base href is /depguard/');

// ---- 6. No credentials or secrets ------------------------------------------
console.log('\n=== Secrets ===');
// Token-shaped values, not the word "token": DepGuard legitimately discusses tokens in
// its own user-facing copy, and matching on the word produced false positives before.
const secretPatterns = [
  [/gh[pousr]_[A-Za-z0-9]{16,}/, 'a GitHub token'],
  [/github_pat_[A-Za-z0-9_]{20,}/, 'a GitHub fine-grained token'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'a private key'],
  [/AKIA[0-9A-Z]{16}/, 'an AWS access key id'],
  [/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./, 'a JWT'],
];
const allText = files
  .filter((f) => /\.(js|css|html|json|txt|map)$/.test(f))
  .map((f) => fs.readFileSync(f, 'utf8'))
  .join('\n');
let secretFound = false;
for (const [pattern, what] of secretPatterns) {
  if (pattern.test(allText)) {
    fail(`the artifact appears to contain ${what}`);
    secretFound = true;
  }
}
if (!secretFound) pass('no credential-shaped values in the artifact');

// ---- 7. Only expected external origins anywhere in the bundle --------------
console.log('\n=== External origins reachable from the bundle ===');
const origins = [
  ...new Set([...allText.matchAll(/https:\/\/[a-z0-9.-]+/gi)].map((m) => m[0].toLowerCase())),
];
// Hosts that appear as text a human reads - documentation links, the advisory and
// repository links the report renders - rather than as request destinations.
const permitted = new Set([
  'https://api.github.com',
  'https://raw.githubusercontent.com',
  'https://api.osv.dev',
  'https://github.com',
  'https://osv.dev',
  'https://dukeofwest.github.io',
  'https://docs.github.com',
  'https://www.w3.org',
  // Angular embeds documentation links in its runtime error messages, for example
  // https://angular.dev/errors/NG0200. They are text in an exception string, never a
  // request destination, and connect-src would refuse a request to them in any case.
  'https://angular.dev',
]);
const unknown = origins.filter((o) => !permitted.has(o));
if (unknown.length > 0) {
  fail(`unexpected origin(s) in the bundle: ${unknown.join(', ')}`);
} else {
  pass(`origins limited to the ${permitted.size} reviewed hosts`);
}

// ---- 8. Size, so a regression in the budget is visible ---------------------
console.log('\n=== Size ===');
const total = files.reduce((sum, f) => sum + fs.statSync(f).size, 0);
console.log(`  bundle total: ${(total / 1024).toFixed(1)} kB across ${files.length} files`);

console.log(
  problems === 0
    ? '\nProduction artifact review passed.'
    : `\n${problems} problem(s) in the production artifact.`,
);
process.exit(problems === 0 ? 0 : 1);
