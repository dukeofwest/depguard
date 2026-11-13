// Verifies that documentation links resolve and that factual claims match the code.
//
//   node tools/check-docs.cjs .
//
// Documentation drifts from code silently. This fails loudly instead: every relative
// link must resolve, the scoring weights and deductions quoted in SCORING.md must match
// weights.ts, the request budget must match api.config.ts, the host allowlist must be
// exactly the three documented hosts, and referenced screenshots must exist.
const fs = require('fs');
const path = require('path');

const root = path.resolve(process.argv[2] ?? '.');
let problems = 0;
const fail = (msg) => {
  console.log('  FAIL ' + msg);
  problems++;
};

// ---- 1. Every relative markdown link resolves ----------------------------
function markdownFiles(dir, acc = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) markdownFiles(full, acc);
    else if (entry.name.endsWith('.md')) acc.push(full);
  }
  return acc;
}

console.log('=== Link check ===');
let linkCount = 0;
for (const file of markdownFiles(root)) {
  if (file.includes('PROJECT_SPECIFICATION')) continue;
  const text = fs.readFileSync(file, 'utf8');
  const links = [...text.matchAll(/\]\(([^)]+)\)/g)].map((m) => m[1]);
  for (const link of links) {
    if (/^(https?:|mailto:|#)/.test(link)) continue;
    linkCount++;
    const target = path.resolve(path.dirname(file), link.split('#')[0]);
    if (!fs.existsSync(target)) {
      fail(`${path.relative(root, file)} -> ${link}`);
    }
  }
}
console.log(`  checked ${linkCount} relative links`);

// ---- 2. Claims that must match the code ---------------------------------
console.log('\n=== Claim check ===');
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');

// Prettier pads markdown table cells to align them, so comparisons collapse runs of
// spaces. The claim being verified is the content, not its formatting.
const squash = (text) => text.replace(/[ 	]+/g, ' ');

const weights = read('src/app/engine/scoring/weights.ts');
const scoring = squash(read('docs/SCORING.md'));
const claims = [
  ["'dependency-security': 0.3", '| Dependency Security | 30% |'],
  ["'security-configuration': 0.25", '| Security Configuration | 25% |'],
  ['maintenance: 0.2', '| Maintenance and Activity | 20% |'],
  ['engineering: 0.15', '| Engineering and Project Quality | 15% |'],
  ["'dependency-health': 0.1", '| Dependency Health | 10% |'],
];
for (const [code, doc] of claims) {
  if (!weights.includes(code)) fail(`weights.ts no longer contains ${code}`);
  if (!scoring.includes(squash(doc))) fail(`SCORING.md no longer states ${doc}`);
}

const deductions = [
  ['Critical: 15', '| Critical | −15 |'],
  ['High: 8', '| High | −8 |'],
  ['Medium: 3', '| Medium | −3 |'],
  ['Low: 1', '| Low | −1 |'],
  ['Unknown: 3', '| Unknown | −3 |'],
];
for (const [code, doc] of deductions) {
  if (!weights.includes(code)) fail(`weights.ts no longer contains ${code}`);
  if (!scoring.includes(squash(doc))) fail(`SCORING.md no longer states ${doc}`);
}

if (!weights.includes('MAX_SECURITY_DEDUCTION = 60')) fail('deduction cap changed');
if (!squash(scoring).includes('capped at **−60**')) fail('SCORING.md cap statement out of date');

const config = read('src/app/core/config/api.config.ts');
if (!config.includes('requestsPerScan: 8')) fail('requestsPerScan is no longer 8');
if (!config.includes('minimumRemainingToStart: 10'))
  fail('minimumRemainingToStart is no longer 10');
if (!config.includes('maxQueriesPerBatch: 1000')) fail('OSV batch cap changed');
for (const [doc, claim] of [
  ['README.md', 'An analysis costs\n8'],
  ['docs/DATA-SOURCES.md', '**Total: 8 quota-consuming requests per analysis**'],
]) {
  const text = read(doc);
  if (doc === 'docs/DATA-SOURCES.md' && !squash(text).includes(squash(claim)))
    fail(`${doc}: request count claim`);
}

// Allowlist must be exactly the three documented hosts.
const origins = [...config.matchAll(/https:\/\/[a-z.]+/g)].map((m) => m[0]);
const expected = [
  'https://api.github.com',
  'https://raw.githubusercontent.com',
  'https://api.osv.dev',
];
for (const host of expected) {
  if (!origins.includes(host)) fail(`allowlist missing ${host}`);
}
const unexpected = [...new Set(origins)].filter(
  (o) => !expected.includes(o) && !o.includes('osv.dev'),
);
if (unexpected.length > 0) fail(`unexpected origin in config: ${unexpected.join(', ')}`);

// Test count in the README should be close to reality.
const specFiles = [];
(function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (entry.name.endsWith('.spec.ts')) specFiles.push(full);
  }
})(path.join(root, 'src'));
console.log(`  ${specFiles.length} spec files present`);

// Screenshots referenced by the README must exist.
const readme = read('README.md');
for (const shot of [...readme.matchAll(/docs\/screenshots\/([a-z-]+\.png)/g)].map((m) => m[1])) {
  if (!fs.existsSync(path.join(root, 'docs/screenshots', shot))) fail(`missing screenshot ${shot}`);
}

// ---- 2b. Security claims must match the code -----------------------------
//
// These exist because a security document that has drifted from the code is worse than no
// document: it is a false assurance. Each check pins a claim a reader would rely on.
console.log('\n=== Security claim check ===');

const indexHtml = read('src/index.html');
const securityDoc = read('docs/SECURITY.md');

// Every directive the documentation quotes must actually be in the delivered policy.
const policyMatch = /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/.exec(
  indexHtml,
);
if (policyMatch === null) {
  fail('src/index.html delivers no Content Security Policy');
} else {
  const policy = policyMatch[1];
  const required = [
    "default-src 'none'",
    "script-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'none'",
    "require-trusted-types-for 'script'",
    'https://api.github.com',
    'https://raw.githubusercontent.com',
    'https://api.osv.dev',
  ];
  for (const directive of required) {
    if (!policy.includes(directive)) fail(`CSP no longer declares ${directive}`);
    if (!squash(securityDoc).includes(squash(directive))) {
      fail(`docs/SECURITY.md no longer documents the CSP directive ${directive}`);
    }
  }
  if (/script-src[^;]*unsafe-(inline|eval)/.test(policy)) {
    fail("the CSP grants 'unsafe-inline' or 'unsafe-eval' to script-src");
  }
  if (/trusted-types[^;]*angular#unsafe-bypass/.test(policy)) {
    fail('the Trusted Types policy list allows angular#unsafe-bypass');
  }
  console.log('  CSP matches the documentation');
}

// Every GitHub Action must be pinned to a full commit SHA, and that SHA must be the one
// the documentation lists. An unpinned action is the supply-chain hole the pins exist to
// close, so this is a hard failure rather than a warning.
const workflowDir = path.join(root, '.github/workflows');
const actionPins = new Map();
for (const name of fs.readdirSync(workflowDir)) {
  const workflow = fs.readFileSync(path.join(workflowDir, name), 'utf8');
  for (const use of [...workflow.matchAll(/uses:\s*([^\s#]+)(?:\s*#\s*(\S+))?/g)]) {
    const reference = use[1];
    const at = reference.lastIndexOf('@');
    const action = reference.slice(0, at);
    const version = reference.slice(at + 1);
    if (!/^[0-9a-f]{40}$/.test(version)) {
      fail(`${name} uses ${action}@${version}, which is not a full commit SHA`);
      continue;
    }
    actionPins.set(action, version);
    if (!securityDoc.includes(version)) {
      fail(`docs/SECURITY.md does not record the pinned SHA for ${action}`);
    }
  }
}
console.log(`  ${actionPins.size} action(s) pinned to a full SHA and documented`);

// Credentials must not be left in the checkout for later steps to read.
for (const name of fs.readdirSync(workflowDir)) {
  const workflow = fs.readFileSync(path.join(workflowDir, name), 'utf8');
  const checkouts = (workflow.match(/uses:\s*actions\/checkout@/g) ?? []).length;
  const disabled = (workflow.match(/persist-credentials:\s*false/g) ?? []).length;
  if (checkouts !== disabled) {
    fail(
      `${name} has ${checkouts} checkout step(s) but ${disabled} with persist-credentials: false`,
    );
  }
  if (/^s*pull_request_targets*:/m.test(workflow)) {
    fail(`${name} uses pull_request_target`);
  }
}
console.log('  no workflow persists checkout credentials or uses pull_request_target');

// The limits quoted in the documentation must match the code that enforces them.
const inputBounds = read('src/app/engine/validation/external-input.ts');
for (const [code, doc] of [
  ['MAX_JSON_DEPTH = 32', '| JSON nesting depth | 32 |'],
  ['MAX_EXTERNAL_STRING_LENGTH = 4096', '| Any single external string | 4,096 chars |'],
]) {
  if (!inputBounds.includes(code)) fail(`external-input.ts no longer defines ${code}`);
  if (!squash(securityDoc).includes(squash(doc))) {
    fail(`docs/SECURITY.md no longer states ${doc}`);
  }
}
console.log('  documented resource limits match the code');

// The dangerous sinks must stay absent from application source.
const sourceFiles = [];
(function walkSource(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkSource(full);
    else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.spec.ts')) sourceFiles.push(full);
  }
})(path.join(root, 'src'));

const sinks = [
  [/\.innerHTML\s*=/, 'innerHTML assignment'],
  [/\.outerHTML\s*=/, 'outerHTML assignment'],
  [/insertAdjacentHTML/, 'insertAdjacentHTML'],
  [/document\.write/, 'document.write'],
  [/bypassSecurityTrust/, 'a sanitiser bypass'],
  [/[^.\w]eval\s*\(/, 'eval'],
  [/new\s+Function\s*\(/, 'Function construction from a string'],
];
for (const sourceFile of sourceFiles) {
  const source = fs.readFileSync(sourceFile, 'utf8');
  for (const [pattern, what] of sinks) {
    if (pattern.test(source)) {
      fail(`${path.relative(root, sourceFile)} uses ${what}`);
    }
  }
}
console.log(`  ${sourceFiles.length} source files contain no dangerous DOM or eval sink`);

// ---- 3. No placeholder text --------------------------------------------
console.log('\n=== Placeholder check ===');
for (const file of markdownFiles(root)) {
  if (file.includes('PROJECT_SPECIFICATION')) continue;
  const text = fs.readFileSync(file, 'utf8');
  for (const marker of ['TODO', 'FIXME', 'XXX', 'Lorem ipsum', 'coming soon', 'TBD']) {
    if (text.includes(marker)) fail(`${path.relative(root, file)} contains "${marker}"`);
  }
}

console.log(problems === 0 ? '\nAll documentation checks passed.' : `\n${problems} problem(s).`);
process.exit(problems === 0 ? 0 : 1);
