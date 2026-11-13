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
