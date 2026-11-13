import fs from 'node:fs';

const ECO = {
  npm: 'npm',
  pypi: 'PyPI',
  maven: 'Maven',
  golang: 'Go',
  cargo: 'crates.io',
  nuget: 'NuGet',
  gem: 'RubyGems',
  composer: 'Packagist',
  pub: 'Pub',
  hex: 'Hex',
  swift: 'SwiftURL',
  conan: 'ConanCenter',
  cocoapods: 'CocoaPods',
};
// deliberately NOT mapping: githubactions, github, actions

const EXACT = {
  npm: /^\d+\.\d+\.\d+/,
  PyPI: /^\d+/,
  Maven: /^\d+/,
  Go: /^v?\d+/,
  'crates.io': /^\d+\.\d+\.\d+/,
  NuGet: /^\d+/,
  RubyGems: /^\d+/,
  Packagist: /^v?\d+/,
};

function parsePurl(loc) {
  // pkg:npm/%40scope/name@%5E1.2.3
  if (!loc?.startsWith('pkg:')) return null;
  const noQual = loc.split('?')[0].split('#')[0];
  const body = noQual.slice(4);
  const at = body.lastIndexOf('@');
  const nameTypePart = at > 0 ? body.slice(0, at) : body;
  const version = at > 0 ? decodeURIComponent(body.slice(at + 1)) : null;
  const slash = nameTypePart.indexOf('/');
  if (slash < 0) return null;
  const type = nameTypePart.slice(0, slash).toLowerCase();
  const rawName = nameTypePart.slice(slash + 1);
  const name = rawName.split('/').map(decodeURIComponent).join('/');
  return { type, name, version };
}

function triage(sbomDoc) {
  const s = sbomDoc.sbom;
  const out = { queryable: [], skipped: [], all: [] };
  for (const p of s.packages) {
    const ref = (p.externalRefs || []).find((r) => r.referenceType === 'purl');
    const purl = ref ? parsePurl(ref.referenceLocator) : null;
    const version = p.versionInfo ?? purl?.version ?? null;
    const eco = purl ? (ECO[purl.type] ?? null) : null;
    const rec = {
      name: purl?.name ?? p.name,
      purlType: purl?.type ?? null,
      ecosystem: eco,
      version,
    };
    out.all.push(rec);
    let reason = null;
    if (!purl) reason = 'no-purl';
    else if (!eco) reason = `unsupported-ecosystem:${purl.type}`;
    else if (!version) reason = 'no-version';
    else if (!(EXACT[eco] ?? /^\d/).test(version)) reason = 'version-is-range';
    if (reason) out.skipped.push({ ...rec, reason });
    else out.queryable.push(rec);
  }
  return out;
}

async function querybatch(queries, chunkSize) {
  const ids = new Map();
  let reqs = 0;
  let paginated = 0;
  for (let i = 0; i < queries.length; i += chunkSize) {
    const chunk = queries.slice(i, i + chunkSize);
    const res = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        queries: chunk.map((q) => ({
          package: { name: q.name, ecosystem: q.ecosystem },
          version: q.version,
        })),
      }),
    });
    reqs++;
    if (!res.ok) {
      console.log('  OSV batch HTTP', res.status, (await res.text()).slice(0, 200));
      continue;
    }
    const data = await res.json();
    data.results.forEach((r, j) => {
      if (r.next_page_token) paginated++;
      (r.vulns || []).forEach((v) => {
        if (!ids.has(v.id)) ids.set(v.id, []);
        ids.get(v.id).push(chunk[j]);
      });
    });
  }
  return { ids, reqs, paginated };
}

const files = process.argv.slice(2);
for (const f of files) {
  const doc = JSON.parse(fs.readFileSync(f, 'utf8'));
  if (!doc.sbom) {
    console.log(f, 'NO SBOM');
    continue;
  }
  const t = triage(doc);
  const reasons = {};
  t.skipped.forEach((s) => (reasons[s.reason] = (reasons[s.reason] || 0) + 1));
  console.log('\n===', f, '===');
  console.log(
    'total packages:',
    t.all.length,
    '| OSV-queryable:',
    t.queryable.length,
    '| skipped:',
    t.skipped.length,
    `(coverage ${((100 * t.queryable.length) / t.all.length).toFixed(1)}%)`,
  );
  console.log('skip reasons:', reasons);
  const t0 = Date.now();
  const { ids, reqs, paginated } = await querybatch(t.queryable, 500);
  console.log(
    `OSV: ${reqs} batch request(s), chunk=500, ${Date.now() - t0}ms -> ${ids.size} unique vuln IDs, paginated results: ${paginated}`,
  );
  const affected = new Set();
  ids.forEach((pkgs) => pkgs.forEach((p) => affected.add(p.name + '@' + p.version)));
  console.log('affected package-versions:', affected.size);
  console.log('detail requests that would be needed (unique IDs):', ids.size);
}
