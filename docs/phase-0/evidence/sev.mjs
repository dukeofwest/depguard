import fs from 'node:fs';
const ECO = {
  npm: 'npm',
  pypi: 'PyPI',
  maven: 'Maven',
  golang: 'Go',
  cargo: 'crates.io',
  nuget: 'NuGet',
  gem: 'RubyGems',
};
const d = JSON.parse(fs.readFileSync('sbom_npm_cli.json', 'utf8')).sbom;
const q = [];
for (const p of d.packages) {
  const ref = (p.externalRefs || []).find((r) => r.referenceType === 'purl');
  if (!ref) continue;
  const body = ref.referenceLocator.slice(4).split('?')[0];
  const at = body.lastIndexOf('@');
  if (at < 0) continue;
  const type = body.slice(0, body.indexOf('/')).toLowerCase();
  const eco = ECO[type];
  if (!eco) continue;
  const name = body
    .slice(body.indexOf('/') + 1, at)
    .split('/')
    .map(decodeURIComponent)
    .join('/');
  const v = p.versionInfo;
  if (!v || !/^\d/.test(v)) continue;
  q.push({ name, ecosystem: eco, version: v });
}
const ids = new Map();
for (let i = 0; i < q.length; i += 1000) {
  const chunk = q.slice(i, i + 1000);
  const r = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      queries: chunk.map((x) => ({
        package: { name: x.name, ecosystem: x.ecosystem },
        version: x.version,
      })),
    }),
  });
  const jr = await r.json();
  jr.results.forEach((res, j) =>
    (res.vulns || []).forEach((v) => {
      if (!ids.has(v.id)) ids.set(v.id, new Set());
      ids.get(v.id).add(chunk[j].name + '@' + chunk[j].version);
    }),
  );
}
console.log('unique vuln IDs:', ids.size);
const t0 = Date.now();
const details = await Promise.all(
  [...ids.keys()].map((id) => fetch('https://api.osv.dev/v1/vulns/' + id).then((r) => r.json())),
);
console.log(`fetched ${details.length} details in ${Date.now() - t0}ms (full parallel)`);
const bySev = {};
let noSev = 0,
  withdrawn = 0;
for (const v of details) {
  if (v.withdrawn) withdrawn++;
  const s = v.database_specific?.severity;
  if (!s) {
    noSev++;
    bySev.UNKNOWN = (bySev.UNKNOWN || 0) + 1;
  } else bySev[s] = (bySev[s] || 0) + 1;
}
console.log('severity distribution (database_specific.severity):', bySev);
console.log('records lacking qualitative severity:', noSev, '| withdrawn:', withdrawn);
const cvss = {};
details.forEach((v) => (v.severity || []).forEach((s) => (cvss[s.type] = (cvss[s.type] || 0) + 1)));
console.log('CVSS vector types present:', cvss);
console.log(
  'records with NO severity[] array at all:',
  details.filter((v) => !v.severity || !v.severity.length).length,
);
console.log('\nsample fixed-version extraction:');
details.slice(0, 3).forEach((v) => {
  const fixes = [];
  (v.affected || []).forEach((a) =>
    (a.ranges || []).forEach((r) =>
      (r.events || []).forEach((e) => e.fixed && fixes.push(a.package.name + ' -> ' + e.fixed)),
    ),
  );
  console.log(
    ' ',
    v.id,
    v.database_specific?.severity,
    '| fixes:',
    fixes.slice(0, 2).join(', ') || 'NONE',
  );
});
