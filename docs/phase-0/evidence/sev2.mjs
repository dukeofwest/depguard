const r = await fetch('https://api.osv.dev/v1/querybatch', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    queries: [
      { package: { name: 'django', ecosystem: 'PyPI' }, version: '3.2.0' },
      { package: { name: 'github.com/gogs/gogs', ecosystem: 'Go' }, version: '0.12.0' },
      { package: { name: 'openssl', ecosystem: 'crates.io' }, version: '0.10.0' },
    ],
  }),
});
const jr = await r.json();
const ids = [...new Set(jr.results.flatMap((x) => (x.vulns || []).map((v) => v.id)))];
console.log(
  'total unique ids:',
  ids.length,
  '| prefixes:',
  [...new Set(ids.map((i) => i.split('-')[0]))].join(','),
);
const det = await Promise.all(
  ids.slice(0, 60).map((i) => fetch('https://api.osv.dev/v1/vulns/' + i).then((r) => r.json())),
);
const byPrefix = {};
det.forEach((v) => {
  const p = v.id.split('-')[0];
  byPrefix[p] ??= { total: 0, noQual: 0, noCvss: 0 };
  byPrefix[p].total++;
  if (!v.database_specific?.severity) byPrefix[p].noQual++;
  if (!v.severity?.length) byPrefix[p].noCvss++;
});
console.log('by source prefix -> {total, missing qualitative severity, missing CVSS vector}:');
console.table(byPrefix);
