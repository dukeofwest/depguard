const mk = (n) => ({
  queries: Array.from({ length: n }, (_, i) => ({
    package: { name: 'lodash', ecosystem: 'npm' },
    version: '4.17.' + (i % 22),
  })),
});
for (const n of [500, 1000, 1001, 2000]) {
  const t0 = Date.now();
  const r = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(mk(n)),
  });
  const txt = await r.text();
  let note = '';
  try {
    const j = JSON.parse(txt);
    note = 'results=' + (j.results ? j.results.length : '?');
  } catch {
    note = txt.slice(0, 160);
  }
  console.log(`batch n=${n}: HTTP ${r.status} ${Date.now() - t0}ms ${note}`);
}
// concurrency check on detail endpoint
const ids = [
  'GHSA-29mw-wpgm-hmr9',
  'GHSA-35jh-r3h4-6jhm',
  'GHSA-p6mc-m468-83gw',
  'GHSA-vh95-rmgr-6w4m',
  'GHSA-xvch-5gv4-984h',
  'GHSA-r5fr-rjxr-66jc',
  'GHSA-xxjr-mmjv-4gpg',
  'GHSA-4xc9-xhrj-v574',
];
const t1 = Date.now();
const rs = await Promise.all(
  ids.map((id) => fetch('https://api.osv.dev/v1/vulns/' + id).then((r) => r.status)),
);
console.log('8 parallel detail GETs:', rs.join(','), Date.now() - t1 + 'ms');
