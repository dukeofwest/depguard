import fs from 'node:fs';
const H = { Accept: 'application/vnd.github+json', 'User-Agent': 'DepGuard-Feasibility/0.1' };
for (const R of ['angular/angular.js', 'request/request']) {
  const m = await fetch(`https://api.github.com/repos/${R}`, { headers: H });
  const b = await m.json();
  console.log(
    `${R}: archived=${b.archived} pushed=${b.pushed_at} stars=${b.stargazers_count} rem=${m.headers.get('x-ratelimit-remaining')}`,
  );
  const sb = await fetch(`https://api.github.com/repos/${R}/dependency-graph/sbom`, { headers: H });
  console.log(`  SBOM HTTP ${sb.status} rem=${sb.headers.get('x-ratelimit-remaining')}`);
  if (sb.ok) {
    const d = await sb.json();
    fs.writeFileSync(`sbom_${R.replace('/', '_')}.json`, JSON.stringify(d));
    console.log('  packages=', d.sbom.packages.length);
  }
}
