const H = { Accept: 'application/vnd.github+json', 'User-Agent': 'DepGuard-Feasibility/0.1' };
const R = 'expressjs/express';
const eps = [
  ['tree(recursive)', `https://api.github.com/repos/${R}/git/trees/master?recursive=1`],
  ['commits(per_page=1)', `https://api.github.com/repos/${R}/commits?per_page=1`],
  ['releases/latest', `https://api.github.com/repos/${R}/releases/latest`],
  [
    'contributors(anon count)',
    `https://api.github.com/repos/${R}/contributors?per_page=1&anon=true`,
  ],
  ['languages', `https://api.github.com/repos/${R}/languages`],
  ['actions/workflows', `https://api.github.com/repos/${R}/actions/workflows`],
  ['community/profile', `https://api.github.com/repos/${R}/community/profile`],
  ['stats/commit_activity', `https://api.github.com/repos/${R}/stats/commit_activity`],
];
for (const [name, url] of eps) {
  const res = await fetch(url, { headers: H });
  const rem = res.headers.get('x-ratelimit-remaining');
  const acao = res.headers.get('access-control-allow-origin');
  const link = res.headers.get('link');
  let note = '';
  if (res.ok) {
    const j = await res.json();
    if (name.startsWith('tree')) note = `entries=${j.tree?.length} truncated=${j.truncated}`;
    else if (name.startsWith('commits')) note = `last=${j[0]?.commit?.committer?.date}`;
    else if (name.includes('releases')) note = `tag=${j.tag_name} published=${j.published_at}`;
    else if (name.startsWith('contributors')) note = `link=${(link || 'none').slice(0, 90)}`;
    else if (name === 'languages') note = Object.keys(j).join(',');
    else if (name.includes('workflows'))
      note = `count=${j.total_count} names=${(j.workflows || [])
        .slice(0, 4)
        .map((w) => w.path)
        .join('|')}`;
    else if (name.includes('community')) note = `keys=${Object.keys(j).join(',')}`;
    else if (name.includes('stats'))
      note = `weeks=${Array.isArray(j) ? j.length : JSON.stringify(j).slice(0, 80)}`;
  } else note = (await res.text()).slice(0, 120);
  console.log(`${res.status} ${name} | acao=${acao} rem=${rem} | ${note}`);
}
