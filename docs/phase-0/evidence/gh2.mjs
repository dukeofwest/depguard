const H = { Accept: 'application/vnd.github+json', 'User-Agent': 'DepGuard-Feasibility/0.1' };
const j = async (u) => {
  const r = await fetch(u, { headers: H });
  return {
    s: r.status,
    rem: r.headers.get('x-ratelimit-remaining'),
    b: r.ok ? await r.json() : await r.text(),
  };
};

let r = await j('https://api.github.com/repos/expressjs/express/community/profile');
console.log('community/profile files:', JSON.stringify(r.b.files, null, 1).slice(0, 700));
console.log('health_percentage:', r.b.health_percentage, 'rem:', r.rem);

// huge repo: does recursive tree truncate?
r = await j('https://api.github.com/repos/torvalds/linux/git/trees/master?recursive=1');
console.log(
  '\ntorvalds/linux tree:',
  r.s,
  'entries=',
  r.b.tree?.length,
  'TRUNCATED=',
  r.b.truncated,
  'rem:',
  r.rem,
);

// archived repo
r = await j('https://api.github.com/repos/jashkenas/underscore');
console.log('\nunderscore archived=', r.b.archived, 'pushed=', r.b.pushed_at);
// stats on a big repo - 202?
const s = await fetch('https://api.github.com/repos/torvalds/linux/stats/commit_activity', {
  headers: H,
});
console.log('linux stats/commit_activity HTTP', s.status, 'len', (await s.text()).length);
// no releases case
r = await j('https://api.github.com/repos/sindresorhus/is-odd/releases/latest');
console.log(
  '\nis-odd releases/latest:',
  r.s,
  typeof r.b === 'string' ? r.b.slice(0, 80) : r.b.tag_name,
  'rem:',
  r.rem,
);
