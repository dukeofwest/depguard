const H = { Accept: 'application/vnd.github+json', 'User-Agent': 'DepGuard-Feasibility/0.1' };
const r = await fetch(
  'https://api.github.com/repos/expressjs/express/git/trees/master?recursive=1',
  { headers: H },
);
const t = await r.json();
console.log(
  'rem:',
  r.headers.get('x-ratelimit-remaining'),
  'entries:',
  t.tree.length,
  'truncated:',
  t.truncated,
);
const interesting = t.tree.filter((e) =>
  /^(SECURITY|LICENSE|README|CONTRIBUTING|CODE_OF_CONDUCT)|^\.github\/|^(test|tests|spec)\//i.test(
    e.path,
  ),
);
console.log('signal-bearing paths found in ONE request:');
interesting.slice(0, 25).forEach((e) => console.log('  ', e.type, e.path, e.size ?? ''));
console.log('total signal paths:', interesting.length);
