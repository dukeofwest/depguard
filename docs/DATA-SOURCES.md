# Data sources

DepGuard contacts exactly three hosts. It never follows a URL discovered inside repository
content, and it never executes anything it downloads.

| Host                        | Purpose                                                                                                              | Authentication |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------- | -------------- |
| `api.github.com`            | Repository metadata, file tree, workflows, releases, contributors, languages, commit activity, dependency graph SBOM | None           |
| `raw.githubusercontent.com` | Contents of four allowlisted configuration files                                                                     | None           |
| `api.osv.dev`               | Vulnerability advisories                                                                                             | None           |

## GitHub REST API

Every endpoint below was verified against live repositories during Phase 0 — status,
CORS headers and response shape. See the
[feasibility report](phase-0/FEASIBILITY-REPORT.md) for the measurements.

| Endpoint                                                      | Why it is needed                                                                    | Quota |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ----: |
| `GET /repos/{owner}/{repo}`                                   | Identity, stars, forks, archived status, licence, dates. The only required request. |     1 |
| `GET /repos/{owner}/{repo}/dependency-graph/sbom`             | The dependency inventory, as SPDX 2.3 JSON                                          |     1 |
| `GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1`    | Every file path in one request                                                      |     1 |
| `GET /repos/{owner}/{repo}/actions/workflows`                 | CI, CodeQL and dependency review detection                                          |     1 |
| `GET /repos/{owner}/{repo}/releases/latest`                   | Release recency                                                                     |     1 |
| `GET /repos/{owner}/{repo}/contributors?per_page=1&anon=true` | Contributor count, from the `Link` header                                           |     1 |
| `GET /repos/{owner}/{repo}/languages`                         | Language breakdown                                                                  |     1 |
| `GET /repos/{owner}/{repo}/stats/commit_activity`             | 52 weeks of commit totals                                                           |     1 |
| `GET /rate_limit`                                             | Primes the remaining-requests display                                               | **0** |

**Total: 8 quota-consuming requests per analysis**, plus up to 2 more when the file tree
is truncated.

### The SBOM endpoint is synchronous

The specification anticipated an asynchronous generate/poll/redirect workflow, and
authorised building a serverless proxy if browser CORS blocked the redirect.

**No such workflow exists.** The endpoint returns `200 OK` with the SPDX document in the
body on the first call — no `202`, no `Location` header, no redirect. Verified with
[`redirected: false`](phase-0/BROWSER-CORS-PROOF.md) in a real browser. No proxy is needed
and none was built.

404 from this endpoint is normal, not an error: 2 of the 6 repositories tested had no
dependency graph.

### Two decisions that save quota

**One recursive tree call replaces every per-file check.** A single request returned all
133 signal-bearing paths for `expressjs/express`. Checking those files individually would
have cost ~10 of the 60 hourly requests.

**`raw.githubusercontent.com` costs nothing.** Verified: the quota does not decrement.
This is what makes content-level validation affordable — confirming that a Dependabot
config actually declares updates, rather than inferring it from a filename. Only these
four paths are ever fetched:

```
.github/dependabot.yml
.github/dependabot.yaml
SECURITY.md
.github/SECURITY.md
```

### `community/profile` is deliberately not used

It would supply documentation and security-policy signals in one request, but it resolves
**organisation-level fallbacks** — reporting a `CODE_OF_CONDUCT.md` that lives in the
org's `.github` repository as though the analysed repository provided it. Reading the file
tree reports only what the repository actually contains.

### GitHub lists workflows it injects

`GET /actions/workflows` returns entries the repository never committed, with paths such
as `dynamic/copilot-pull-request-reviewer`. Only workflows under `.github/workflows/`
count as evidence that a project configured CI. Found by live testing, not by reading the
documentation.

## OSV.dev

| Endpoint              | Purpose                             |
| --------------------- | ----------------------------------- |
| `POST /v1/querybatch` | Matches packages against advisories |
| `GET /v1/vulns/{id}`  | Full advisory record                |

Two passes are unavoidable: `querybatch` returns **identifiers only** — no severity, no
summary, no fixed version. For `npm/cli`, 1,026 packages produced 54 unique advisories, so
batch-then-detail costs 3 + 54 requests where one query per package would cost 1,026.

Measured constraints:

| Property                    | Value                              |
| --------------------------- | ---------------------------------- |
| Maximum queries per batch   | **1,000** (1,001 returns HTTP 400) |
| Chunk size used             | 500, sent sequentially             |
| Advisory detail concurrency | 8, capped at 400 total requests    |

OSV publishes no rate limit, but a burst of large POSTs from every visitor is not a
reasonable thing to do to a free public service.

### Only exact versions are ever sent

OSV does **not** reject a range supplied where a version belongs — it silently returns a
different, wrong answer:

| Query             |            Advisories returned |
| ----------------- | -----------------------------: |
| `lodash@4.17.15`  |                              5 |
| `lodash@4.17.21`  |                              2 |
| `lodash@^4.17.15` | **4 — a third, incorrect set** |

Packages without an exact version are excluded, counted, and reported to the user with the
reason. See [ADR-0002](adr/0002-exact-versions-only-for-osv.md).

### Severity is read, never computed

DepGuard does not derive a CVSS base score from a vector. GHSA records always publish a
qualitative severity; every PYSEC record measured had none at all — not even a vector to
compute from. Severity therefore comes from the advisory or is `Unknown`. CVSS vectors are
displayed unconverted, as evidence.

## Ecosystems

Package URL types are mapped to OSV ecosystems as follows:

| purl type  | OSV ecosystem | Verified against live data |
| ---------- | ------------- | -------------------------- |
| `npm`      | npm           | **Yes**                    |
| `pypi`     | PyPI          | **Yes**                    |
| `maven`    | Maven         | No                         |
| `golang`   | Go            | No                         |
| `cargo`    | crates.io     | No                         |
| `nuget`    | NuGet         | No                         |
| `gem`      | RubyGems      | No                         |
| `composer` | Packagist     | No                         |

`githubactions` and `github` appear in real SBOMs but are **not** OSV package ecosystems
in that form, so packages carrying them are reported as unsupported rather than queried
and silently returning nothing.

A report whose inventory uses an unverified ecosystem carries an explicit notice, because
§5.2 forbids claiming ecosystem support that has not been demonstrated.

## Rate limits

Anonymous GitHub REST allows **60 requests per hour, per IP address**. At 8 requests per
analysis that is roughly 7 scans per hour. The remaining budget is displayed in the header
at all times — possible only because Phase 0 verified in a real browser that
`x-ratelimit-remaining` is readable from JavaScript, which depends on
`Access-Control-Expose-Headers` and cannot be tested with curl.

A scan will not start when fewer than 10 requests remain, so it cannot fail halfway
through. Results are cached for the session, so re-analysing a repository costs nothing.

A rate-limit response is never retried — it cannot succeed before the window resets.
Bounded exponential backoff applies only to 5xx, network errors and timeouts.

Users behind shared IP addresses may arrive with the budget already spent through no fault
of their own. The interface explains this rather than showing a generic failure.
