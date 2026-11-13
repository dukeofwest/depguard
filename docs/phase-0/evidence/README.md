# Phase 0 evidence — reproduction scripts

Every claim in [`../FEASIBILITY-REPORT.md`](../FEASIBILITY-REPORT.md) comes from these
scripts. They are plain Node ESM (Node 22+), send **unauthenticated** requests only, and
write nothing outside their working directory.

Run from this directory:

```bash
node gh.mjs       # GitHub endpoint matrix: status, CORS, quota cost
node gh2.mjs      # community/profile, tree truncation, archived + no-release cases
node gh4.mjs      # archived repo (angular/angular.js) and request/request SBOM
node tree.mjs     # proves one recursive tree call surfaces every signal path
node limits.mjs   # OSV querybatch size cap and detail-fetch concurrency
node sev.mjs      # real severity distribution for npm/cli  (needs sbom_npm_cli.json)
node sev2.mjs     # severity availability by advisory source (GHSA vs PYSEC)
node pipeline.mjs <sbom.json>...   # SBOM -> triage -> OSV coverage measurement
```

`pipeline.mjs` and `sev.mjs` read SBOM files saved by `gh4.mjs` or fetched directly:

```bash
curl -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/npm/cli/dependency-graph/sbom > sbom_npm_cli.json
```

## Budget warning

Anonymous GitHub REST allows **60 requests/hour/IP**. `gh.mjs` spends 8, `gh2.mjs` 5,
`gh4.mjs` 4, `tree.mjs` 1. Running everything twice in one hour will exhaust the quota.
`GET /rate_limit` is free — check it first.

OSV imposes no quota but caps `querybatch` at 1,000 queries per request.

## Browser proof (the important one)

`curl` cannot prove browser behaviour — it reports CORS headers without enforcing them.
The SBOM/CORS risk is tested in real Chrome instead:

```bash
cd browser
# one-time: certificate for the production hostname
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 2 -nodes -subj "/CN=dukeofwest.github.io" \
  -addext "subjectAltName=DNS:dukeofwest.github.io"
node runner.mjs        # launches headless Chrome, writes results.json
```

`runner.mjs` serves `index.html` over HTTPS and maps `dukeofwest.github.io` to localhost
via Chrome's `--host-resolver-rules`, so the page origin is **exactly the production
origin**. It requires Chrome at the path set in the file. Results and analysis:
[`../BROWSER-CORS-PROOF.md`](../BROWSER-CORS-PROOF.md).

The suite includes a **negative control** that must FAIL. If it ever passes, CORS was not
being enforced and the entire run is void.

## Results recorded on 2026-11-13

| Claim                                      | Script                      | Result                                            |
| ------------------------------------------ | --------------------------- | ------------------------------------------------- |
| **SBOM retrievable by a real browser**     | `browser/runner.mjs`        | `200`, `type:cors`, body read, `redirected:false` |
| **No redirect to be CORS-blocked**         | `browser/runner.mjs`        | `redirected:false` on all 8 calls                 |
| **Rate-limit headers readable from JS**    | `browser/runner.mjs`        | `x-ratelimit-remaining` = `54`, `53`, …           |
| **1.1 MB SBOM parses on main thread**      | `browser/runner.mjs`        | 1,208 packages in **2.8 ms**                      |
| **CORS really was enforced**               | `browser/runner.mjs`        | negative control blocked, as required             |
| SBOM is synchronous, not async             | `gh4.mjs`                   | `200` + body, first call, no redirect             |
| All GitHub endpoints CORS-open anonymously | `gh.mjs`                    | 8/8 `200`, `acao=*`                               |
| `raw.` costs no quota                      | manual curl + `/rate_limit` | quota unchanged                                   |
| Recursive tree surfaces all signals        | `tree.mjs`                  | 133 signal paths, 1 request                       |
| Tree truncates on huge repos               | `gh2.mjs`                   | linux: 71,474 entries, `truncated:true`           |
| OSV batch cap                              | `limits.mjs`                | 1,000 OK · 1,001 → `400`                          |
| Ranges give wrong OSV answers              | `pipeline.mjs` / manual     | `lodash@^4.17.15` → 4 vulns vs 5 exact            |
| Coverage tracks lockfiles                  | `pipeline.mjs`              | 84.9% / 14.8% / 10.0% / **0.0%**                  |
| PYSEC has no severity                      | `sev2.mjs`                  | 22/22 missing both qualitative and CVSS           |
| npm/cli severity spread                    | `sev.mjs`                   | 3 Critical, 32 High, 15 Moderate, 4 Low           |

Numbers involving live advisory data will drift as OSV is updated. The structural findings
(CORS, synchronicity, batch cap, range behaviour, lockfile dependence) should not.
