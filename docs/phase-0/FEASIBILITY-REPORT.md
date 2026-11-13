# DepGuard — Phase 0 Technical Feasibility Report

**Date of investigation:** 2026-11-13
**Status:** Complete — awaiting approval gate
**Application code written:** None (per Section 20 of the specification)

All findings below come from **real, unauthenticated HTTP requests** made during this
investigation. Reproduction scripts are in [`evidence/`](evidence/). Where something was
not tested, it is marked **Not verified** rather than assumed.

> **On the evidence for CORS.** The tables below were initially measured with `curl`, which
> _reports_ CORS headers but never _enforces_ them — so curl alone cannot prove a browser
> can make these requests. The SBOM and CORS behaviour has therefore been re-verified in
> **real headless Chrome, from the exact production origin
> `https://dukeofwest.github.io`**, including a negative control proving CORS was actually
> being enforced. See **[BROWSER-CORS-PROOF.md](BROWSER-CORS-PROOF.md)**. That document,
> not this one, is the evidence for the project's biggest architectural risk.

---

## 1. Product feasibility assessment

**Verdict: DepGuard is feasible as a browser-only Angular SPA on GitHub Pages, with no
backend and no authentication — but one of its five categories is materially weaker than
the specification assumes.**

Three things were proven outright:

1. Every GitHub REST endpoint DepGuard needs works **anonymously** and returns
   `Access-Control-Allow-Origin: *`.
2. The GitHub SBOM endpoint is **synchronous** — a single `GET` returning SPDX 2.3 JSON.
   The asynchronous generate/poll/redirect workflow described in specification §8.2 and
   §0.2 **does not exist** for this endpoint.
3. OSV.dev is fully usable from a browser, including the CORS preflight that its
   `application/json` POST requires.

One thing was disproven, and it is the most important result in this report:

4. **SBOM-derived vulnerability coverage is governed entirely by whether the repository
   commits a lockfile.** It ranges from 85% of packages down to **0%**. This is a product
   problem, not an engineering one, and it is addressed in §4 and §12.

---

## 2. GitHub API endpoint matrix

All requests sent anonymously with only `Accept: application/vnd.github+json`.

| #   | Endpoint                                                 | Status    | CORS | Quota | Verified result                                                                                                                                       |
| --- | -------------------------------------------------------- | --------- | ---- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `GET /repos/{o}/{r}`                                     | 200       | `*`  | 1     | All of: stars, forks, open issues, archived, disabled, visibility, default_branch, created/updated/pushed_at, license SPDX ID, topics, size, language |
| 2   | `GET /repos/{o}/{r}/dependency-graph/sbom`               | 200 / 404 | `*`  | 1     | SPDX-2.3 JSON, **synchronous**, no redirect, no polling                                                                                               |
| 3   | `GET /repos/{o}/{r}/git/trees/{branch}?recursive=1`      | 200       | `*`  | 1     | 284 entries for express, `truncated:false`; includes path, type, **size**                                                                             |
| 4   | `GET /repos/{o}/{r}/community/profile`                   | 200       | `*`  | 1     | `health_percentage` + resolved README/LICENSE/CONTRIBUTING/CoC/security-policy links                                                                  |
| 5   | `GET /repos/{o}/{r}/actions/workflows`                   | 200       | `*`  | 1     | `total_count: 9`, workflow `path` values                                                                                                              |
| 6   | `GET /repos/{o}/{r}/releases/latest`                     | 200 / 404 | `*`  | 1     | `tag_name`, `published_at`. **404 is the normal "no releases" case**, not an error                                                                    |
| 7   | `GET /repos/{o}/{r}/contributors?per_page=1&anon=true`   | 200       | `*`  | 1     | Count derived from `Link: rel="last"` header                                                                                                          |
| 8   | `GET /repos/{o}/{r}/languages`                           | 200       | `*`  | 1     | Byte counts per language                                                                                                                              |
| 9   | `GET /repos/{o}/{r}/stats/commit_activity`               | 200       | `*`  | 1     | 52 weeks of commit counts                                                                                                                             |
| 10  | `GET /rate_limit`                                        | 200       | `*`  | **0** | Confirmed free — `used` did not increment                                                                                                             |
| 11  | `https://raw.githubusercontent.com/{o}/{r}/{ref}/{path}` | 200 / 404 | `*`  | **0** | Confirmed free — quota unchanged across repeated fetches                                                                                              |

### 2.1 The two findings that shape the architecture

**(a) One recursive tree call replaces every per-file existence check.**
A single request returned all 133 signal-bearing paths for `expressjs/express` —
`.github/dependabot.yml`, all five workflow files, `LICENSE`, `Readme.md`, and the whole
`test/` tree — with blob sizes attached. Checking those files individually via the
Contents API would have cost ~10 requests from a 60/hour budget.

> **Case sensitivity is a real hazard.** express ships `Readme.md`, not `README.md`.
> All filename matching must be case-insensitive.

**(b) `raw.githubusercontent.com` is CORS-open and costs no quota.**
This is the single most valuable optimisation available. File _contents_ needed for
validation (parsing `dependabot.yml`, confirming a workflow actually invokes
`github/codeql-action`) are fetched from `raw.` for free, reserving the 60/hour API
budget for metadata, SBOM and tree.

### 2.2 Tree truncation

`torvalds/linux` returned **71,474 entries with `truncated: true`**. The non-recursive
root tree for the same repo returned 42 entries, `truncated: false`.

Mitigation: request `?recursive=1`; if `truncated` is true, fall back to the
non-recursive root tree plus a targeted `.github` subtree fetch (2 requests), and mark
deep-path signals such as test-directory detection as `Unknown` rather than
`Not detected`. Truncation must never be allowed to silently read as absence.

---

## 3. SBOM proof-of-concept results

### 3.1 The specification's premise is incorrect

Specification §8.2 and §0.2 instruct me to verify an "asynchronous generation and
retrieval workflow", "generation and retrieval statuses", "temporary download redirects"
and whether "CORS restrictions prevent retrieval".

**No such workflow exists on this endpoint.** `GET /repos/{o}/{r}/dependency-graph/sbom`
returned `200 OK` with `Content-Type: application/json` and the SPDX document in the body
on the first call, with no `Location` header, no `202 Accepted`, and no redirect. Measured
on four repositories.

**Verified in a real browser, not just curl.** From a Chrome 157 page at origin
`https://dukeofwest.github.io`, the SBOM fetch returned `status 200`, `type: "cors"`,
`redirected: false`, with a fully readable 38,798-byte body for express and
**1,146,068 bytes for `npm/cli`**. A negative control in the same run (sending a header
GitHub disallows) failed with `TypeError: Failed to fetch`, proving CORS enforcement was
active and the successes are genuine. Full results:
**[BROWSER-CORS-PROOF.md](BROWSER-CORS-PROOF.md)**.

Two things that only a browser could establish were also confirmed there:
`x-ratelimit-remaining` **is readable from JavaScript** (the rate-limit UI in ADR-0004
depends on this and curl could not prove it), and OSV's preflighted POST succeeds in
practice.

This is good news — it removes the polling state machine, the redirect-CORS risk and the
serverless-proxy contingency from the MVP entirely. The following states proposed in
specification §10.4 should be **deleted** as they describe work that does not happen:
`generatingSbom`, `waitingForSbom`, `retrievingSbom` → replaced by a single `fetchingSbom`.

### 3.2 Availability across real repositories

| Repository            | SBOM    | Packages | Note                        |
| --------------------- | ------- | -------- | --------------------------- |
| `expressjs/express`   | 200     | 54       | No committed lockfile       |
| `npm/cli`             | 200     | 1,208    | Commits `package-lock.json` |
| `psf/requests`        | 200     | 30       | Python, no pinned lockfile  |
| `request/request`     | 200     | 41       | Abandoned, no lockfile      |
| `sindresorhus/is-odd` | **404** | —        | No dependency graph         |
| `angular/angular.js`  | **404** | —        | Archived repo               |

404 is common and must be a first-class "SBOM unavailable" result, not an error state.

### 3.3 Document shape (verified)

```
{ sbom: { spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID, name,
          documentNamespace, creationInfo: { creators[], created },
          packages[], relationships[] } }
```

Package entries carry `name`, `SPDXID`, `versionInfo`, `licenseConcluded`, and an
`externalRefs[]` entry of `referenceType: "purl"`. **The purl is percent-encoded**
(`pkg:npm/%40npmcli/git@%5E8.0.0`) and must be decoded before use.

`relationships[]` uses `DEPENDS_ON` and `DESCRIBES`. For express all 53 `DEPENDS_ON`
edges originate from the single root document element, so **direct-vs-transitive
classification is not derivable** there. `npm/cli` returned 2,277 relationships across
1,208 packages, so the graph is meaningful only when a lockfile exists. Per specification
§5.2 this classification is to be shown "where known" — it will be reported as `Unknown`
whenever every edge originates from the root element.

---

## 4. The critical finding: version strings are frequently unusable

`versionInfo` often contains a **semver range, not a resolved version**:
`"versionInfo": "^1.2.1"`, `purl: pkg:npm/range-parser@%5E1.2.1`.

### 4.1 Why this is dangerous, demonstrated

OSV does **not** reject a range passed where a version belongs. It silently returns a
different and wrong answer:

| Query                     | Vulnerabilities returned       |
| ------------------------- | ------------------------------ |
| `lodash@4.17.15` (exact)  | 5                              |
| `lodash@4.17.21` (exact)  | 2                              |
| `lodash@^4.17.15` (range) | **4 — a third, incorrect set** |

Passing ranges through to OSV would produce confident, wrong, unfalsifiable findings.
**Rule: a package is queried only when its version parses as an exact version. There is
no exception to this rule.**

### 4.2 Measured coverage after applying that rule

| Repository          | Total packages | Queryable |  Coverage | Dominant skip reason    |
| ------------------- | -------------- | --------: | --------: | ----------------------- |
| `npm/cli`           | 1,208          |     1,026 | **84.9%** | 164 ranges              |
| `expressjs/express` | 54             |         8 | **14.8%** | 36 ranges               |
| `psf/requests`      | 30             |         3 | **10.0%** | 12 no version, 4 ranges |
| `request/request`   | 41             |         0 |  **0.0%** | 40 ranges               |

**`request/request` is the case that matters.** It is an abandoned, widely-depended-upon
repository last pushed in August 2024. DepGuard can query **zero** of its 41 packages. A
naive implementation would display "0 vulnerabilities found" — the most damaging possible
output, and a direct violation of the specification's own principle: _"Do not label a
dependency safe merely because OSV returned no matching vulnerability."_

### 4.3 Required product response

Dependency Security **must not produce a score** when queryable coverage is below a
defined floor. It reports `Insufficient data` and contributes nothing to the overall
score, with its weight redistributed (§9.3). The UI must state the real sentence:
_"8 of 54 packages had exact versions that could be checked. The remaining 46 are declared
as version ranges and were not checked. This repository does not commit a lockfile."_

This also turns DepGuard's biggest weakness into a genuine, actionable recommendation that
no other scanner surfaces this way: **"Commit a lockfile so your dependency tree can be
analysed."**

### 4.4 Ecosystems

Observed purl types: `npm`, `pypi`, `githubactions`, `github`.
`githubactions` and `github` are **not OSV package ecosystems** in this form and are
excluded from queries (17 and 1 packages respectively in `npm/cli`). Mapping table:
`npm→npm`, `pypi→PyPI`, `maven→Maven`, `golang→Go`, `cargo→crates.io`, `nuget→NuGet`,
`gem→RubyGems`. **Only `npm` and `pypi` were observed in live SBOMs**; the rest are
documented as untested and will be enabled per-ecosystem as real repositories confirm them
(specification §5.2: _"Do not claim comprehensive ecosystem support until it has been tested"_).

---

## 5. OSV proof-of-concept results

### 5.1 Verified constraints

| Property                          | Measured                              |
| --------------------------------- | ------------------------------------- |
| `POST /v1/querybatch` max queries | **1,000**. 1,001 → `HTTP 400`         |
| 1,000-query batch latency         | ~2.4 s                                |
| 1,026 packages (3 chunks of 500)  | 1.96 s total                          |
| CORS preflight (`OPTIONS`)        | `200`, allows `POST` + `Content-Type` |
| `GET /v1/vulns/{id}`              | `200`, CORS OK                        |
| 54 parallel detail fetches        | all `200` in 622 ms                   |

### 5.2 querybatch returns identifiers only

A `querybatch` result element is `{ vulns: [{ id, modified }] }` — **no severity, no
summary, no fixed version**. A second pass of `GET /v1/vulns/{id}` per _unique_ ID is
mandatory. This is bounded by distinct advisories, not package count: `npm/cli`'s 1,026
packages produced only **54 unique IDs**.

Rejected alternative: `POST /v1/query` returns full records but is one request per
package — 1,026 requests for `npm/cli` versus 3 + 54. Batch-then-detail wins decisively.

`next_page_token` was absent from all observed results but must still be handled.

### 5.3 Severity availability is uneven — "Unknown" is a frequent real outcome

| Source | Records | Missing qualitative severity | Missing CVSS vector |
| ------ | ------: | ---------------------------: | ------------------: |
| GHSA   |      38 |                            0 |                   0 |
| PYSEC  |      22 |                       **22** |              **22** |

**Every PYSEC record carried no severity data of any kind.** Specification §5.1's
`Unknown` severity category is therefore load-bearing, not a defensive edge case.

Severity is read in this precedence, and never synthesised:

1. `database_specific.severity` (`CRITICAL`/`HIGH`/`MODERATE`→Medium/`LOW`) — GHSA only
2. `severity[]` CVSS vector (`CVSS_V3` and `CVSS_V4` both observed) — displayed as the
   vector string
3. Otherwise → `Unknown`

Real distribution for `npm/cli`: **3 Critical, 32 High, 15 Moderate, 4 Low.**

### 5.4 Deduplication is mandatory

Querying three packages (`django`, `gogs`, `openssl`) returned **94 unique IDs** spanning
`GHSA`, `PYSEC`, `GO` and `RUSTSEC` — with GHSA and PYSEC records describing the **same
underlying Django CVEs**. Counting raw IDs would inflate Django's vulnerability count
roughly twofold. Findings are deduplicated on the CVE in `aliases[]`, falling back to the
raw ID only when no CVE alias exists.

### 5.5 Fixed versions

Extracted from `affected[].ranges[].events[].fixed`. Multiple fixed versions occur across
release lines (`js-yaml → 4.3.2` and `→ 3.15.2` for one advisory); all are shown. Some
advisories have none — then no upgrade target is claimed.

---

## 6. Repository health signal matrix

| Signal                         | Source                          | Anonymous? | Reliability                                        | MVP      |
| ------------------------------ | ------------------------------- | ---------- | -------------------------------------------------- | -------- |
| Repository metadata            | `/repos`                        | Yes        | **High**                                           | Yes      |
| Stars / forks / issues         | `/repos`                        | Yes        | **High**                                           | Yes      |
| Archived status                | `/repos`                        | Yes        | **High**                                           | Yes      |
| Last push / created / updated  | `/repos`                        | Yes        | **High**                                           | Yes      |
| License (SPDX)                 | `/repos` + `/community/profile` | Yes        | **High**                                           | Yes      |
| File tree & sizes              | `/git/trees?recursive=1`        | Yes        | **High** (Medium if truncated)                     | Yes      |
| Docs (README/CONTRIBUTING/CoC) | tree + `/community/profile`     | Yes        | **High**                                           | Yes      |
| Security policy                | tree + `/community/profile`     | Yes        | **High**                                           | Yes      |
| Dependabot config              | tree + `raw.` content           | Yes        | **High** for presence; **cannot verify enabled**   | Yes      |
| CodeQL workflow                | `/actions/workflows` + `raw.`   | Yes        | **Medium** — presence only, not execution          | Yes      |
| CI workflows                   | `/actions/workflows`            | Yes        | **High** for presence                              | Yes      |
| Test configuration             | tree                            | Yes        | **Medium** — heuristic                             | Yes      |
| Releases                       | `/releases/latest`              | Yes        | **High** (404 = none)                              | Yes      |
| Commit activity (52w)          | `/stats/commit_activity`        | Yes        | **Medium** — may return `202` while computing      | Yes      |
| Contributors count             | `/contributors` + `Link`        | Yes        | **Medium** — header parsing                        | Yes      |
| Languages                      | `/languages`                    | Yes        | **High**                                           | Yes      |
| SBOM / dependencies            | `/dependency-graph/sbom`        | Yes        | **High** when present, 404 otherwise               | Yes      |
| Vulnerabilities                | OSV                             | Yes        | **High per package, but low repo coverage** (§4.2) | Yes      |
| Direct vs transitive           | SBOM relationships              | Yes        | **Low** without lockfile                           | Degraded |
| Latest version / outdated      | —                               | —          | **No source**                                      | **No**   |
| Dependabot _enabled_           | —                               | —          | Requires auth                                      | **No**   |
| CodeQL _results_               | —                               | —          | Requires auth                                      | **No**   |
| Deprecated packages            | —                               | —          | Needs registry integration                         | **No**   |

Per specification §5.2, version freshness displays `Version freshness analysis: Not available`.

---

## 7. Rate limits — the binding constraint

**Anonymous GitHub REST is 60 requests per hour, per IP** (`X-RateLimit-Limit: 60`,
confirmed). This is the hardest practical limit on the product.

### Budget per scan

| Request                  |            Count |
| ------------------------ | ---------------: |
| Repository metadata      |                1 |
| SBOM                     |                1 |
| Recursive tree           |                1 |
| Community profile        |                1 |
| Actions workflows        |                1 |
| Releases latest          |                1 |
| Contributors (count)     |                1 |
| Languages                |                1 |
| Commit activity          |                1 |
| **Core total**           |            **9** |
| Tree-truncation fallback |        +2 (rare) |
| File contents via `raw.` |            **0** |
| OSV (separate service)   | 0 against GitHub |

**≈ 9 requests per scan → roughly 6 scans per hour per visitor IP.**

This is acceptable for the MVP's validation purpose, but it must be _visible_, not
discovered. Required handling:

- Read `X-RateLimit-Remaining` / `-Reset` from every response; display remaining budget
  persistently in the UI.
- Refuse to start a scan when fewer than 9 remain, showing the reset time, rather than
  failing halfway through.
- Cache per-repository results in memory for the session so re-analysis costs 0.
- `GET /rate_limit` is free and can be used to prime the display on load.
- Note that corporate/shared NAT means a user may arrive with the budget already spent —
  the 403 rate-limit response must be explained clearly, not shown as a generic failure.

No retry on 403-rate-limit (cannot succeed without waiting). Bounded exponential backoff
only on 5xx and network errors.

---

## 8. Recommended architecture

**Browser-only Angular 21 SPA on GitHub Pages. No backend. No proxy. No authentication.**
Every dependency of that decision was tested and holds:

- Both external services send permissive CORS headers, including OSV's preflight.
- The SBOM is a single synchronous GET — the proxy contingency in §8.2 is moot.
- Largest observed payload is `npm/cli` at 1,208 packages; parsing is milliseconds.

**Web Worker: not required for the MVP — now measured in-browser.** The largest SBOM
tested (`npm/cli`, **1.1 MB, 1,208 packages**) parsed in **2.8 ms on Chrome's main
thread** — roughly one sixth of a single 16 ms frame. The full pipeline including network
took ~2.6 s, almost all of it network wait, not CPU. A worker would add structured-clone
overhead to optimise something already far below the perceptible threshold, and is exactly
the "architectural decoration" §12 forbids. Revisit only if a repository is found whose
parse time measurably blocks; a hard cap on SBOM response size is enforced instead.

**Third-party npm packages: none needed.** `fetch`/`HttpClient` covers HTTP, `JSON.parse`
covers SPDX, and the only non-trivial algorithm is exact-version detection — and since we
_reject_ ranges rather than resolve them, no semver library is required. YAML parsing for
`dependabot.yml` is deliberately avoided: presence plus a conservative line-level check for
an `updates:` key is sufficient for the claim being made, and avoids a parser dependency
processing untrusted input.

### Revised state machine (replacing specification §10.4)

```
idle → validatingUrl → fetchingRepository → fetchingRepositoryData
     → fetchingSbom → analysingDependencies → queryingVulnerabilities
     → fetchingAdvisoryDetails → evaluating → buildingReport → completed
                                                     ↘ failed | cancelled
```

The three async-SBOM states are removed (§3.1). Progress reflects completed stages only —
no synthetic percentages.

---

## 9. Scoring model

### 9.1 Weights

I evaluated the specification's proposed weights against what the data actually supports
and recommend **one change**:

| Category               | Spec | **Recommended** | Rationale                                                                                                                                                                                 |
| ---------------------- | ---: | --------------: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dependency Security    |  35% |         **30%** | Highest value when available, but unavailable or unscorable for a large share of repositories (§4.2). 35% of a score that frequently cannot be computed makes the overall score unstable. |
| Dependency Health      |  15% |         **10%** | With freshness and deprecation out of scope, this category is thin — mostly inventory completeness. Weighting it at 15% overstates it.                                                    |
| Security Configuration |  20% |         **25%** | Fully and reliably observable for every repository, from free `raw.` content. Deserves more weight precisely because it is solid.                                                         |
| Maintenance & Activity |  15% |         **20%** | The most reliable signal set in the entire product (all High reliability) and the specification's named differentiator (§5.4).                                                            |
| Engineering Quality    |  15% |         **15%** | Unchanged.                                                                                                                                                                                |

Rebalancing toward what is reliably measurable makes the overall score more stable and
more honest. Recorded in [ADR-0003](../adr/0003-scoring-model.md).

### 9.2 Unknown handling

Per specification §6.2, unknown is neither 0 nor full marks. Each check yields
`Configured | Not detected | Unknown | Not applicable`. **Only `Configured` and
`Not detected` enter a category score.** `Unknown` and `Not applicable` are excluded from
both numerator and denominator and reduce that category's coverage.

### 9.3 Coverage and weight redistribution

Each category reports `coverage ∈ [0,1]` = scorable checks ÷ applicable checks.

- A category with coverage below **0.5** is reported as **`Insufficient data`**, produces
  no score, and its weight is redistributed proportionally across scorable categories.
- Dependency Security additionally requires **≥ 50% of packages queryable** (§4.3) —
  `request/request` at 0% therefore yields no security score at all.
- If redistribution would leave under 50% of total weight scorable, no overall score is
  shown — the report displays findings only.
- Overall coverage = Σ(weight × coverage) over applicable categories, displayed alongside
  the score at equal prominence, per §6.3.

### 9.4 Deduction rules

Deductions are capped per category and traceable to a specific finding.
Dependency Security starts at 100 and deducts per **deduplicated** advisory:
Critical −15, High −8, Medium −3, Low −1, Unknown −3 (floor 0, cap −60 total).
`Unknown` is weighted as Medium and **flagged as unscored severity in the explanation**,
so PYSEC-heavy Python repos are neither silently ignored nor over-penalised.

Per §6.5, a repository with no detected vulnerabilities does **not** reach 100 — the
maximum attainable is capped by queryable coverage, since unchecked packages are unknown,
not safe. No finding is counted in more than one category.

### 9.5 Worked example — `npm/cli`, from real measured data

Measured: 1,208 packages, 1,026 queryable (84.9%), 54 unique advisories after dedup:
3 Critical, 32 High, 15 Moderate, 4 Low.

```
Raw deduction = 3(15) + 32(8) + 15(3) + 4(1) = 45 + 256 + 45 + 4 = 350
Capped at −60                                → Dependency Security = 40/100
Coverage 0.849 (≥0.5)                        → category is scorable
```

A capped 40 is the correct outcome: the cap prevents a long tail of advisories from
driving every large repository to 0, while the score still reads clearly as poor. The
explanation must list the 3 Critical advisories by ID with their fixed versions, so the
deduction is traceable per §6.5.

### 9.6 Worked example — `request/request`

```
0 of 41 packages queryable (0% < 50% floor)
→ Dependency Security: INSUFFICIENT DATA — no score, weight redistributed
→ Overall score computed from remaining 70% of weight, rescaled
→ Report states: "No lockfile is committed, so no dependency version could be verified.
   This is not evidence that the dependencies are free of vulnerabilities."
```

This is the single most important behaviour in the product and the primary integration
test for Phase 3.

### 9.7 Interpretation labels

90–100 Excellent · 75–89 Good · 60–74 Fair · 40–59 Needs attention · 0–39 Poor —
always rendered next to coverage, and always with the §6.4 disclaimer that this is
DepGuard's heuristic assessment and not a security certification.

### 9.8 Maintenance thresholds (single source of truth)

Defined once in `engine/health/thresholds.ts`, never inline (§5.4):
`archived → Archived`; last push ≤30d → Recently active; ≤90d → Active;
≤365d → Limited activity; >365d → Potentially stale; no date → Insufficient data.

---

## 10. Proposed data models

Pure TypeScript in `src/app/engine/`, no Angular imports (§4.4). Discriminated unions
throughout; every externally-sourced field is optional until validated by a type guard.

```ts
type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown';
type CheckStatus = 'Configured' | 'Not detected' | 'Unknown' | 'Not applicable';

interface NormalizedPackage {
  readonly name: string;
  readonly purlType: string;
  readonly ecosystem: OsvEcosystem | null; // null = not queryable
  readonly declaredVersion: string | null;
  readonly versionKind: 'exact' | 'range' | 'missing'; // drives §4.1 rule
  readonly relationship: 'direct' | 'transitive' | 'unknown';
}

type CategoryResult =
  | {
      readonly kind: 'scored';
      readonly score: number;
      readonly coverage: number;
      readonly deductions: readonly Deduction[];
    }
  | { readonly kind: 'insufficient-data'; readonly reason: string; readonly coverage: number };
```

`CategoryResult` makes "insufficient data" unrepresentable as a zero — the type system
enforces §6.2 rather than relying on discipline.

---

## 11. Security considerations

- **No credentials anywhere.** No PAT input, no OAuth, no storage (§9.1). Nothing to leak.
- **Strict URL allowlist.** Only `api.github.com`, `raw.githubusercontent.com` and
  `api.osv.dev`. Owner/repo validated against `^[A-Za-z0-9._-]{1,100}$` and
  percent-encoded before interpolation. URLs found _inside_ repository content are never
  fetched (§9.2).
- **All external responses are untrusted.** Type guards before use; malformed JSON caught;
  response size capped.
- **No `innerHTML`, no `bypassSecurityTrust*`, no `eval`.** Package names, advisory
  summaries and repository descriptions are attacker-controllable and are rendered as
  text through interpolation only.
- **Advisory reference links** rendered with `rel="noopener noreferrer"`, never auto-followed.
- **Export contains no credentials** by construction (§7.3).
- **DoS self-protection:** caps on SBOM size, package count, OSV detail fetches and
  concurrency; bounded polling; no unbounded retries.

---

## 12. Technical risks

| #   | Risk                                                 | Severity | Mitigation                                                                                                                  |
| --- | ---------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Lockfile-dependent vulnerability coverage (§4.2)** | **High** | Coverage floor, `Insufficient data` state, explicit UI copy, lockfile recommendation. Accepted as a product characteristic. |
| 2   | 60 req/hour anonymous limit                          | **High** | Budget display, pre-flight check, session cache, clear 403 copy                                                             |
| 3   | Shared-IP users arrive with exhausted quota          | Medium   | Explain plainly; offer retry-at time                                                                                        |
| 4   | SBOM 404 on 2 of 6 tested repos                      | Medium   | First-class unavailable state                                                                                               |
| 5   | Tree truncation on very large repos                  | Medium   | Fallback + `Unknown`, never `Not detected`                                                                                  |
| 6   | PYSEC advisories carry no severity                   | Medium   | `Unknown` as a real category, surfaced in explanations                                                                      |
| 7   | `/stats/commit_activity` may return `202`            | Low      | Treat as `Unknown`, one bounded retry                                                                                       |
| 8   | GitHub changes SBOM response shape                   | Low      | Type guards fail closed to `Unknown`                                                                                        |
| 9   | Non-npm/PyPI ecosystem mappings untested             | Low      | Ship only verified ecosystems                                                                                               |

---

## 13. Final MVP scope

**In scope (all five categories, per your decision #3):** repository URL validation;
metadata; SBOM retrieval and SPDX parsing; exact-version triage; OSV batch + detail;
alias dedup; security configuration checks with evidence; maintenance analysis; engineering
signals; five category scores; coverage; overall score with redistribution; evidence-linked
prioritised recommendations; searchable/filterable dependency inventory; versioned JSON
export; rate-limit visibility; responsive accessible dark UI.

**Explicitly deferred:** version freshness / outdated detection (no reliable free source);
deprecated-package detection; PDF export; historical tracking; multi-repo monitoring.

**Requires authentication — out of scope (your decision #1):** private repositories;
Dependabot alert status; CodeQL scan results; higher rate limits.

**Requires a backend — out of scope:** scheduled scans; shareable stored reports.

---

## 14. Implementation plan

| Phase | Content                                                                                                     | Gate                                                          |
| ----- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| 1     | Angular 21 standalone app, strict TS, test runner, design tokens, layout, Pages workflow                    | Build + lint + test pass                                      |
| 2     | GitHub client: 9 verified endpoints, `raw.` content, rate-limit tracking, cache, cancellation, typed errors | Real repos retrieved                                          |
| 3     | Pure engine: SPDX parser, purl decode, version triage, checks, scoring, coverage, recommendations, report   | Engine tests, zero Angular imports                            |
| 4     | OSV: batching at 1,000 cap, detail fetch, alias dedup, severity precedence                                  | `npm/cli` and `request/request` fixtures behave per §9.5/§9.6 |
| 5     | Landing, progress, dashboard, five category views, inventory table, JSON export                             | Full workflow                                                 |
| 6     | Hardening: security, performance, a11y, empty/partial states                                                | Acceptance criteria                                           |
| 7     | README + `docs/`, deployment                                                                                | Live URL                                                      |
| 8     | Validation against the seven §13.5 scenarios                                                                | Release gate                                                  |

---

## 15. Acceptance criteria status

- [x] GitHub API feasibility demonstrated — 11 endpoints, real requests
- [x] SBOM retrieval **tested**, not assumed — 6 repositories, async premise disproven
- [x] OSV integration tested — batch cap, CORS, severity, dedup all measured
- [x] CORS limitations documented — including preflight; no proxy required
- [x] Every MVP metric has a real data source — §6 matrix, with gaps marked No
- [x] Scoring rules defined — weights, coverage, redistribution, two worked examples
- [x] Architecture justified — browser-only; worker and backend explicitly rejected with data

---

## 16. Decisions requiring your approval

1. **Weight rebalance** (35/15/20/15/15 → 30/10/25/20/15), §9.1.
2. **Coverage floors** — 0.5 category floor, 0.5 queryable-package floor for Dependency
   Security, with weight redistribution, §9.3.
3. **Removal of the async SBOM states** from §10.4, since that workflow does not exist, §3.1.
4. **Ship only `npm` and `PyPI` ecosystems as verified**, adding others as tested, §4.4.
5. **No Web Worker and no YAML parser in the MVP**, §8.

Your three stated decisions are unchanged and all three are supported by the evidence:
anonymous public analysis works end to end; SBOM-first is the right starting point and its
real limits are now quantified rather than guessed; and all five categories are deliverable.
