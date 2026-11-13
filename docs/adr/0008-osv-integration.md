# ADR-0008: OSV vulnerability integration

- **Status:** Accepted (Phase 4)
- **Date:** 2026-11-13

## Context

Phase 4 connects the OSV client to the analysis engine, completing the dependency
security workflow end to end.

## Decisions

### 1. Batch, then fetch details for unique advisories

`POST /v1/querybatch` returns advisory **identifiers only** — no severity, no summary, no
fixed version — so a second pass is unavoidable.

Measured against live data for `npm/cli`: 1,026 queryable packages produced **54 unique
advisories**, so batch-then-detail costs 3 + 54 requests. The alternative,
`POST /v1/query` per package, would cost 1,026. The two-pass approach wins by roughly
18×, and the gap widens with repository size because advisories are shared between
packages.

Detail requests are deduplicated by advisory id before fetching, since one advisory
commonly affects several packages.

### 2. Sequential batches, bounded-concurrency details

Chunks are sent sequentially at 500 queries each, within OSV's measured hard cap of 1,000
(1,001 returns HTTP 400). OSV publishes no rate limit, but a burst of large POSTs from
every visitor is not a reasonable thing to do to a free public service, and the measured
cost is low: 1,026 packages complete in about 2 seconds.

Advisory details use `mergeMap` with a concurrency of 8, plus a hard cap of 400 total
detail requests. The cap matters because a repository with many vulnerable dependencies
could otherwise generate hundreds of requests from a single page load. When it is
reached, the omission is **disclosed in the result** rather than silently truncating.

### 3. Partial results, never silent loss

A failed chunk degrades that chunk only: the packages it covered are counted as
`packagesFailed`, and the overall result becomes `partial` with a reason. A failed
individual advisory fetch drops that record and keeps the rest.

This matters because `partial` and `completed` are distinct variants in the engine's
`VulnerabilityResult`, so a scan that failed halfway can never be presented as a clean
bill of health.

### 4. Misaligned batch responses are discarded

`querybatch` results are positional — `results[i]` corresponds to `queries[i]`. If the
lengths disagree, the response is treated as unusable and no matches are recorded.

Guessing at the alignment would attribute advisories to the wrong packages, which is worse
than reporting none: a user acting on a wrong attribution would upgrade the wrong
dependency while the real one stayed vulnerable.

### 5. The exact-version rule is enforced at the boundary too

`queryPackages` filters out anything without an exact version, even though the engine's
`queryablePackages()` already does. The rule from ADR-0002 is the one place where a
mistake produces confident wrong answers rather than visible failure, so it is enforced
at both ends rather than trusted across the boundary.

A live test asserts the invariant against real data: no installed version in any finding
may contain range syntax.

### 6. Live pipeline verification

`analysis-pipeline.live.spec.ts` runs real GitHub SBOM → real OSV → real findings under
`DEPGUARD_LIVE=1`, including two controls that check for opposite failure modes:

- `lodash@4.17.15` must report **more** advisories than the patched `4.17.21` — proving
  matching works;
- a package with no advisories must report **none** — proving it does not invent them.

Assertions check invariants and relationships rather than exact counts, because advisory
databases change daily and a test that fails when a new CVE is published is noise.

### 7. Verified result against the ADR-0003 worked example

The live pipeline reproduces the predicted scoring exactly:

| Measure                  | Value                                 |
| ------------------------ | ------------------------------------- |
| Queryable packages       | 1,026 of 1,208 (85.0%)                |
| Unique advisories        | 54                                    |
| Severity spread          | 3 Critical, 32 High, 15 Medium, 4 Low |
| Raw deduction            | 350 points                            |
| Capped at 60 → **score** | **40 / 100**                          |

No duplicates were merged for `npm/cli`, because every advisory came from GHSA. CVE-level
deduplication matters for Python and Go inventories, where GHSA and PYSEC/GO records
describe the same CVEs — covered by the fixture test using real
`GHSA-v6rh-hp5x-86rv` / `PYSEC-2021-439` records.
