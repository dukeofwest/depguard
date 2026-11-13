# ADR-0006: GitHub data integration

- **Status:** Accepted (Phase 2)
- **Date:** 2026-11-13

## Context

Phase 2 implements retrieval of every repository signal the analysis needs, within the 60
requests/hour anonymous budget and without any credential.

## Decisions

### 1. Required versus optional sources

Only `GET /repos/{owner}/{repo}` is required; its failure fails the scan, because without
metadata there is nothing to analyse and no default branch to query.

Every other source degrades to `null` on failure. A partial analysis that says what is
missing is far more useful than a failed one (§6.3), and `null` is what later drives
`Unknown` statuses and reduced coverage — so the loss is reported rather than hidden.

### 2. `community/profile` dropped

The recursive tree plus free `raw.githubusercontent.com` content cover the same signals
for one request fewer. It is also _more accurate_: `community/profile` resolves
organisation-level fallbacks, reporting a `CODE_OF_CONDUCT.md` that lives in the org's
`.github` repository as though the analysed repository provided it. Reading the repository
tree reports only what the repository actually contains.

### 3. Only `.github/workflows/` counts as repository-configured CI

**Found by live testing, not by reasoning.** `GET /actions/workflows` for
`expressjs/express` returns entries the repository never committed, with paths such as
`dynamic/copilot-pull-request-reviewer` — workflows GitHub injects. Crediting those as
evidence that a project has configured CI would be exactly the unfounded claim §5.3
forbids.

`WorkflowSummary.isRepositoryDefined` now records the distinction, set only for paths
under `.github/workflows/`. A mocked regression test covers it so the finding survives
without network access.

This is a concrete argument for the opt-in live test: no amount of fixture-writing would
have revealed a field whose existence we did not suspect.

### 4. Retry only what a retry can fix

Bounded exponential backoff (2 attempts, 300 ms then 600 ms) applies **only** to network
failures, timeouts and 5xx. A 4xx is never retried: a 404 will not become a 200, and a
rate-limit 403 cannot succeed before the window resets. Retrying either would burn a
budget of 60/hour for nothing (§8.4).

### 5. Cache with `refCount: true`

The session cache deduplicates in-flight requests so concurrent callers share one request,
and serves repeat analyses at zero quota cost.

`shareReplay` uses `refCount: true`. An earlier draft used `false` on the reasoning that
it would stop one caller's cancellation aborting another's — that reasoning was wrong.
`refCount: true` tears the source down only when the **last** subscriber leaves, so it
already protects concurrent callers while still making cancellation real (§10.4). The
teardown also clears the in-flight entry, so a cancelled request cannot leave a dead
observable that later callers wait on forever.

Nothing is persisted to `localStorage`: §14 forbids unnecessary storage, and a stale
cached report surviving a reload would be worse than spending the quota again.

### 6. Every response is untrusted

`github-response.ts` validates and normalises each payload. Missing or wrongly typed
fields become `null` rather than throwing or defaulting to a plausible-looking value; an
unparseable date becomes `null`, never "now".

`html_url` is re-validated before use and replaced with a constructed `github.com` URL
unless it genuinely parses as one — it is rendered as a link, so a hostile value must not
become an open redirect.

### 7. Opt-in live integration test

`github-response.live.spec.ts` runs against the real API under `DEPGUARD_LIVE=1`. It is
excluded from CI because it makes unauthenticated calls against a shared hourly budget and
would be both flaky and quota-bound.

Assertions check shape and invariants, never values: star counts and commit activity
change daily, and a test that fails because a repository gained a star is noise. It also
re-asserts the central Phase 0 finding — the SBOM arrives in one synchronous response with
`redirected: false` — so if GitHub ever moves to an asynchronous workflow, we find out
from a failing test rather than from users.
