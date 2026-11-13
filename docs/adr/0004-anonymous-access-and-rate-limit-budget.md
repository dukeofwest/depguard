# ADR-0004: Anonymous access only, with an explicit per-scan request budget

- **Status:** Proposed (Phase 0)
- **Date:** 2026-11-13

## Context

Specification §9.1 rules out OAuth and Personal Access Tokens for v1.0: public repository
analysis is enough to validate the product, and authentication adds security and privacy
complexity before demand is demonstrated.

Phase 0 confirms this is technically viable, and quantifies what it costs.

## Decision

Analyse public repositories anonymously. Treat the **60 requests/hour/IP** limit as a
first-class product constraint that is surfaced in the UI, not an error discovered
mid-scan.

## Evidence

- `X-RateLimit-Limit: 60` on every anonymous response. Confirmed.
- `GET /rate_limit` returns the budget and **does not consume it** (`used` did not
  increment). Confirmed — usable to prime the UI on load.
- `raw.githubusercontent.com` returns content with `Access-Control-Allow-Origin: *` and
  **does not consume the quota**. Confirmed across repeated fetches.
- A single `git/trees/{branch}?recursive=1` call returned all 133 signal-bearing paths for
  `expressjs/express`, replacing ~10 individual Contents API calls.

### Budget: 8 quota-consuming requests per scan

metadata · SBOM · recursive tree · actions workflows · releases/latest · contributors ·
languages · commit activity. Plus up to 2 more only when the tree truncates.

**≈ 7 scans per hour per visitor IP.**

> **Revised during Phase 2 implementation: 9 → 8.** The original budget included
> `GET /repos/{o}/{r}/community/profile`. It was dropped: the recursive tree plus file
> contents from `raw.githubusercontent.com` (which cost no quota) establish the same
> documentation and security-policy signals for one request fewer — and do so from the
> repository itself, whereas `community/profile` silently credits org-level files from a
> `.github` repository, which would overstate what the analysed repository actually
> contains. `RATE_LIMIT.requestsPerScan` is asserted by a test against the real request
> count, so the two cannot drift apart.
>
> `minimumRemainingToStart` is deliberately set higher, at 10, to leave headroom for the
> tree-truncation fallback so a scan never dies halfway through.

File _contents_ (`dependabot.yml`, workflow YAML, `SECURITY.md`) are fetched from
`raw.githubusercontent.com` at zero quota cost.

## Consequences

**Positive**

- No credentials exist in the product, so none can be leaked, logged or exported.
- Nothing to explain to users about trusting a new application with a token.
- Privacy statement is simple and true: analysis runs in your browser, against GitHub and
  OSV only.

**Negative**

- Roughly 6 scans/hour/IP. Users behind corporate NAT may arrive with the budget already
  spent through no fault of their own.
- Dependabot _enabled_ status and CodeQL _results_ require authentication and are
  therefore permanently out of v1.0 scope — DepGuard can only ever report that
  configuration files are present, never that the features are running. The UI must say
  exactly that (§5.3).

### Required handling

- Read `X-RateLimit-Remaining` / `-Reset` from every response; display remaining budget persistently.
- Refuse to start a scan with fewer than 9 remaining, showing the reset time, rather than
  failing halfway through.
- Cache per-repository results in memory for the session; re-analysis costs 0.
- Never retry a 403 rate-limit response — it cannot succeed without waiting. Bounded
  exponential backoff on 5xx and network errors only.

## Revisit when

Real usage shows users hitting the limit routinely. The natural next step is a GitHub App
or optional user-supplied PAT — deliberately deferred until demand exists.
