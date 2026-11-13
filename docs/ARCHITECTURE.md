# Architecture

DepGuard is a browser-only Angular application. There is no backend, no proxy and no
database — a decision validated by measurement rather than preference
([ADR-0001](adr/0001-browser-only-architecture.md)).

## Why there is no server

The specification anticipated that GitHub's SBOM endpoint might use an asynchronous
workflow whose redirect a browser could not follow, and pre-authorised a serverless proxy
if so. Phase 0 tested that assumption in **real headless Chrome, from the production
origin**, with a negative control confirming CORS was genuinely being enforced:

- the SBOM arrives in one synchronous response, `redirected: false`;
- all three hosts send permissive CORS headers, including OSV's preflight;
- `x-ratelimit-remaining` is readable from JavaScript.

Every reason to build a proxy was tested and none held. See
[BROWSER-CORS-PROOF.md](phase-0/BROWSER-CORS-PROOF.md).

## Layers

```
┌─────────────────────────────────────────────────────────────┐
│ features/           Landing · Progress · Dashboard          │
│                     Angular components, signals, OnPush     │
├─────────────────────────────────────────────────────────────┤
│ core/               state/     ScanStore (state machine)    │
│                     services/  orchestration, cache, export │
│                     api/       GitHub + OSV clients         │
│                     models/    domain types                 │
├─────────────────────────────────────────────────────────────┤
│ engine/             Pure TypeScript. No Angular, no DOM,    │
│                     no I/O, no clock. Deterministic.        │
└─────────────────────────────────────────────────────────────┘
```

Data flows **up**: the API layer fetches, the engine decides, the components render.
Nothing flows down — the engine cannot reach back out, and that boundary is enforced
mechanically.

## The engine boundary

`src/app/engine/` contains every analytical decision: SPDX parsing, version triage,
vulnerability deduplication, repository checks, scoring, coverage and recommendations.

It may not import Angular, touch the DOM, perform I/O, read the clock, or use randomness.
The current time is passed into `buildReport()` as an argument, which is what makes
reports reproducible.

This is enforced **twice**, deliberately:

- an ESLint rule on `src/app/engine/**`, and
- [`engine-purity.spec.ts`](../src/app/engine/engine-purity.spec.ts), which reads the
  engine's own sources and fails the test suite on a violation.

Both were verified to fire by committing a deliberate violation and watching each fail.
Lint and tests run as separate CI steps, and an inline `eslint-disable` can silence a
rule — so neither guard is sufficient alone. The rule has caught three real violations
during development that review had not.

Type-only imports from `core/models` are permitted: they are erased at compile time, so
the engine shares the domain vocabulary without acquiring a runtime dependency.

## Honesty enforced by types

The specification's central rule is that unavailable data must never be presented as a
zero or as success. Rather than relying on discipline, the types make the wrong rendering
unrepresentable:

```ts
type CategoryResult =
  | { kind: 'scored'; score: number; coverage: number; deductions: Deduction[] }
  | { kind: 'insufficient-data'; coverage: number; reason: string };
```

A category that could not be assessed has **no `score` field**, so it cannot be rendered
as 0. Similarly, `VulnerabilityResult` separates `not-applicable` ("nothing could be
checked") from `completed` with no findings ("checked, found nothing") — the distinction
that keeps a lockfile-less repository from displaying a clean bill of health.

This is also why all 16 uses of Angular's `$any()` were removed from templates in Phase 6:
`$any()` disables template type checking, defeating exactly this protection at the point
of rendering.

## Request flow

```
URL ──► parseRepositoryUrl()        validated in-browser, no request yet
    ──► GET /repos/{owner}/{repo}   required; failure fails the scan
    ──► 6 parallel requests         optional; each degrades to null
    ──► GET .../dependency-graph/sbom
    ──► parseSbom()                 engine: normalise, classify versions
    ──► queryablePackages()         engine: exact versions only
    ──► POST /v1/querybatch         OSV, chunked at 500
    ──► GET /v1/vulns/{id}          unique advisories, concurrency 8
    ──► processVulnerabilities()    engine: dedupe on CVE, read severity
    ──► buildReport()               engine: score, cover, recommend
```

Only repository metadata is required. Every other source degrades to `null`, which becomes
an `Unknown` status and reduced coverage — a partial analysis that says so is far more
useful than a failed one.

## State and cancellation

`ScanStore` is a signal-based state machine: `idle → running → completed | failed |
cancelled`.

Starting a new scan invalidates the previous one **two ways**: the subscription is
unsubscribed, and every emission is checked against a run token before being accepted.
Unsubscribing stops delivery, but an already-queued emission could still arrive — so the
token is what actually guarantees a stale result cannot overwrite a current one.

The session cache deduplicates in-flight requests so concurrent callers share one, and
serves repeat analyses at zero quota cost. It uses `shareReplay({ refCount: true })`: an
earlier draft used `false`, reasoning that it protected concurrent callers from one
caller's cancellation. That reasoning was wrong — `refCount: true` tears down only when
the _last_ subscriber leaves, so it already does that while keeping cancellation real.

## No router

DepGuard has two views, and the report lives in memory for the session. A deep link could
not restore one without re-running the scan at a cost of 8 of the 60 hourly requests, so
view state is a signal rather than a route. This also avoids the GitHub Pages SPA problem,
where a project page returns 404 for client-side routes without a `404.html` fallback.

Revisit if shareable report URLs are implemented.

## Dependencies

Runtime: `@angular/common`, `@angular/compiler`, `@angular/core`,
`@angular/platform-browser`, `rxjs`, `tslib`. Nothing else.

No UI framework, no HTTP library, no semver library, no YAML parser. Notably:

- **No semver library**, because DepGuard _rejects_ ranges rather than resolving them.
- **No YAML parser**, because the Dependabot check only claims that the file declares an
  `updates:` section — too narrow a claim to justify a parser processing untrusted input.
- **No Web Worker**: the largest real SBOM (1.1 MB, 1,208 packages) parses in **2.8 ms**
  on the main thread, measured in-browser. A worker would add structured-clone overhead to
  optimise something far below the perceptible threshold.

## Testing

| Layer       | Approach                                                                    |
| ----------- | --------------------------------------------------------------------------- |
| Engine      | Unit tests over **real SBOM and advisory fixtures** captured from live APIs |
| API clients | `HttpTestingController`: success, 404, rate limit, retry, cancellation      |
| Components  | `TestBed` rendering, including adversarial XSS payloads                     |
| Integration | Full pipeline against live GitHub and OSV, opt-in via `DEPGUARD_LIVE=1`     |
| Browser     | Chrome via CDP: workflow, accessibility, screenshots                        |

Live tests are opt-in because they spend the shared hourly quota, and assert invariants
rather than exact counts — a test that fails when a new CVE is published is noise.

## Directory map

```
src/app/
  core/
    api/        github-api.service.ts  github-response.ts  osv-api.service.ts
    config/     api.config.ts          limits, allowlist
    models/     domain types
    services/   repository-data, repository-analysis, cache, rate-limit, export
    state/      scan.store.ts
    utils/      github-url.ts          URL validation (security boundary)
  engine/
    sbom/       spdx-parser.ts
    dependencies/ purl.ts  ecosystems.ts
    security/   vulnerability-processor.ts  security-checks.ts
    health/     maintenance-analyzer.ts  engineering-analyzer.ts  thresholds.ts
    scoring/    category-scorer.ts  overall-scorer.ts  weights.ts
    recommendations/ recommendation-engine.ts
    report/     report-builder.ts  schema.ts
  features/
    landing/  analysis/  dashboard/
  shared/
    components/ severity-badge  check-status  score-ring  coverage-bar
```

## Decision records

| ADR                                                        | Decision                                 |
| ---------------------------------------------------------- | ---------------------------------------- |
| [0001](adr/0001-browser-only-architecture.md)              | Browser-only; no backend or proxy        |
| [0002](adr/0002-exact-versions-only-for-osv.md)            | Query OSV only for exact versions        |
| [0003](adr/0003-scoring-model.md)                          | Weights, coverage floors, redistribution |
| [0004](adr/0004-anonymous-access-and-rate-limit-budget.md) | Anonymous access, request budget         |
| [0005](adr/0005-toolchain-choices.md)                      | Angular 21, Vitest pin, no router        |
| [0006](adr/0006-github-api-integration.md)                 | GitHub data integration                  |
| [0007](adr/0007-analysis-engine.md)                        | Engine design                            |
| [0008](adr/0008-osv-integration.md)                        | OSV batching and deduplication           |
