# Browser CORS proof — SBOM retrieval from the production origin

**Date:** 2026-11-13
**Browser:** Chrome 157.0.8103.39, headless, CDP-driven
**Page origin:** `https://dukeofwest.github.io/depguard/` — **the real production origin**
**Raw output:** [`evidence/browser/results.json`](evidence/browser/results.json)
**Reproduce:** [`evidence/browser/runner.mjs`](evidence/browser/runner.mjs)

> This document exists because the rest of Phase 0 was measured with `curl`, and **curl is
> not a browser**. curl _reports_ CORS headers; it never _enforces_ them. A passing curl
> request is therefore not evidence that an Angular app can make the same request. This is
> the largest architectural risk in the project, so it is tested directly rather than
> inferred.

## Method

The test cannot be run from `localhost`, because `localhost` is not the origin DepGuard
will be served from. Instead:

1. A local HTTPS server serves the test page, with a self-signed certificate issued for
   `CN=dukeofwest.github.io`.
2. Chrome is launched with
   `--host-resolver-rules=MAP dukeofwest.github.io 127.0.0.1:8443`, so the hostname
   resolves locally while the browser's **origin is genuinely
   `https://dukeofwest.github.io`** — confirmed in the output by reading `location.origin`
   from inside the page.
3. The page runs real `fetch()` calls. Chrome enforces CORS normally.
4. Each response body is **read to completion**. A CORS-blocked response is `opaque` and
   unreadable, so a readable body with `type: "cors"` is proof the request genuinely
   succeeded rather than silently failing.

### Validity control

`--ignore-certificate-errors` is required for the self-signed certificate. To prove this
did not disable CORS enforcement generally, the suite includes a **negative control**: a
request sending `X-Depguard-Not-Allowed`, a header GitHub's
`Access-Control-Allow-Headers` does not permit.

**It failed, as required** (`TypeError: Failed to fetch`, logged as
`net::ERR_FAILED`). CORS was therefore being enforced throughout, and the nine successes
are meaningful rather than an artefact of a weakened browser.

## Results — 9 passes, 1 intentional failure

| Test                                    | Status  | `type` |         Bytes |   Time | Redirected             |
| --------------------------------------- | ------- | ------ | ------------: | -----: | ---------------------- |
| **SBOM `expressjs/express`**            | **200** | `cors` |        38,798 | 107 ms | **false**              |
| **SBOM `npm/cli` (large)**              | **200** | `cors` | **1,146,068** |  24 ms | **false**              |
| SBOM 404 (`is-odd`)                     | 404     | `cors` |           103 |  27 ms | false                  |
| Repository metadata                     | 200     | `cors` |         6,925 |  31 ms | false                  |
| Recursive tree                          | 200     | `cors` |        81,462 |  29 ms | false                  |
| `raw.githubusercontent.com`             | 200     | `cors` |           442 |  56 ms | false                  |
| **OSV `querybatch` (preflighted POST)** | **200** | `cors` |           375 | 532 ms | false                  |
| OSV vuln detail                         | 200     | `cors` |         4,846 | 189 ms | false                  |
| **Negative control**                    | —       | —      |             — |      — | **FAILED as required** |

## What this settles

**1. The SBOM workflow is retrievable directly by a browser.** The endpoint returned the
full SPDX document on the first request, in-browser, from the production origin. No
`202`, no polling, and `redirected: false` on every call — **there is no temporary
download redirect to be blocked by CORS**. The serverless-proxy contingency in
specification §8.2 is not needed. ([ADR-0001](../adr/0001-browser-only-architecture.md))

**2. Rate-limit headers are readable from JavaScript.** `x-ratelimit-remaining` returned
real values (`54`, `53`, `52`, `51`, `50`) through `res.headers.get()`. This was previously
_assumed_ and curl could not confirm it, because cross-origin header visibility depends on
`Access-Control-Expose-Headers` and is enforced only by a browser.

This matters: the entire rate-limit budget UI required by
[ADR-0004](../adr/0004-anonymous-access-and-rate-limit-budget.md) depends on it. Had this
header been hidden, that design would have been impossible and DepGuard could only have
discovered exhaustion by failing. It works.

OSV exposes no such headers (`NOT EXPOSED`), which is expected and harmless — OSV
publishes no quota we need to track.

**3. The OSV preflight succeeds in practice.** OSV's `application/json` POST triggers a
real `OPTIONS` preflight, which Chrome performed and accepted. This is the one call in the
product that a browser could have blocked while curl showed success.

**4. The Web Worker question is settled empirically.** The largest SBOM tested —
**1.1 MB, 1,208 packages** — parsed in **2.8 ms** in the browser's main thread. That is
well inside a single 16 ms frame. A Web Worker would add structured-clone overhead and
architectural complexity to optimise something ~6× faster than one frame. Rejected for the
MVP, per specification §12's prohibition on worker infrastructure as decoration.

## Limitations of this test

- Chrome only. Firefox and Safari were not tested; all three implement the same CORS
  specification, and nothing observed relies on Chrome-specific behaviour, but this is
  stated rather than assumed.
- `--ignore-certificate-errors` was active. The negative control is what makes the result
  trustworthy despite it.
- The page was served locally rather than from GitHub Pages. Only the _origin_ matters for
  CORS, and it was exact. A final confirmation against the live deployment belongs in
  Phase 7.
- Rate-limit values reflect an unauthenticated quota of 60/hour and will differ per run.
