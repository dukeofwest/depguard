# ADR-0001: Browser-only architecture, no backend and no proxy

- **Status:** Proposed (Phase 0)
- **Date:** 2026-11-13

## Context

The specification (§8.2) anticipated that the GitHub SBOM endpoint might use an
asynchronous workflow with temporary download redirects that browsers could not follow
due to CORS, and pre-authorised investigating "a minimal serverless proxy" on Cloudflare
Workers if so.

## Decision

Ship DepGuard as a **browser-only Angular SPA on GitHub Pages**. No backend, no proxy,
no server-side component of any kind.

## Evidence

### Verified in a real browser at the production origin

The decisive evidence is [BROWSER-CORS-PROOF.md](../phase-0/BROWSER-CORS-PROOF.md):
headless Chrome 157, page origin **`https://dukeofwest.github.io`**, CORS enforced by the
browser.

| Test                                        | Result                                                          |
| ------------------------------------------- | --------------------------------------------------------------- |
| SBOM `expressjs/express`                    | `200`, `type: cors`, 38,798 B readable, **`redirected: false`** |
| SBOM `npm/cli`                              | `200`, `type: cors`, **1,146,068 B** readable                   |
| OSV preflighted POST                        | `200`, preflight accepted                                       |
| `x-ratelimit-remaining` via `headers.get()` | **readable** (`54`, `53`, `52`…)                                |
| Negative control (disallowed header)        | **blocked**, as required — proves enforcement was on            |

`curl` could not have established any of this: it reports CORS headers without enforcing
them, and cannot show whether `Access-Control-Expose-Headers` makes the rate-limit headers
visible to JavaScript.

### Supporting curl measurements, 2026-11-13, unauthenticated:

- `GET /repos/{o}/{r}/dependency-graph/sbom` returns **`200 OK` with the SPDX document in
  the body on the first call**. There is no `202`, no `Location` header, no polling and no
  redirect. The async workflow the specification feared does not exist on this endpoint.
- All 11 required GitHub endpoints return `Access-Control-Allow-Origin: *`.
- `api.osv.dev` answers the CORS preflight its `application/json` POST requires:
  `OPTIONS → 200`, `access-control-allow-methods: GET,POST,OPTIONS`,
  `access-control-allow-headers: ...Content-Type...`.
- `raw.githubusercontent.com` also returns `Access-Control-Allow-Origin: *`.

Every reason to introduce a proxy was tested and none of them hold.

## Consequences

**Positive**

- Zero hosting cost and zero operational surface.
- No server can leak data, because no server exists; all analysis happens in the user's browser.
- The specification's `generatingSbom` / `waitingForSbom` / `retrievingSbom` states are
  deleted, removing a polling state machine from the MVP.

**Negative**

- Bound by the anonymous rate limit of **60 GitHub requests/hour/IP** (ADR-0002).
- CORS availability is GitHub's and OSV's choice, not ours. If either revokes it the
  product stops working. Accepted: both are long-standing public APIs, and the proxy
  remains available as a contingency that we are explicitly not building now.

## Rejected alternatives

- **Serverless proxy (Cloudflare Workers).** Rejected: solves no demonstrated problem,
  adds cost, deployment surface and a component that sees user repository queries.
- **Web Worker for SBOM parsing.** Rejected for the MVP: the 1.1 MB / 1,208-package
  `npm/cli` SBOM parsed in **2.8 ms on Chrome's main thread**, measured in-browser — about
  one sixth of a 16 ms frame. Specification §12 forbids worker infrastructure as decoration.
