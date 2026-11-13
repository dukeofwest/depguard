# Security

DepGuard runs entirely in the browser, holds no credentials, and contacts three fixed
hosts. This document records what that means in practice, what was reviewed in Phase 6,
and which risks remain.

## Threat model

DepGuard analyses repositories chosen by the user. Everything it reads — repository
metadata, package names, advisory text, file contents — is **third-party data that an
attacker may control**. Anyone can publish a package or a repository whose name, version
or description is a payload.

The realistic threats are therefore:

| Threat                                                        | Mitigation                                                                                                                                                                                                                                                                          |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hostile repository or package metadata executing in the page  | All third-party data is rendered through Angular interpolation; no `innerHTML`, no `bypassSecurityTrust*`, no `eval`. Verified by [`untrusted-content.spec.ts`](../src/app/features/dashboard/untrusted-content.spec.ts) against eight XSS payloads pushed through the real engine. |
| A hostile URL becoming a navigation or fetch target           | Requests go only to three allowlisted origins. Advisory references are filtered to `http(s)` before rendering; `javascript:`, `data:` and `vbscript:` URLs are dropped in the engine.                                                                                               |
| A crafted repository URL reaching the API as a path traversal | Owner and repo are validated against strict patterns, relative path segments are rejected before parsing, and both are percent-encoded before interpolation. 40 tests in [`github-url.spec.ts`](../src/app/core/utils/github-url.spec.ts).                                          |
| An oversized or pathological API response exhausting memory   | Caps on SBOM bytes, file-content bytes, package count, OSV batch size, advisory detail requests and concurrency. Verified by [`performance.spec.ts`](../src/app/engine/performance.spec.ts) at 20,000 packages.                                                                     |
| Credential leakage                                            | There are no credentials. The MVP analyses public repositories anonymously, so there is nothing to store, log or export.                                                                                                                                                            |

## What was reviewed in Phase 6

### Rendering

A repository-wide search confirms there is no `innerHTML`, `outerHTML`,
`insertAdjacentHTML`, `document.write`, `eval`, `new Function`, `DomSanitizer` or
`bypassSecurityTrust*` anywhere in `src/`.

`$any()` — Angular's template escape hatch, which disables type checking for an
expression — was used in 16 places to read discriminated unions in templates. All were
removed and replaced with narrowed `computed()` signals, so the templates are fully type
checked again. ESLint forbids `any`, `@ts-ignore` and non-null assertions as errors.

Adversarial tests push `<script>`, `<img onerror>`, `<svg onload>`, `javascript:` URLs,
`data:` URIs, `<iframe>`, `<style>` and an Angular interpolation payload through the real
SBOM parser and advisory processor into the real components, then assert that no element,
script or inline event handler is created. The payloads must still appear as **visible
text**: sanitising a package name away would hide a real dependency.

### Network

Every request is built from validated input and checked against the origin allowlist
immediately before dispatch — a redundant check, kept so a future refactor cannot turn a
bug into a request to an arbitrary host.

URLs found _inside_ repository content are never fetched. File contents come from a fixed
allowlist of four paths ([`api.config.ts`](../src/app/core/config/api.config.ts)), never
from a path discovered in a file.

External links render with `rel="noopener noreferrer"` and `target="_blank"`, asserted by
test.

### Untrusted response handling

`github-response.ts` validates every field of every GitHub response. Missing or wrongly
typed values become `null` rather than throwing or defaulting to something plausible; an
unparseable date becomes `null`, never "now".

`html_url` is re-parsed and replaced with a constructed `github.com` URL unless it
genuinely is one — it is rendered as a link, so a hostile value must not become an open
redirect.

OSV `querybatch` results are positional. If the result count does not match the query
count, the whole response is discarded rather than aligned by guesswork: a wrong
attribution would send someone to upgrade the wrong dependency while the real one stayed
vulnerable.

### Denial of service against ourselves

| Limit                 | Value                          | Why                                         |
| --------------------- | ------------------------------ | ------------------------------------------- |
| SBOM response         | 16 MB                          | Largest real SBOM observed was 1.1 MB       |
| File content          | 512 KB, truncated              | Bounds a hostile file                       |
| Packages processed    | 20,000                         | Beyond this the excess is dropped, not held |
| OSV queries per batch | 1,000                          | OSV's measured hard limit                   |
| OSV advisory details  | 400 requests, concurrency 8    | Bounds requests from one page load          |
| Request timeout       | 30 s                           | No request hangs indefinitely               |
| Retries               | 2, only on 5xx/network/timeout | A 4xx is never retried                      |

Deeply nested and million-character inputs are covered by test and do not recurse or hang.

### Accessibility as a correctness property

Severity and check status are communicated by **word, glyph shape and colour**, never
colour alone, so a colour-blind reader cannot misread "Critical" as "Low".

A browser audit ([`tools/a11y-test.mjs`](../tools/a11y-test.mjs)) probes all 49
token/surface colour combinations through the real cascade. It found **11 WCAG AA
failures** in the original palette, including the primary button (white on accent at
3.68:1) and every "unknown" indicator. All were fixed; the audit now passes with no
failures and exits non-zero on regression.

## Known limitations and accepted risks

1. **DepGuard does not read code.** It cannot find vulnerabilities in the repository's own
   source, only in its declared dependencies. Stated in every report.

2. **Vulnerability coverage depends on lockfiles.** Dependencies declared as version
   ranges cannot be matched against advisory databases. Where fewer than half can be
   checked, the category reports insufficient data rather than a clean result
   ([ADR-0002](adr/0002-exact-versions-only-for-osv.md)).

3. **GitHub feature status is unobservable.** Without authentication DepGuard can see that
   `dependabot.yml` exists but not whether Dependabot is enabled, and that a CodeQL
   workflow exists but not whether it runs or passes. Every such check says so.

4. **Ecosystem matching is verified for npm and PyPI only.** Other mappings follow OSV's
   documentation but were not confirmed against live data. A report whose inventory uses
   one now carries an explicit notice.

5. **Advisory coverage is OSV's.** OSV aggregates many but not all sources. No detected
   vulnerabilities is never presented as proof of safety.

6. **Chrome only, for the browser-based checks.** The CORS, accessibility and workflow
   tools drive headless Chrome. Nothing relies on Chrome-specific behaviour, but Firefox
   and Safari have not been tested.

7. **A shared IP can arrive with no budget.** GitHub's 60 requests/hour is per IP, so a
   user behind corporate NAT may be unable to scan through no fault of their own. The UI
   explains this rather than showing a generic failure.

## Reporting a vulnerability

Open an issue at <https://github.com/dukeofwest/depguard/issues>. DepGuard has no backend
and stores no user data, so the realistic attack surface is the rendering of third-party
content described above.

## Verification

```bash
npm run lint         # bans any, @ts-ignore, non-null assertions; enforces engine purity
npm run typecheck    # strict TypeScript, including noUncheckedIndexedAccess
npm run test:ci      # 223 tests, including adversarial rendering and resource limits

npm run build -- --configuration github-pages
node tools/a11y-test.mjs dist/depguard/browser     # contrast, keyboard, semantics
node tools/workflow-test.mjs dist/depguard/browser # full user journey (uses API quota)
```
