# Security review

> ## Historical correction: post-audit remediation
>
> **Status updated: 14 November 2026**
>
> This document records the security position at the original audit and
> remediation-planning stage. Some findings and limitations below were subsequently
> addressed.
>
> The following corrections apply to the final remediation state:
>
> - **XML parsing.** The XML parser and its security controls have since been implemented
>   and tested. The earlier statement that XML parsing was absent (§9.2, and residual
>   limitation 2) describes the historical audit baseline, not the current implementation.
> - **Aggregate discovery budget.** The 4 MiB aggregate budget is now enforced during
>   response consumption, with a documented one-chunk overshoot qualification. The 512 KiB
>   per-file limit remains in place.
> - **Destination validation.** Validation occurs at the GitHub client's relevant call
>   sites. There is no universal HTTP interceptor. See §2.4 "Destination validation,
>   precisely".
> - **Redirect handling.** `fetch` follows redirects by default. CSP `connect-src`
>   restricts connection destinations and browser CORS governs whether script may read a
>   cross-origin response; these are browser-level protections of two different kinds, and
>   neither is an application-controlled redirect validator. Application code does not
>   inspect every redirect hop. See §2.4 "Redirects, precisely".
>
> The original findings remain preserved as historical evidence. For the current
> implementation status, consult `AUDIT-REMEDIATION-REPORT.md` and the standing security
> documentation.
>
> The above changes do not imply that every historical finding was independently verified,
> or that all residual risks have been eliminated.

Application security findings from the audit of `d7e6336`, assessed against §9 of the audit brief.

This complements, and does not replace, the standing security documentation: `docs/THREAT-MODEL.md`
(assets, trust boundaries, attacker classes, attack scenarios, residual risks),
`docs/SECURITY-TESTING.md` (how each control is tested), `docs/SECURITY.md` (advisory triage) and
`docs/INCIDENT-RESPONSE.md`. The security hardening programme that produced those documents
completed immediately before this audit.

**Scope note:** this review covers security as it bears on the audit's subject matter — untrusted
dependency data, scanner honesty, and the security consequences of the proposed fallback. It does
not re-audit the CSP, Trusted Types or the Actions supply chain, which were implemented, proved in
a real browser and documented in the work this audit follows.

---

## 1. Findings

### 1.1 A scanner that reports clean after losing data (critical)

**This is the one security finding of consequence, and it is a correctness defect with security
impact.** Full mechanism in [DEPGUARD-TECHNICAL-AUDIT.md](DEPGUARD-TECHNICAL-AUDIT.md) §4, P0-1.

In short: OSV `querybatch` confirms that a package is affected; the follow-up
`GET /v1/vulns/{id}` fails; `fetchDetail` returns `null`; the record is dropped;
`processVulnerabilities` iterates records rather than matches, so no finding is produced; and
nothing marks the loss, so the report states

> "No known vulnerabilities were found in the N dependencies that could be checked."

Why this is a security finding and not merely a bug: DepGuard's entire value rests on the claim
that it does not say "clean" when it means "unknown". Every other control in the product is built
around that distinction — three separate coverage floors, the `insufficient-data` state, ADR-0002's
version conservatism. This path circumvents all of it, in the one direction that causes a user to
stop looking at a real vulnerability.

The fix is small (plan A1) and needs no new mechanism: the partial-result state already exists, is
already rendered, and already gates the category. Only the signal is missing.

### 1.2 Unavailable data presented as determined fact (low, honesty)

Two instances, neither exploitable, both undermining the evidence quality the product sells:

- A rate limit or network failure during SBOM retrieval is reported as _"GitHub has no dependency
  graph for this repository"_ — a positive claim about GitHub's state derived from an absence of
  evidence (`repository-data.service.ts:115` flattens every transport error to `null`;
  `spdx-parser.ts:58` renders that as the sentence above). Audit §2.4, plan A7.
- An Actions API failure is reported as _"No CI configuration was found"_ and deducts 15 points
  (`security-checks.ts:231`). Unavailable data becoming a failure, which constraint 11 forbids.
  Audit §6, plan A2.

### 1.3 A check whose docblock claims verification it does not perform (low)

`security-checks.ts:140-144` states that the CodeQL check "requires that a workflow actually
references the CodeQL action, rather than inferring it from a filename." It matches the workflow's
name and path. The claim is one level stronger than the evidence, inside the file that exists to
make such claims carefully. Audit §6, P1-10.

### 1.4 Dependabot status contradicting its own evidence (low)

`security-checks.ts:124-136` awards `Configured` and the category's heaviest 25 points to a
`dependabot.yml` whose evidence text reads "no updates section was recognised". Audit §6, P1-9.

---

## 2. The fallback's security gate — decision required

Phase C of the plan cannot start until this is accepted or rejected in writing.

### 2.1 The property being narrowed

`api.config.ts:106-115` currently states:

> "A fixed allowlist, retrieved from raw.githubusercontent.com... **Paths are never taken from
> repository content.**"

Four paths, compiled in. Dependency discovery requires fetching files whose paths vary per
repository, so this guarantee has to change shape.

### 2.2 The proposed replacement

|                             | Today                                                               | Proposed                                                                  |
| --------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Origins                     | 3, allowlisted                                                      | **unchanged**                                                             |
| Path source                 | compiled-in constant                                                | **GitHub git/trees API** — structured metadata from an allowlisted origin |
| Path from file _content_    | never                                                               | **never** (unchanged)                                                     |
| Which paths qualify         | 4 exact strings                                                     | basename matches a **compiled pattern allowlist**                         |
| URL construction            | `raw/{owner}/{repo}/{branch}/{path}`, segments filtered and encoded | **unchanged**                                                             |
| `isAllowedUrl` at transport | enforced                                                            | **unchanged**                                                             |
| Per-file cap                | 512 KB                                                              | **unchanged**                                                             |
| Total cap                   | 4 files                                                             | **N files and a total byte budget**                                       |

### 2.3 Assessment

What does **not** change: the origin allowlist; the prohibition on fetching a path found inside a
file; URL construction and segment filtering; the transport-layer re-check; the 512 KB per-file
bound; the rule that repository content is never executed.

What changes: the set of reachable URLs grows from _four fixed paths in this repository_ to _paths
in this repository whose basename matches a compiled pattern_. The repository is still pinned by
validated `owner`, `repo` and `branch`. The pattern list is as fixed as today's path list — only
its arity differs.

This is **not** arbitrary URL fetching, which §9.1 and the v1.0 constraints prohibit. The
attacker-controlled input is the _selection_ of which allowlisted-pattern paths exist, not the
origin, the host, or the shape of the URL. A repository owner can cause DepGuard to fetch, from
their own public repository, files whose names they chose from a list DepGuard compiled — which is
indistinguishable in effect from them having named the file `package-lock.json` today.

Residual risks introduced, with mitigations:

| Risk                                                                    | Mitigation                                                                                         |
| ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Many matching files inflate request count and scan time                 | Hard cap on file count and total bytes; measure before merge                                       |
| A hostile repository ships a 512 KB-per-file × N-file payload           | Total byte budget across the set, not just per file                                                |
| Path traversal via a crafted tree entry                                 | Existing segment filter (drops empty, `.`, `..`; percent-encodes each segment) plus `isAllowedUrl` |
| A truncated tree hides manifests, producing a false "no manifest found" | Discovery must report `partial`, never `no-manifest`, on a truncated tree (plan C1)                |
| Pattern list drift turning into a broad glob                            | Keep the list in `api.config.ts` beside the origin allowlist; assert its contents in `check-docs`  |

**Recommendation: accept.** The narrowing is small, bounded and auditable, and the capability it
buys — a correct dependency inventory for repositories GitHub has no graph for — is the product's
largest functional gap. But it is a real reduction in a documented guarantee and should be recorded
as a decision, not absorbed into a feature commit.

### 2.4 Review outcome: **accepted and implemented**

Implemented in `core/config/api.config.ts` (`MANIFEST_FILE_NAMES`, `DISCOVERY_LIMITS`,
`isDiscoverableManifest`) and `core/services/dependency-discovery.service.ts`. The ten points
§6.1 of the remediation specification requires a review to establish:

| #   | Requirement                                             | How it is met                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| --- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | Document the existing boundary                          | `api.config.ts` — `INSPECTED_FILE_PATHS`, four exact paths                                                                                                                                                                                                                                                                                                                                                                                       |
| 2   | Document the additional patterns                        | `MANIFEST_FILE_NAMES`: `package-lock.json`, `npm-shrinkwrap.json`                                                                                                                                                                                                                                                                                                                                                                                |
| 3   | How candidate paths are derived                         | Only from `snapshot.tree`, the GitHub git/trees response already fetched. Never from file contents — nothing reads a lockfile's `resolved` URLs or any other embedded location                                                                                                                                                                                                                                                                   |
| 4   | How paths are validated                                 | `isDiscoverableManifest`: length bound, no empty/`.`/`..` segment, **basename equality** against the compiled list. Then `getRawFile`'s own segment filter and per-segment `encodeURIComponent`                                                                                                                                                                                                                                                  |
| 5   | How arbitrary URL fetching is prevented                 | The URL is constructed, never taken: origin is a compile-time constant, owner/repo come from the validated `RepositoryRef`, branch from repository metadata. `isAllowedUrl` is checked in `GithubApiService` on the constructed URL before the request is issued — at that call site, not in an interceptor; see "Destination validation, precisely" below                                                                                       |
| 6   | Response size and parsing limits                        | 512 KB per file (`maxFileContentBytes`), enforced while the response is consumed, and an over-limit file is reported as unread rather than mis-parsed as malformed. All files together are capped at `maxManifestBytes`, also enforced during transfer. Bodies then go through `parseBoundedJson` (size, depth, node count, string length) before the parser sees them. The parser additionally bounds entries at 20,000 and v1 tree depth at 64 |
| 7   | How request budgets are respected                       | Zero additional GitHub API requests: the tree is reused and contents come from `raw.githubusercontent.com`, which is outside the quota. Asserted by a test that counts `api.github.com` requests across a full fallback scan and requires exactly 8                                                                                                                                                                                              |
| 8   | Cancellation and timeouts                               | Fetches run sequentially through `concatMap` and are torn down on unsubscribe (tested); each inherits `getRawFile`'s 30-second timeout                                                                                                                                                                                                                                                                                                           |
| 9   | A malicious repository cannot cause arbitrary fetches   | Tested directly: a tree containing `.env`, `id_rsa`, `secrets/credentials.json`, `package-lock.json.bak` and a workflow file produces **exactly one** request, for `package-lock.json`                                                                                                                                                                                                                                                           |
| 10  | Regression tests for path and resource-limit violations | `dependency-discovery.service.spec.ts` — basename near-misses, traversal, over-long paths, the file-count cap, the oversized-file path, prototype-pollution-shaped keys and the quota assertion                                                                                                                                                                                                                                                  |

Two additional hardening measures were added while implementing, neither required by the
review but both cheap:

- **Prototype-safe object walking.** Lockfile keys are attacker-controlled package paths, so
  every read goes through an `own()`/`ownEntries()` helper using
  `Object.prototype.hasOwnProperty`, and `__proto__` keys are dropped. A naive `obj[key]` walk
  would resolve `constructor` and `toString` to inherited values. Tested.
- **Iterative traversal of the v1 nested tree.** A recursive walker would overflow the stack on
  exactly the input the depth bound exists to reject; tested with a 5,000-level lockfile.

**Residual risk accepted:** a repository can cause up to 8 lockfile requests plus up to 24
project-file requests per scan, together downloading at most `maxManifestBytes` (4 MB) plus the
chunk in flight when that allowance is crossed. This costs the visitor bandwidth but no API quota.
Reaching any of those limits is reported as incomplete discovery, never absorbed silently.

### Destination validation, precisely

Corrected November 2026, after the verification pass found the original wording claimed more than
the code does.

**What is true.** Every URL is constructed from compile-time origins and validated inputs.
`isAllowedUrl` is called on the constructed URL before the request is issued, in `requestJson`
(all `api.github.com` traffic) and in the raw-file helpers (all `raw.githubusercontent.com`
traffic). Raw paths are additionally filtered segment by segment and percent-encoded, so a
traversal segment cannot survive even if a caller's own allowlist were bypassed.

**What is not true.** There is no HTTP interceptor. `provideHttpClient(withFetch())` is configured
without one, so destination validation is not applied uniformly to every outgoing request as a
property of the transport. The OSV client does not call `isAllowedUrl` at all: its endpoints are
built from the `OSV_API_ORIGIN` constant plus a percent-encoded advisory id, so its origin is
fixed by construction. Sound as written, and per-call-site rather than structural — a client added
later inherits nothing.

No interceptor was added. Adding one would centralise a check that currently passes, without
closing any reachable gap; the honest fix was the documentation, and the note on `isAllowedUrl`
now records where the check lives and what it does not cover.

### Redirects, precisely

Unchanged in substance from §9.1 and residual limitation 3, restated here because §2.4 is where
the file-discovery boundary is assessed:

`fetch` follows redirects by default, Angular's backend does not set `redirect: 'manual'`, and no
application code inspects individual hops — a browser application cannot, since intermediate URLs
are not exposed to script.

The restrictions are the browser's, and they are two different kinds of control that should not be
conflated:

- **CSP `connect-src`** restricts _connection destinations_. It names the same three origins and is
  applied to every hop, so a redirect leaving them is refused by the user agent before a connection
  is made. Proved in real Chrome by `tools/csp-test.mjs`.
- **CORS** governs _whether script may read a cross-origin response_. It does not prevent the
  request or the redirect; it determines whether the body becomes available to the application.

Both are real. Neither is an application-controlled redirect validator: they are enforced by the
user agent, the stronger of the two is lost if the application is ever served without its CSP, and
DepGuard neither observes nor reports that a redirect occurred.

---

## 3. §9 checklist

### 9.1 Input validation — sound

Owner/repo validation, URL parsing, embedded-credential rejection
(`https://user:token@github.com/...`), non-default port rejection, loopback, private-range,
cloud-metadata, IPv6 and decimal/hex IP rejection, traversal and lookalike hosts: all implemented
in `core/utils/github-url.ts` and covered by 63 cases in its spec. Destination allowlisting is
enforced by `isAllowedUrl` on each constructed URL at the GitHub client's call sites — not by an
interceptor, and not at the transport layer; the wording here previously claimed otherwise, and
§2.4 "Destination validation, precisely" now records what is actually in place. Package identity
is validated by parsing, never by string assembly.

Redirects: the browser follows them opaquely and `fetch`/`XHR` do not expose a per-hop hook, so
cross-origin redirect restriction is not something a browser-only application can enforce directly.
The mitigation is `connect-src`, which the browser applies to _every_ hop in a redirect chain — so a
redirect to a non-allowlisted origin is blocked by the CSP rather than by application code. Proved
in real Chrome by `tools/csp-test.mjs`. Worth stating plainly because "redirects are validated"
would be the wrong claim.

### 9.2 SBOM and manifest parsing — sound for JSON, absent for XML

Bounded before and during parse: `maxSbomBytes` 16 MB, `maxJsonBytes` 12 MB, `maxPackages` 20,000,
`MAX_JSON_DEPTH` 32, `MAX_JSON_NODES` 2,000,000, `MAX_EXTERNAL_STRING_LENGTH` 4,096. `Content-Length`
is checked before reading and re-checked against the text actually received, because
`Content-Length` is absent on chunked responses and is the server's own claim either way. The depth
checker is **iterative** — a recursive one would overflow on exactly the input it exists to reject.
Malformed JSON returns a value rather than throwing. Duplicate package IDs are counted, kept in the
inventory and collapsed before querying. Unexpected purl schemes become `unsupported-ecosystem`.

Nothing in the repository is ever executed: no build scripts, no MSBuild targets, no package
install scripts, no `eval`, no `new Function` — the last two verified absent from the shipped
bundle by `tools/release-review.cjs`.

**Gap:** XML parsing does not exist yet and is the main new attack surface Phase D introduces.
Requirements are specified in plan D3: no DTD or external entity processing (XXE), a bound on
internal entity expansion (billion laughs), and bounds on depth, node count, attribute count and
attribute length mirroring `external-input.ts`. `DOMParser` in `application/xml` mode does not
resolve external entities, which makes it defensible without a new dependency — but internal entity
expansion still needs an explicit bound, and that must be **tested, not assumed**.

### 9.3 Angular security — sound

CSP delivered as `<meta http-equiv>` (GitHub Pages serves a fixed header set):

```
default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; font-src 'self';
connect-src 'self' https://api.github.com https://raw.githubusercontent.com https://api.osv.dev;
object-src 'none'; base-uri 'self'; form-action 'none'; frame-src 'none';
child-src 'none'; worker-src 'none'; manifest-src 'none';
require-trusted-types-for 'script'; trusted-types angular angular#bundler
```

Trusted Types is enforced, and `angular#unsafe-bypass` is deliberately excluded. Verified in this
audit: **no `innerHTML`, no `bypassSecurityTrust*`, no `eval`, no `new Function` anywhere in
`src/app`**, and **no `localStorage`, `sessionStorage` or IndexedDB usage at all** — nothing is
persisted in the browser. All repository-provided text reaches the DOM through interpolation.
External links are `https`-only, validated by parsing rather than by prefix matching, with correct
`rel`. Enforcement is proved by 24 checks in real headless Chrome, including negative controls that
_attempt_ each blocked action.

`style-src 'unsafe-inline'` is a genuine, documented limitation: Angular injects `<style>` elements
at runtime, and `style-src-attr 'unsafe-inline'` does not cover them — the page rendered unstyled.
Found by running the browser proof, not by reading the policy.

### 9.4 API resilience — sound

30-second timeout on every request; cancellation by unsubscription (tested, including that a late
or superseded result can never reach the page); duplicate request deduplication and caching by URL
in `CacheService`; OSV detail concurrency bounded to 8 with a hard cap of 400 requests; retry
limited to 2 attempts with exponential backoff and **only for what a retry can fix** — a 4xx,
including a rate limit, is never retried, so a rate limit cannot burn more of a 60-request hourly
budget; `GET /rate_limit` primes the display without consuming quota; exhaustion is detected from
`x-ratelimit-remaining` and surfaced with a reset time.

**Gap:** §1.1. Resilience that loses data silently is not resilience. Every other degradation path
in the product reports itself; this one does not.

### 9.5 GitHub Actions and deployment — sound

All five actions pinned to full 40-character SHAs with version comments;
`persist-credentials: false` on checkout; `permissions: {}` at the workflow level with the minimum
granted per job and documented inline; no `pull_request_target`; build and deploy separated, with
the CSP proof and artifact review gating upload; `npm ci` only, never `npm install`, so the lockfile
is the input; `npm audit signatures` verifies registry signatures and provenance; Zizmor runs at
`--persona=auditor --min-severity=low`. No secrets exist to expose — the application uses no
credentials of any kind.

Current advisory position: 0 critical, 0 high, 0 runtime-dependency advisories; 14 moderate audit
_paths_ from **one** root advisory (`minimatch`), reached only through the ESLint toolchain, absent
from the shipped bundle (verified), whose only offered fix is a `typescript-eslint` downgrade —
documented as accepted in `docs/SECURITY.md`.

---

## 4. Residual limitations

Beyond those already recorded in `docs/THREAT-MODEL.md` §7:

1. **A lost advisory record is currently invisible** (§1.1). Until plan A1 ships, a `completed`
   clean result cannot be fully relied upon. This is the finding to fix first.
2. **No XML parsing exists, so its safety is unproven.** Phase D introduces the surface; the bounds
   are specified but not yet implemented or tested.
3. **Cross-origin redirect restriction is delegated to the browser**, not implemented in
   application code, because a browser-only application cannot inspect redirect hops. `fetch`
   follows redirects by default and nothing here overrides that; CSP `connect-src` (every hop) and
   CORS (the final responder) are what confine them, and neither is equivalent to application-level
   validation — a deployment serving the application without its CSP loses the stronger of the two.
4. **OSV's NuGet name and version normalization is measured behaviour, not a documented contract**
   (audit §3.2). It could change without notice; only a live integration test would detect that.
5. **DepGuard still cannot confirm whether any GitHub security feature is actually enabled** —
   Dependabot alerts, code scanning, secret scanning — because that needs authentication. Every
   affected check states this in its `limitation` field, and must continue to.
6. **DepGuard never proves a repository is secure**, and no change in this plan alters that.
   Constraint 20.
