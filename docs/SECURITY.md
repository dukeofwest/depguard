# Security

DepGuard runs entirely in the browser, holds no credentials, and contacts three fixed
hosts. This document records what that means in practice, what has been reviewed, and
which risks remain.

Three companion documents carry the detail:

| Document                                     | Contents                                                                  |
| -------------------------------------------- | ------------------------------------------------------------------------- |
| [THREAT-MODEL.md](THREAT-MODEL.md)           | Assets, trust boundaries, attackers, ten attack scenarios, residual risks |
| [SECURITY-TESTING.md](SECURITY-TESTING.md)   | How every control is tested, how to run it, and the known gaps            |
| [INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md) | What to do when something gets through                                    |

The reporting process and scope are in the root [SECURITY.md](../SECURITY.md).

## Threat model in brief

The full model — assets, trust boundaries, attackers, scenarios and residual risks — is in
[THREAT-MODEL.md](THREAT-MODEL.md). What follows is the summary.

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

## Content Security Policy

Delivered as a `<meta http-equiv>` tag, because GitHub Pages serves a fixed set of
response headers and offers no way to add one.

```
default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; font-src 'self';
connect-src 'self' https://api.github.com https://raw.githubusercontent.com https://api.osv.dev;
object-src 'none'; base-uri 'self'; form-action 'none';
frame-src 'none'; child-src 'none'; worker-src 'none'; manifest-src 'none';
require-trusted-types-for 'script'; trusted-types angular angular#bundler
```

`script-src` grants neither `'unsafe-inline'` nor `'unsafe-eval'`: Angular is compiled
ahead of time, so the JIT compiler is absent from the bundle and no dynamic evaluation is
needed. Trusted Types is **enforced**, and `angular#unsafe-bypass` is deliberately absent
from the policy list — so a future call to `bypassSecurityTrustHtml` would fail loudly
rather than quietly reintroduce an XSS sink.

`style-src 'unsafe-inline'` is required and is the one allowance in the policy. Angular
injects each component's styles as a `<style>` element at runtime. It applies to CSS only,
and CSS has no exfiltration route here because `img-src` is `'self' data:` and
`default-src` is `'none'`. A nonce would be stricter but needs a per-response value, which
a static host cannot provide. The full justification is in the comment above the policy in
[`src/index.html`](../src/index.html).

**The policy is proved, not assumed.** `npm run check:csp` drives real headless Chrome and
attempts each thing the policy should prevent — inline script, an unapproved CDN, a fetch
to `example.com`, `innerHTML` assignment, a cross-origin `<base>`, a form submission —
asserting all are refused while the application still mounts and `api.github.com` stays
reachable. 24 checks, run in CI before every deployment.

Writing that tool immediately found two defects in a policy that read correctly on paper:
`base-uri 'none'` blocks the `<base href="/depguard/">` a project page requires, and
`style-src-attr 'unsafe-inline'` does not cover Angular's runtime-injected styles. Both
are fixed. Two things a meta tag cannot deliver: `frame-ancestors`, which is not a valid meta
directive at all, and `Strict-Transport-Security`, which is a header. The live site was
checked for the latter and **does not send it** — HTTP is answered with a `301` to HTTPS
instead. Both consequences, with the hosting alternative we considered and rejected, are
in [THREAT-MODEL.md](THREAT-MODEL.md) §7.

## Resource limits

Every limit is measured rather than guessed, and each is tested at its boundary.

| Limit                          | Value                  | Defined in                            |
| ------------------------------ | ---------------------- | ------------------------------------- |
| SBOM response                  | 16 MB                  | `core/config/api.config.ts`           |
| Any other JSON response        | 12 MB                  | `core/config/api.config.ts`           |
| File content from raw.github   | 512 kB                 | `core/config/api.config.ts`           |
| Packages per analysis          | 20,000                 | `core/config/api.config.ts`           |
| Request timeout                | 30 s                   | `core/config/api.config.ts`           |
| Header value parsed by a regex | 8 kB                   | `core/config/api.config.ts`           |
| JSON nesting depth             | 32                     | `engine/validation/external-input.ts` |
| Nodes visited when validating  | 2,000,000              | `engine/validation/external-input.ts` |
| Any single external string     | 4,096 chars            | `engine/validation/external-input.ts` |
| OSV queries per batch          | 1,000 (500 used)       | `core/config/api.config.ts`           |
| OSV advisory detail requests   | 400, 8 concurrent      | `core/config/api.config.ts`           |
| HTTP retries                   | 2, exponential backoff | `core/api/github-api.service.ts`      |

Two implementation notes that matter more than the numbers:

- **Responses are fetched as text and parsed under explicit bounds**, not through
  `HttpClient`'s JSON mode. JSON mode parses before any check can run, so a hostile body
  is already an object graph in memory by the time it could be rejected — and
  `Content-Length`, the only thing a pre-parse check could consult, is absent on a chunked
  response.
- **The depth check is iterative, not recursive.** A recursive depth-checker overflows the
  stack on exactly the input it exists to reject, which is the usual way this defence is
  written wrong.

## Dependency and supply-chain review

Six runtime dependencies in total: `@angular/common`, `@angular/compiler`,
`@angular/core`, `@angular/platform-browser`, `rxjs`, `tslib`. No semver library, no YAML
parser, no UI component framework. Every dependency not taken is an attack path not taken.

`package-lock.json` is committed and CI uses `npm ci`. Two audit gates run on every
change:

| Gate                                     | Threshold              | Current state      |
| ---------------------------------------- | ---------------------- | ------------------ |
| `npm audit --omit=dev --audit-level=low` | any advisory fails     | **0 advisories**   |
| `npm audit --audit-level=high`           | high or critical fails | 0 high, 0 critical |

### Findings and their triage

Reviewed, not waved through. A count from `npm audit` counts dependency _paths_, not
distinct problems.

**Resolved — `vitest`, critical (CVSS 9.8), [GHSA-5xrq-8626-4rwp](https://github.com/advisories/GHSA-5xrq-8626-4rwp).**
Arbitrary file read and execution when the Vitest UI server is listening. This project
never runs the UI server, so the finding was not reachable here — and it was fixed anyway,
because "it cannot be reached from here" is an argument that holds until the day it does
not. The fix required `vitest@4.1.12`, which exposed an unrelated bug in npm 10.9.x:
`Cannot read properties of null (reading 'edgesOut')`.

CI initially worked around that by installing npm 11 globally first. That turned out to be
unnecessary, and the workaround was removed. The npm bug is in dependency **resolution**,
which only `npm install` performs; `npm ci` reads the committed lockfile, and was verified
to install this tree correctly with the npm 10.9.9 that Node 22 bundles. Removing the
global install also removed the only package in the pipeline that no lockfile covered —
which is what Zizmor's `adhoc-packages` audit had flagged.

**Accepted — `glob`, moderate, [GHSA-3g3m-2fjr-6pw4](https://github.com/advisories/GHSA-3g3m-2fjr-6pw4).**
AbortSignal cancellation bypass allowing post-timeout filesystem traversal. Reached only
through `@angular/cli` → `pacote`. The only fix is `@angular/cli@22`, a framework major
upgrade that needs its own verification pass and is not a security patch.

**Accepted — `minimatch`, moderate, [GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249).**
Denial of service via globparts amplification. Reached through the Angular CLI and ESLint.
The offered fix is an ESLint **downgrade** from 10 to 9.39.5, which trades a current
linter for a moderate advisory in a glob library used at lint time. Not a worthwhile trade.

Both accepted findings are build-time only, and that is verified rather than asserted:
neither `minimatch` nor `glob` appears anywhere in the shipped bundle, which contains no
`require(`, no `process.env` and no `__dirname`. They affect a developer's machine and the
CI runner, where the glob input is this repository's own file tree. Both clear when Angular
22 is adopted; Dependabot will propose it.

### Signatures and provenance

`npm audit signatures` runs in CI. All 587 installed packages carry a verified registry
signature, and 226 also carry provenance attestations. This answers a different question
from `npm audit`: not whether a package has a known advisory, but whether the tarball
installed is the one the registry signed.

### Lifecycle scripts

Four packages run install scripts, all standard native-binary installers for build
tooling, none present in the shipped bundle:

| Package            | Script                                      | Purpose                             |
| ------------------ | ------------------------------------------- | ----------------------------------- |
| `esbuild`          | `postinstall: node install.js`              | Downloads the platform binary       |
| `@parcel/watcher`  | `install: node-gyp rebuild`                 | Native file-watching for `ng serve` |
| `lmdb`             | `install: node-gyp-build-optional-packages` | Angular's build cache               |
| `msgpackr-extract` | `install: node-gyp-build-optional-packages` | Serialisation for that cache        |

### GitHub Actions

Every action is pinned to a **full commit SHA** with a comment naming the release, because
a tag is mutable by whoever owns the action:

The workflows themselves are the record; see
[`ci.yml`](../.github/workflows/ci.yml) and
[`deploy.yml`](../.github/workflows/deploy.yml). Five actions are pinned:
`actions/checkout`, `actions/setup-node`, `actions/configure-pages`,
`actions/upload-pages-artifact` and `actions/deploy-pages`.

This document deliberately does **not** list the SHAs. It used to, and
`tools/check-docs.cjs` enforced the match — which meant every Dependabot action bump
failed CI until someone hand-edited a table here. A check that makes the correct action
fail is a check people learn to ignore, so what is enforced now is the property that
matters and is local to the workflow: **every action is pinned to a full 40-character
commit SHA and carries a version comment.** An unpinned action, or a SHA with no comment
saying what it is, fails the build.

Each SHA was resolved from the action's own release tags, not copied from documentation.
Dependabot understands a SHA pin with a version comment and updates both together, so
pinning does not mean going stale.

Also in force: `persist-credentials: false` on every checkout, so no token is left in
`.git/config` for a later step or a dependency's install script to read;
`permissions: {}` at the top of the deploy workflow with write access granted only to the
deploy job, which runs no repository code; no `pull_request_target` trigger anywhere, that
being the most exploited Actions misconfiguration; and Zizmor over all workflows at
`--persona=auditor --min-severity=low`.

## Repository hardening

These are **account and repository settings, not code** — they cannot be enforced from
this repository and are the maintainer's responsibility. Recorded here so the list is
checkable rather than remembered.

- [ ] Branch protection on `main`: require pull requests, require the CI checks to pass,
      disallow force-pushes and deletion
- [ ] Two-factor authentication on the GitHub account
- [ ] Secret scanning enabled (**Settings → Code security**)
- [ ] Push protection for secrets enabled
- [ ] Dependabot alerts and security updates enabled — [`.github/dependabot.yml`](../.github/dependabot.yml) configures the update PRs, but alerts are a repository setting
- [ ] Private vulnerability reporting enabled, so advisories can be filed privately
- [ ] Collaborator list reviewed; administration restricted to the maintainer
- [ ] Pages source set to **GitHub Actions**, with the `github-pages` environment limited
      to the `main` branch

**Already done in the repository:** no secret has ever been committed. The full history
was scanned for GitHub tokens and fine-grained PATs, private keys, AWS access key ids,
JWTs and Slack tokens, and for assignments to credential-shaped keys; all clean.
`.gitignore` now also excludes `.env`, `*.pem`, `*.key`, `*.p12`, `*.pfx` and `id_rsa*`, so
a local experiment cannot become a committed credential.

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
npm run test:ci      # 313 tests, including adversarial rendering, fuzzing and resource limits
npm run check:docs   # documentation claims must match the code

npm run build -- --configuration github-pages
npm run check:security                             # audits, CSP proof, artifact review
node tools/a11y-test.mjs dist/depguard/browser     # contrast, keyboard, semantics
node tools/workflow-test.mjs dist/depguard/browser # full user journey (uses API quota)
```

`check:security` needs a build present, because two of its four parts inspect the artifact
itself rather than the configuration meant to produce it.
[SECURITY-TESTING.md](SECURITY-TESTING.md) maps every requirement to the test that covers
it, and is candid about what is not covered.
