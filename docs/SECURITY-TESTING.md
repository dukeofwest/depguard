# Security testing

How DepGuard's security properties are tested, how to run the tests, and how to add to
them.

The principle behind all of it: **a control that is not tested is a claim, not a control.**
And a tool that exits zero has not proved anything on its own — its findings still have to
be read.

---

## Running everything

```bash
npm ci                  # never npm install in CI; the lockfile is the input
npm run lint            # includes the engine purity rules
npm run typecheck       # strict tsc, including noUncheckedIndexedAccess
npm run test:ci         # the unit and fuzz suites
npm run check:docs      # documentation claims must match the code
npm run build -- --configuration github-pages
npm run check:security  # audits + CSP proof + artifact review
```

`check:security` is the aggregate gate and needs a build present, because two of its four
parts inspect the actual artifact:

```bash
npm run audit:prod      # runtime dependencies, gated at low
npm run audit:all       # whole tree, gated at high
npm run check:csp       # CSP enforcement proof in real Chrome
npm run check:release   # production artifact review
```

Opt-in live tests, which spend the hourly GitHub quota:

```bash
DEPGUARD_LIVE=1 npm run test:ci
```

On Windows PowerShell, use `npm.cmd` if the execution policy blocks `npm.ps1`.

---

## What is tested, and where

| Requirement                     | Test                                                                | Location                                                                   |
| ------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| XSS payloads                    | Eight payloads through the real engine into the real components     | `features/dashboard/untrusted-content.spec.ts`                             |
| Angular template syntax in data | `{{1+1}}` renders as text, never evaluated                          | `features/dashboard/untrusted-content.spec.ts`                             |
| Malicious repository URLs       | Loopback, private ranges, cloud metadata, IPv6, decimal and hex IPs | `core/utils/github-url.spec.ts`                                            |
| Malformed URLs                  | Traversal, lookalike hosts, credentials, ports, over-long input     | `core/utils/github-url.spec.ts`                                            |
| Unexpected API response types   | Every field wrongly typed or absent                                 | `core/api/github-api.service.spec.ts`                                      |
| Malformed SBOM files            | Thirteen malformed shapes, none of which may throw                  | `engine/sbom/spdx-parser.spec.ts`                                          |
| Oversized SBOM files            | Size rejection before parsing; `Content-Length` cap                 | `core/api/response-guard.spec.ts`, `github-api.service.spec.ts`            |
| Excessive JSON nesting          | Boundary, boundary ± 1, and a 200,000-level bomb                    | `engine/validation/external-input.spec.ts`                                 |
| Excessive dependency counts     | The 20,000 package cap, and 20,000-package timing                   | `engine/sbom/spdx-parser.spec.ts`, `engine/performance.spec.ts`            |
| Duplicate package entries       | Counted, kept in the inventory, collapsed before querying           | `engine/parser-fuzz.spec.ts`, `spdx-parser.spec.ts`                        |
| Invalid package URLs            | Fuzzed purls; nothing non-exact may ever be queryable               | `engine/parser-fuzz.spec.ts`                                               |
| Malicious metadata strings      | Over-long values truncated, not dropped                             | `engine/validation/external-input.spec.ts`                                 |
| Unexpected redirects            | Every request must target an approved origin                        | `core/security.spec.ts`                                                    |
| External link validation        | Only `https:` survives; `rel` is correct on every link              | `features/dashboard/untrusted-content.spec.ts`                             |
| API timeouts                    | A request that never answers, with fake timers                      | `core/security.spec.ts`                                                    |
| Request cancellation            | Unsubscribing releases every in-flight request                      | `core/services/repository-data.service.spec.ts`, `osv-api.service.spec.ts` |
| Race conditions                 | A late or superseded result must never reach the page               | `core/security.spec.ts`                                                    |
| Excessive concurrent requests   | Detail fetches bounded to 8 concurrent, 400 total                   | `core/api/osv-api.service.spec.ts`                                         |
| Report export handling          | Escaping, round-trip fidelity, file-name safety, no credentials     | `core/security.spec.ts`                                                    |
| Catastrophic backtracking       | Pathological version strings must classify in linear time           | `engine/parser-fuzz.spec.ts`                                               |
| Engine purity                   | No I/O, DOM, clock or randomness in the engine                      | `engine/engine-purity.spec.ts`                                             |
| CSP enforcement                 | Negative controls in real Chrome                                    | `tools/csp-test.mjs`                                                       |
| Production artifact             | Source maps, dev code, sinks, CSP, secrets, origins                 | `tools/release-review.cjs`                                                 |
| Workflow security               | Zizmor, `--persona=auditor --min-severity=low`                      | CI job `workflows`                                                         |
| Tool scripts parse              | `node --check` over every script in `tools/`                        | `tools/check-docs.cjs`                                                     |
| Dependency advisories           | `npm audit`, gated separately for runtime and build                 | CI job `audit`                                                             |

---

## The four kinds of test, and why each exists

### 1. Unit tests against hostile input

Ordinary Vitest specs. The important ones do not use hand-written fixtures: they push
hostile values through the **real** parser and into the **real** component, because a test
that constructs its own intermediate representation can pass while the actual pipeline
fails.

### 2. Fuzz tests

`engine/parser-fuzz.spec.ts` generates 400 structurally-plausible-but-corrupted documents
per parser and asserts the one contract every parser holds: **totality.** For any input, a
result is returned — never an exception, never a hang.

The generator is a seeded xorshift PRNG rather than `Math.random`, so the suite is
deterministic. A failure is reproducible exactly, and CI cannot be flaky. The seeds are
`0x5eed`, `0xc0ffee`, `0xbeef` and `0xd00d`.

It also asserts invariants that must hold whatever the input:

- `coverage.totalPackages` always equals `packages.length`
- `queryableRatio` is always finite and within `[0, 1]`
- nothing without an exact version is ever queryable (ADR-0002)
- every rendered advisory reference is an `https` URL

To widen the sweep, add values to `NASTY_SCALARS`. Each entry there is a value that has
broken a parser somewhere.

### 3. Browser-driven proofs

Some claims cannot be tested in a unit test, because the thing being asserted is the
browser's behaviour. `tools/csp-test.mjs` drives real headless Chrome over the DevTools
Protocol and, for each control, **attempts the thing the policy should prevent**:

- an injected inline script must not execute
- `eval` must be absent from the bundle (see the honest caveat below)
- a script from an unapproved CDN must be refused
- a `fetch` to `example.com` must be refused, while `api.github.com` stays reachable
- assigning a raw string to `innerHTML` must throw under Trusted Types
- a cross-origin `<base>` injection must be refused
- a form submission to another origin must be blocked

Paired with positive controls — the app mounts, styles apply, tokens resolve — because a
policy that breaks the application is not a success.

This pattern is inherited from `phase-0/BROWSER-CORS-PROOF.md`, which established the
rule: **a security claim about browser behaviour must be demonstrated in a browser.**
Writing this tool immediately found two real defects in a policy that looked correct on
paper, described below.

#### An honest caveat about `eval`

The tool does **not** claim to demonstrate at runtime that `eval` is blocked, and this is
worth understanding before anyone "fixes" it. Chrome exempts DevTools Protocol evaluation
from the page's CSP by design, so `eval('1+1')` issued over CDP succeeds regardless of the
policy. An earlier version of this tool reported that as a failure; the result was
meaningless either way.

What is asserted instead is checkable and sufficient:

1. the delivered policy text grants no `'unsafe-eval'`, and
2. the shipped bundle contains no `eval(` call site and no `new Function(`.

A tool that reports a result it cannot actually measure is worse than one that says what
it does not know.

### 4. Static review of the artifact

`tools/release-review.cjs` inspects the files that will actually be published, not the
configuration meant to produce them. The distinction matters: a build option can be set
correctly and still not take effect.

It checks source maps, development-mode code, dynamic evaluation, the full CSP, inline
script, asset paths, the base href, credential-shaped values, and that every external
origin reachable from the bundle is one of nine reviewed hosts.

---

## Interpreting `npm audit`

Two gates, deliberately different.

**Runtime dependencies — `npm audit --omit=dev --audit-level=low`.** Anything here ships
to a visitor's browser, so a single advisory of any severity fails the build. Currently
**zero**. There are only six runtime dependencies, which is why this gate is realistic.

**The whole tree — `npm audit --audit-level=high`.** The build toolchain. A high or
critical finding fails the build; moderates are reported and triaged, not ignored.

A count from `npm audit` is a count of dependency _paths_, not of distinct problems. It
reported 31 moderate advisories before the Angular 22 upgrade, which were **two** root
advisories (`glob` and `minimatch`) reached by 31 paths; it now reports 14, which are
**one** root advisory (`minimatch`) reached by 14 paths. Read the advisory list, not the
number. The current triage is in [SECURITY.md](SECURITY.md).

The release gate from the requirements is "no unresolved critical or high-severity
application security issue". Resolving the one critical finding that existed — a Vitest
advisory requiring the UI server, which this project never runs — meant upgrading to a
version that exposed an unrelated npm bug. Both are documented in
[SECURITY.md](SECURITY.md); the point is that it was fixed rather than argued away on
reachability grounds, which would have been the easier answer.

---

## Defects this testing has actually found

Listed because a test suite's value is what it catches, not its size.

| Found by                       | Defect                                                                                                                         |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| `tools/csp-test.mjs`           | `base-uri 'none'` blocked the `<base href="/depguard/">` that GitHub Pages project sites require                               |
| `tools/csp-test.mjs`           | `style-src-attr 'unsafe-inline'` does not cover Angular's runtime-injected `<style>` elements; the page rendered unstyled      |
| `tools/release-review.cjs`     | An unreviewed origin (`angular.dev`) reachable from the bundle — benign, in framework error strings, but previously unexamined |
| URL parser probe               | `https://user:token@github.com/owner/repo` was accepted, silently discarding the credential                                    |
| URL parser probe               | `https://github.com:8080/owner/repo` was accepted                                                                              |
| `core/security.spec.ts`        | The export file name could contain `..` for a repository named `..`                                                            |
| `core/security.spec.ts`        | The export left `<` and `>` unescaped, so a report forwarded and served as HTML could carry live markup                        |
| `tools/check-docs.cjs`         | A patch left a duplicated import in three browser tools; only one of them runs in CI, so the breakage was otherwise invisible  |
| `engine/engine-purity.spec.ts` | Three real purity violations that code review missed                                                                           |
| `tools/a11y-test.mjs`          | Eleven WCAG AA contrast failures in the original palette                                                                       |
| `tools/screenshot.mjs`         | A locale bug rendering `69.679` stars on an `en` page — only visible in a rendered screenshot                                  |

---

## Adding a security test

1. **Write it against the real pipeline.** Hostile package names belong in an SBOM passed
   to `parseSbom`, not in a hand-built `NormalizedPackage`.
2. **Assert the absence of the dangerous outcome, not the presence of a sanitiser.** Check
   that no `<script>` element exists in the DOM, not that a function was called.
3. **Include a negative control** whenever testing that something is blocked. A test that
   only ever sees "blocked" cannot tell you whether the mechanism works or whether the
   attempt was malformed.
4. **Prefer a boundary value and one either side of it** to a single arbitrary case.
5. **If it concerns browser behaviour, test it in a browser** and wire it into CI.

## Known gaps in this testing

Stated plainly, because the requirements ask for the limits of the assessment as well as
its results.

- **Chrome only.** The browser-driven checks run headless Chrome. Nothing relies on
  Chrome-specific behaviour, but Firefox and Safari are an assumption, not a measurement.
  Tracked in [ROADMAP.md](ROADMAP.md).
- **No independent audit or penetration test.** All of this was written by the same people
  who wrote the code.
- **No production CSP violation reporting**, because that needs an endpoint. The CI proof
  compensates before release, but a violation occurring in a real visitor's browser is not
  observed.
- **Six OSV ecosystems unverified against live data** — mapped from documentation only.
- **The fuzzers are structure-aware, not coverage-guided.** They generate plausible
  documents with corrupted fields; they do not explore branches a coverage-guided fuzzer
  would reach.
