# DepGuard audit remediation report

**Specification:** `docs/audits/AUDIT_REMEDIATION.md`
**Audit:** [DEPGUARD-TECHNICAL-AUDIT.md](DEPGUARD-TECHNICAL-AUDIT.md), 14 November 2026
**Baseline commit:** `d7e6336`
**Completed:** 14 November 2026
**Phases:** A–F, all complete

---

## A. Executive summary

Seventeen audit findings addressed: one P0, eleven P1, five P2. All resolved.

The single most consequential change is the P0: a vulnerability OSV had already confirmed
could disappear when its advisory-detail request failed, and the report then stated "No
known vulnerabilities were found." The scanner's entire value rests on not saying "clean"
when it means "unknown", and this path circumvented every mechanism built to protect that
distinction. It is now impossible: a lost advisory forces a partial result, costs score,
and is named in the report.

The most visible change is dependency discovery. DepGuard previously had exactly one source
of dependency data, so a repository GitHub has no dependency graph for got no dependency
analysis at all — including DepGuard's own, which commits a 587-package lockfile. It now
reads npm and NuGet manifests from the repository when the graph is unavailable, at **zero
additional GitHub API quota**.

Measured on `dukeofwest/depguard`, in the real application against the live APIs:

|                                  | Before |      After |
| -------------------------------- | -----: | ---------: |
| Overall score                    | 83/100 | **91/100** |
| Categories scored                | 3 of 5 | **5 of 5** |
| Evidence coverage                |    50% |    **93%** |
| Dependencies identified          |  **0** |    **587** |
| Dependencies checked against OSV |      0 |    **587** |
| GitHub API requests per scan     |      8 |      **8** |

The score rose because two categories became assessable, not because anything was
loosened. Four separate changes in this work make scores _harder_ to achieve.

Alongside that, the scoring model had five defects where missing or newly-discovered
information moved a score the wrong way — including one where **finding a vulnerability
raised the score by 11 points**. All are fixed, with property tests asserting the
invariants rather than spot-checking them.

**Tests: 313 → 506.** Lint, strict typecheck, format, documentation gate, production
build, CSP proof (24/24), artifact review, accessibility audit and both npm audit gates all
pass. No runtime dependency carries an advisory. No scoring weight was changed.

---

## B. Findings matrix

| Finding | Priority | Status       | Implementation summary                                                                                                                                                                                                                              | Regression test                                                                                                                 |
| ------- | -------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| P0-1    | P0       | **Resolved** | `fetchDetail` returns the advisory id with its record, so a failed detail is retained as `advisoriesUnretrieved` instead of dropped. Forces `kind: 'partial'`, deducts at the `Unknown` severity rate, and the summary can no longer read as clean. | `analysis-pipeline.spec.ts` Scenarios A–D; `osv-api.service.spec.ts` ×5. **Proven to fail against the old behaviour.**          |
| P1-1    | P1       | **Resolved** | New `DependencyDiscoveryService` reads npm and NuGet manifests from tree-listed paths via `raw.githubusercontent.com` when the dependency graph is unavailable.                                                                                     | `npm-lockfile.spec.ts` (587/587 against the real lockfile), `dependency-discovery.service.spec.ts`, `analysis-pipeline.spec.ts` |
| P1-2    | P1       | **Resolved** | `traced()` replaces `optional()`, keeping the typed failure. New `SourceUnavailableReason` union distinguishes not-found / pending / access-denied / rate-limited / network / timeout / cancelled / invalid / unsupported / limit-exceeded / error. | `repository-data.service.spec.ts`; pipeline test asserting a 429 is never rendered as "no dependency graph"                     |
| P1-3    | P1       | **Resolved** | `overall.assessedWeight` added as its own field; both figures named in the explanation and rendered as separately-labelled bars.                                                                                                                    | `scoring.spec.ts` — reproduces the 83 / 60% / 50% report exactly                                                                |
| P1-4    | P1       | **Resolved** | Category renamed "Activity and Recency"; summary states what was weighed and what is not observable.                                                                                                                                                | `scoring.spec.ts`, `dashboard.component.spec.ts`                                                                                |
| P1-5    | P1       | **Resolved** | Coverage counts only signals that can affect the score. `contributorCount` and `daysSinceLastRelease` kept as reported context.                                                                                                                     | `scoring.spec.ts`                                                                                                               |
| P1-6    | P1       | **Resolved** | The `commitsLast52Weeks === 0` deduction removed; `202 Accepted` now reported as `pending`, distinct from a failure.                                                                                                                                | `scoring.spec.ts` (unknown ≤ known); `github-api.service.spec.ts` ×3                                                            |
| P1-7    | P1       | **Resolved** | Dependency-health coverage derived from named dimensions (1 of 3) instead of a hardcoded `1`; summary states what is not assessed.                                                                                                                  | `scoring.spec.ts`                                                                                                               |
| P1-8    | P1       | **Resolved** | CI check consults the file tree for `.github/workflows/*.y*ml` when the Actions API fails; `Unknown` reserved for when neither source is available.                                                                                                 | `security-checks.spec.ts` ×8                                                                                                    |
| P1-9    | P1       | **Resolved** | `Configured` requires a recognised `updates:` section containing a `package-ecosystem`. A listed-but-unfetchable file is `Unknown`, not `Not detected`.                                                                                             | `security-checks.spec.ts` ×8                                                                                                    |
| P1-10   | P1       | **Resolved** | CodeQL check reads workflow **file contents**, fetched from the tree, and requires a real `github/codeql-action` reference. A workflow merely _named_ CodeQL is now `Not detected`.                                                                 | `security-checks.spec.ts` ×7                                                                                                    |
| P1-11   | P1       | **Resolved** | Coverage ceiling applied after deductions, unconditionally.                                                                                                                                                                                         | `scoring.spec.ts` — including the monotonicity property test                                                                    |
| P2-1    | P2       | **Resolved** | Dead divide-then-multiply removed from the coverage formula.                                                                                                                                                                                        | `scoring.spec.ts` — equivalence to the intended formula                                                                         |
| P2-2    | P2       | **Resolved** | Security-policy evidence now states all three searched locations.                                                                                                                                                                                   | `security-checks.spec.ts` ×5                                                                                                    |
| P2-3    | P2       | **Resolved** | The documented tree-truncation fallback does not exist; the comment was corrected rather than the fallback built. No request-count change.                                                                                                          | Existing 8-request budget test                                                                                                  |
| P2-4    | P2       | **Resolved** | `advisoriesOmitted` and `advisoriesUnretrieved` exposed as structured fields on the partial result.                                                                                                                                                 | `osv-api.service.spec.ts` — omission vs failure kept distinct                                                                   |
| P2-5    | P2       | **Resolved** | `NuGet` added to `VERIFIED_ECOSYSTEMS` on measured OSV behaviour, with the four capability questions documented as separate.                                                                                                                        | `nuget.spec.ts` ×4                                                                                                              |

### The three P3 findings

**Not addressed, deliberately.** The audit's summary table counts three P3 findings but
never describes them, and §9.5 of the specification is explicit: do not invent P3
remediation tasks and do not claim they are resolved. They remain outside scope because
their details were never supplied.

---

## C. Changed files, by phase

### Phase A — OSV vulnerability loss (P0-1)

| File                                           | Why                                                                                                                   |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `core/api/osv-api.service.ts`                  | `fetchDetail` pairs each record with its id; `advisoriesUnretrieved` added; omission and failure described separately |
| `core/models/vulnerability.model.ts`           | `partial` carries `advisoriesUnretrieved` and `advisoriesOmitted`                                                     |
| `core/services/repository-analysis.service.ts` | A lost advisory forces `partial`                                                                                      |
| `engine/scoring/category-scorer.ts`            | Unretrieved advisories deduct at the `Unknown` rate; summary cannot claim cleanliness                                 |
| `core/services/analysis-pipeline.spec.ts`      | **New** — end-to-end report assertions                                                                                |
| `core/api/osv-api.service.spec.ts`             | Extended; the existing test asserted only the weaker property                                                         |

### Phase B — scoring, coverage, uncertainty (P1-3…P1-7, P1-11, P2-1)

| File                                          | Why                                                                   |
| --------------------------------------------- | --------------------------------------------------------------------- |
| `core/models/repository.model.ts`             | `SourceState`, `SourceUnavailableReason`, `SourceId`, `WeeklyCommits` |
| `core/models/health-report.model.ts`          | `overall.assessedWeight`                                              |
| `core/models/analysis.model.ts`               | Category renamed                                                      |
| `core/api/github-api.service.ts`              | `getWeeklyCommits` returns three-way state                            |
| `core/services/repository-data.service.ts`    | `traced()`; `sourceStates` assembled                                  |
| `engine/scoring/overall-scorer.ts`            | Two figures named; dead arithmetic removed                            |
| `engine/scoring/category-scorer.ts`           | Unconditional ceiling; maintenance corrections; health coverage       |
| `engine/report/schema.ts`                     | Schema 1.0.0 → 1.1.0, additive                                        |
| `features/dashboard/dashboard.component.html` | Both percentages labelled                                             |
| `engine/scoring/scoring.spec.ts`              | Ceiling, monotonicity, coverage invariants                            |

### Phase C — npm discovery (P1-1, P1-2)

| File                                             | Why                                                                             |
| ------------------------------------------------ | ------------------------------------------------------------------------------- |
| `engine/dependencies/npm-lockfile.ts`            | **New** — v1/v2/v3 parser, prototype-safe, iterative, bounded                   |
| `engine/dependencies/inventory.ts`               | **New** — cross-file merge without double-counting                              |
| `core/services/dependency-discovery.service.ts`  | **New** — all discovery I/O                                                     |
| `core/config/api.config.ts`                      | Manifest pattern allowlist, discovery limits, `isDiscoverableManifest`          |
| `core/models/dependency.model.ts`                | `DependencySource`, `VersionResolution`, `DependencyScope`; coverage provenance |
| `engine/sbom/spdx-parser.ts`                     | Provenance on SBOM packages; `queryablePackages` admits only `resolved`         |
| `engine/report/report-builder.ts`                | Provenance, transitive-coverage and discovery-note limitations                  |
| `engine/__fixtures__/package-lock-depguard.json` | **New** — the real 587-package lockfile                                         |

### Phase D — NuGet discovery

| File                                            | Why                                                                   |
| ----------------------------------------------- | --------------------------------------------------------------------- |
| `engine/dependencies/xml.ts`                    | **New** — bounded XML reader; refuses DOCTYPE and all custom entities |
| `engine/dependencies/nuget.ts`                  | **New** — `packages.lock.json`, `packages.config`, project files, CPM |
| `core/config/api.config.ts`                     | Project-file extensions, `maxProjectFiles`, `isProjectFile`           |
| `core/services/dependency-discovery.service.ts` | Two-stage fetch-then-parse so CPM precedes project files              |
| `engine/dependencies/ecosystems.ts`             | NuGet verified; the four questions documented                         |

### Phase E — repository checks (P1-8, P1-9, P1-10, P2-2)

| File                                       | Why                                                                   |
| ------------------------------------------ | --------------------------------------------------------------------- |
| `engine/security/security-checks.ts`       | All four fixes                                                        |
| `core/config/api.config.ts`                | `isWorkflowFile`, `INSPECTED_WORKFLOW_LIMIT`                          |
| `core/services/repository-data.service.ts` | Tree fetched before raw files, so workflow contents can be discovered |
| `engine/security/security-checks.spec.ts`  | **New** — 29 tests including the degradation invariant                |

### Phase F — consistency (P2-3, P2-5, documentation)

| File                                          | Why                                          |
| --------------------------------------------- | -------------------------------------------- |
| `core/config/api.config.ts`                   | Fictional fallback justification corrected   |
| `docs/SCORING.md`                             | Formulas, labels and the two percentages     |
| `docs/audits/DEPENDENCY-ECOSYSTEM-SUPPORT.md` | Rewritten for actual capability              |
| `tools/check-docs.cjs`                        | Gate updated for the renamed category        |
| `engine/parser-fuzz.spec.ts`                  | npm, XML and NuGet added to the seeded sweep |

---

## D. Test results

All commands run from the repository root. Every figure below was observed, not estimated.

```
npm run test:ci        506 passed | 0 failed   (313 at baseline; 13 live tests skipped
                                                without DEPGUARD_LIVE=1)
DEPGUARD_LIVE=1 …      506 passed | 0 failed   (live GitHub and OSV included)
npm run lint           All files pass linting
npm run typecheck      clean (TypeScript 6, strict, noUncheckedIndexedAccess)
npm run format:check   All matched files use Prettier code style
npm run check:docs     All documentation checks passed
npm run build          334.21 kB initial, 86.30 kB transferred
npm run check:csp      24/24 checks passed
npm run check:release   Production artifact review passed
npm run audit:prod     found 0 vulnerabilities
npm run audit:all      0 high, 0 critical (14 moderate paths, 1 root advisory, unchanged)
node tools/a11y-test.mjs       No accessibility failures detected
node tools/smoke-test.mjs      no console errors, no failed requests
```

### End-to-end, in the real application

`node tools/workflow-test.mjs dist/depguard/browser dukeofwest/depguard` — real Chrome,
live GitHub and OSV:

```
score 91/100 (Excellent)   evidence coverage 93%   5 of 5 categories scored
  Dependency Security              97/100
  Dependency Health               100/100
  Security Configuration           75/100
  Activity and Recency            100/100
  Engineering and Project Quality  90/100
all six tabs render · no console errors · no horizontal overflow at 375px
```

`expressjs/express` — the repository with ranges and no committed lockfile:

```
score 79/100 (Good)   evidence coverage 63%   assessed weight 70%
Dependency Security: insufficient data (8 of 53 queryable, below the 50% floor)
```

Both results are correct and were checked by hand. Express's Security Configuration of
70/100 is −20 for having no `SECURITY.md` anywhere in the repository (verified: 404) and
−10 for no dependency review, with CodeQL **credited** — its workflow genuinely invokes
`github/codeql-action/init` and `/analyze`, SHA-pinned, which the new content check reads
correctly.

### Demonstrating the old behaviour failed

§3.3 of the specification asks that a regression test be shown to fail against the old
code. For P0-1 this was done explicitly: reverting `fetchDetail` to drop the id and
re-running produced

```
× Scenario B: a lost advisory detail must not produce a clean result
× Scenario C: keeps the retrieved advisory and discloses the lost one
3 failed | 315 passed
```

The fix was then restored and all tests pass.

### Two defects found by the new tests, during this work

Worth recording, because they are the argument for the tests:

1. **The scoring worked examples** in `SCORING-MODEL.md` §4 were computed by hand during
   the audit, and that arithmetic is what exposed P1-11 — finding a vulnerability raising
   the score. Reading the code had not revealed it.
2. **The degradation invariant** in `security-checks.spec.ts` immediately caught a defect
   in my own first attempt at P1-9: making the Dependabot status depend on file contents
   turned a listed-but-unfetchable config into `Not detected`, which is precisely the
   error P1-8 was about. Now `Unknown`.

---

## E. Security review

### The widened file-discovery boundary

Dependency discovery narrows a documented property: file fetching moves from a **fixed
list of four paths** to **fixed basenames and extensions matched against tree-listed
paths**. This required a documented review before implementation (§6.1), recorded in
[SECURITY-REVIEW.md](SECURITY-REVIEW.md) §2.4 against all ten required points.

What does **not** change: the three-origin allowlist; the prohibition on fetching a path
found inside a file; URL construction and per-segment encoding; the transport-layer
`isAllowedUrl` re-check; the 512 KB per-file bound; the rule that repository content is
never executed.

What changes: the reachable set grows to paths in _this_ repository whose basename or
extension DepGuard compiled in. The attacker-controlled input is which allowlisted names
exist, not the origin or the URL's shape — indistinguishable in effect from a repository
owner naming a file `package-lock.json` today.

Tested directly: a tree containing `.env`, `id_rsa`, `secrets/credentials.json`,
`package-lock.json.bak` and a deploy workflow produces **exactly one** request, for
`package-lock.json`.

### XML parsing

The first XML in the product, so a new untrusted-input surface. It is a purpose-built
bounded reader, not `DOMParser` (a browser global, barred from the pure engine) and not a
library (a new dependency processing untrusted input, which ADR-0005 declined for YAML).

- **Any DOCTYPE is refused outright**, which forecloses the entire XXE and
  entity-expansion class in one rule rather than trying to tell a safe DTD from a hostile
  one. No MSBuild project file has one.
- **Any entity reference other than the five XML built-ins is refused.** Without a DTD one
  cannot be declared, so its presence is malformed or hostile; and this parser never
  consults a DTD, so there is nothing to expand from.
- **Bounded** on size, depth, node count, attributes per element, name length and value
  length, with numeric character references range-checked and surrogates refused.
- Nothing is resolved from outside the string: no network, no file access.

Tested with real XXE and billion-laughs payloads, plus a timing test over seven
pathological shapes.

### Untrusted content handling

- Lockfile keys are attacker-controlled package paths, so every object read goes through
  an `own()`/`ownEntries()` helper using `Object.prototype.hasOwnProperty`, with
  `__proto__` dropped. A naive `obj[key]` walk resolves `constructor` and `toString` to
  inherited values. Tested, including a literal `__proto__` key.
- The v1 lockfile tree and the XML element search are **iterative**. A recursive walker
  would overflow on exactly the input the depth bound exists to reject; tested with a
  5,000-level lockfile.
- Every fetched body passes the existing `parseBoundedJson` bounds before any new parser
  sees it.
- All four new parsers are **total**: 400 seeded fuzz iterations each, asserting that a
  result is always returned and that nothing non-`resolved` ever becomes queryable.

### Resource limits

8 lockfiles and 24 project files per scan, 512 KB per file, 4 MB total, 20,000 entries per
lockfile, 64 levels of nesting. Reaching any limit is reported as incomplete discovery,
never absorbed. Fetches are sequential and cancellable; unsubscribing abandons the queue.

### GitHub request budget

**Unchanged at 8.** Discovery reuses the already-fetched tree and reads contents from
`raw.githubusercontent.com`, which is outside the API quota. Asserted by a test that counts
`api.github.com` requests across a full fallback scan and requires exactly 8.

---

## F. Dependency support matrix

Full detail in [DEPENDENCY-ECOSYSTEM-SUPPORT.md](DEPENDENCY-ECOSYSTEM-SUPPORT.md).

| Source                         | Status                                                                      | Versions                    |
| ------------------------------ | --------------------------------------------------------------------------- | --------------------------- |
| GitHub dependency graph / SBOM | Supported and tested                                                        | Resolved                    |
| npm `package-lock.json` v1     | **Supported and tested**                                                    | **Resolved**                |
| npm `package-lock.json` v2     | **Supported and tested**                                                    | **Resolved**                |
| npm `package-lock.json` v3     | **Supported and tested**                                                    | **Resolved**                |
| npm `npm-shrinkwrap.json`      | **Supported and tested**                                                    | **Resolved**                |
| NuGet via SBOM                 | Supported (ingestion path tested; no live .NET SBOM exists to test against) | Resolved                    |
| `packages.lock.json`           | **Supported and tested**                                                    | **Resolved**                |
| `packages.config`              | **Supported and tested**                                                    | **Resolved**                |
| `.csproj`                      | **Supported and tested**                                                    | **Declared only**           |
| `.vbproj`                      | **Supported and tested**                                                    | **Declared only**           |
| `.fsproj`                      | **Supported and tested**                                                    | **Declared only**           |
| `Directory.Packages.props`     | **Supported and tested**                                                    | Supplies declared versions  |
| `Directory.Build.props`        | **Supported and tested**                                                    | Supplies literal properties |
| `.sln`                         | Not supported                                                               | —                           |
| `yarn.lock`, `pnpm-lock.yaml`  | Not supported (reported as such)                                            | —                           |

**Declared is not resolved, and the distinction is enforced in code.**
`<PackageReference Version="13.0.1" />` means `[13.0.1, )` — a minimum. Only
`packages.lock.json`, `packages.config` and NuGet's bracketed `[13.0.1]` yield `resolved`,
and `queryablePackages` admits nothing else. A .NET repository without a lockfile therefore
reports insufficient data rather than a score, which is the correct answer and the same one
DepGuard already gave an npm repository with no lockfile.

---

## G. Known limitations

1. **A .NET repository without `packages.lock.json` has no checkable dependencies.** Not a
   gap to close by guessing — `dotnet/machinelearning` has 83 `.csproj` files and zero
   lockfiles, so this is the common case, and the report says what to do about it.
2. **`.csproj` transitive dependencies are invisible.** Not approximated.
3. **MSBuild is not evaluated.** Conditions and non-literal properties stay unresolved;
   conditional references are listed with the uncertainty recorded.
4. **`yarn.lock` and `pnpm-lock.yaml` are unread.** Reported as unsupported, not ignored.
5. **Five of eight ecosystems have never had their OSV matching exercised** against live
   data.
6. **No version freshness or deprecation detection.** Dependency Health reports 1 of 3
   intended dimensions.
7. **Monorepo discovery is bounded**, so a repository with more than 8 lockfiles or 24
   project files is sampled; reported as partial.
8. **OSV's NuGet normalisation is measured, not contractual.** Regression-tested so a
   change would be caught, but it could change.
9. **No live .NET SBOM was ever examined** — neither .NET repository sampled has a
   dependency graph.
10. **A truncated file tree** means manifests may exist that DepGuard never saw; reported
    as `cannot-determine`.
11. **OSV partial retrieval** now costs score and is disclosed, but an unretrieved advisory
    still cannot be described.
12. **DepGuard never proves a repository is secure**, and nothing here changes that.

---

## H. Remaining audit findings

None of the seventeen specified findings is unresolved.

The three P3 findings are **not** addressed, because the audit never described them (§9.5).

---

## I. Final scope confirmation

| Question                           | Answer                                                                                                                                                                                                                                              |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Existing architecture preserved?   | **Yes.** Engine still pure — no I/O, DOM, clock or randomness; enforced by ESLint and `engine-purity.spec.ts`, which caught a local variable named `document` during this work. All new I/O is in `core/services`; all new parsing is in `engine/`. |
| Unrelated architecture modified?   | **No.** No component, style or unrelated module was touched. No file renamed. One category label changed, which an audit finding required.                                                                                                          |
| New runtime dependency introduced? | **No.** No YAML parser, no XML library, no semver library. `package.json` dependencies are unchanged — hence the hand-written bounded XML reader.                                                                                                   |
| Scoring weights changed?           | **No.** `CATEGORY_WEIGHTS` is byte-identical. Four _formulas_ changed, each from a specific finding, each documented with before/after behaviour.                                                                                                   |
| Security boundary widened?         | **Yes, one, deliberately and with a documented review.** File fetching moved from fixed paths to fixed patterns over tree-listed paths. No origin added, no arbitrary URL fetching. [SECURITY-REVIEW.md](SECURITY-REVIEW.md) §2.4.                  |
| Angular or TypeScript migrated?    | **No.** Angular 22.2.6, TypeScript 6.0.3, as found. (§2.1 of the specification says "Angular 21"; the repository was already on 22 at the baseline commit, and nothing here changed it.)                                                            |
| `any` introduced?                  | **No.** Strict mode clean.                                                                                                                                                                                                                          |
| Tests weakened or removed?         | **No.** Six existing tests were updated because the behaviour they asserted was the behaviour a finding identified as wrong; each now asserts the corrected contract, and every update is listed in §C. None was deleted or skipped.                |
| Committed or pushed?               | **No.** Working tree only, as instructed.                                                                                                                                                                                                           |

### Scoring impact, as constraint 14 requires

No weights changed, but four formulas did, so here is what moves:

| Change                                          | Direction                | Effect                                                                             |
| ----------------------------------------------- | ------------------------ | ---------------------------------------------------------------------------------- |
| Unconditional coverage ceiling (P1-11)          | **Lower**                | A partially-covered repository with findings loses the points it previously gained |
| Lost advisory deducts (P0-1)                    | **Lower**                | A scan with unretrieved advisories can no longer score as clean                    |
| Dependabot requires real config (P1-9)          | **Lower**                | An empty `dependabot.yml` loses 25 points                                          |
| CodeQL requires a real action reference (P1-10) | **Lower**                | A workflow named CodeQL that does nothing loses 15 points                          |
| Commit-activity deduction removed (P1-6)        | Higher for known-zero    | Removes an asymmetry; unknown can no longer beat known                             |
| Maintenance coverage (P1-5)                     | Higher coverage          | Stops unscored signals reducing confidence in a number they cannot affect          |
| Dependency-health coverage (P1-7)               | **Lower coverage**       | 1 → 0.333; stops overstating what was assessed                                     |
| CI from the tree (P1-8)                         | Higher                   | An Actions API failure no longer costs 15 points                                   |
| Discovery fallback (P1-1)                       | Higher, where it applies | Categories become assessable; the scores themselves are not loosened               |

Net effect on DepGuard's own report: 83 → 91, with coverage 50% → 93%. The rise comes
from two categories becoming assessable at all, not from any threshold being relaxed.

---

## J. Closing statement

Recorded here because it is the standard the work above was held to, and the standard any
later change to it should be held to.

> DepGuard's own security posture should follow the same principle as its analysis
> results. Report what the evidence supports, disclose what it doesn't, and never claim
> more than has been demonstrated.

Applied to this remediation, that means the following are **three different claims** and
are not interchangeable:

| Claim                      | What it means here                                                                           |
| -------------------------- | -------------------------------------------------------------------------------------------- |
| **Implemented**            | The code exists and the gates pass                                                           |
| **Demonstrated**           | A test fails when the implementation is removed, so the test measures the behaviour it names |
| **Independently verified** | Someone other than the implementer opened the source and re-ran it                           |

The aggregate byte budget, the UTF-8 accounting and the P0 advisory fix are
**demonstrated**: each was proved by reverting the implementation and watching named tests
fail — 25 requests instead of 9, a 1,600-byte body accepted against a 1,000-byte
allowance, two scenarios losing their advisory. The rest of the remediation is
**implemented** and covered by tests that pass, which is a weaker statement and is meant
to be.

The review of November 2026 states its own position in the same terms: it assessed the
evidence and test results supplied, and did not independently open the modified source or
re-run the suite. That distinction is preserved rather than smoothed over.

**Status: remediation complete, with documented residual limitations.** Not "secure" —
which is a claim DepGuard is built never to make about any repository, including its own.
