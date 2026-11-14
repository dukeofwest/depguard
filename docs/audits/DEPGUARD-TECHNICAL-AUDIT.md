# DepGuard technical audit

> **Status: historical record.** This describes the implementation as it stood at `d7e6336`, before remediation. Every finding below has since been addressed — see [AUDIT-REMEDIATION-REPORT.md](AUDIT-REMEDIATION-REPORT.md) for what changed and [DEPENDENCY-ECOSYSTEM-SUPPORT.md](DEPENDENCY-ECOSYSTEM-SUPPORT.md) for current capability. It is kept unedited so the evidence behind each finding stays checkable.

**Date:** 14 November 2026
**Scope:** the implementation on `main` at `d7e6336`, audited against the DepGuard self-analysis
report of the same date (`depguard-dukeofwest-depguard-2026-11-14.json`).
**Status:** audit only. No application code was modified. Every claim below was traced to a file
and line, or measured against a live API; measurements are labelled as such.

---

## 0. Summary

The implementation is, with one exception, more careful than the assignment anticipated. The
`insufficient-data` plumbing is real and load-bearing; `Unknown` genuinely never collapses into
`Not detected`; version classification is deliberately conservative and documented; the engine is
pure and the purity is enforced by a test. The audit found **no** instance of the headline risks
§6 warns about — "no severity means low severity", "unsupported means clean", "a missing version
can be matched" — except one, which is severe.

Three things need stating plainly:

1. **One confirmed P0.** A failed OSV advisory-detail request erases a vulnerability OSV has
   already confirmed, and the report then says "No known vulnerabilities were found." This is the
   exact failure mode the project's own ADR-0002 exists to prevent, and it is enshrined in a
   passing test.

2. **The missing dependency inventory is not DepGuard's fault — but it is DepGuard's problem.**
   GitHub genuinely has no dependency graph for `dukeofwest/depguard` (measured: 404 even with an
   authenticated token). The SBOM integration is correct. Meanwhile `package-lock.json` sits in
   the repository with **587 packages, all 587 carrying exact resolved versions**, reachable from
   the browser at zero API cost. The inventory was reported as unavailable while a complete,
   fully-resolved one was one free request away.

3. **The 50% / 60% discrepancy is not an arithmetic bug.** Both numbers are correct and measure
   different quantities. It is a reporting defect: two unlike percentages are presented adjacently
   with nothing to distinguish them.

### Finding counts

| Priority                              | Count |
| ------------------------------------- | ----: |
| P0 — critical correctness or security |     1 |
| P1 — important functional gaps        |    11 |
| P2 — improvements                     |     5 |
| P3 — future                           |     3 |

---

## 1. Architecture

### 1.1 Layering

```
src/app/
  core/        Angular layer. All I/O, all HTTP, all state.
    api/       github-api.service, osv-api.service, response-guard, github-response
    config/    api.config          — origin allowlist, every limit
    models/    the shared vocabulary (types only)
    services/  repository-data, repository-analysis, cache, rate-limit, report-export
    state/     scan.store          — signals
    utils/     github-url          — input validation
  engine/      Pure. No I/O, no DOM, no clock, no randomness.
    dependencies/ purl, ecosystems
    sbom/         spdx-parser
    security/     security-checks, vulnerability-processor
    health/       maintenance-analyzer, engineering-analyzer, thresholds
    scoring/      category-scorer, overall-scorer, weights
    report/       report-builder, schema
    validation/   external-input   — bounds shared by engine parsers
  features/    Standalone components, OnPush, zoneless
  shared/      Presentational components
```

Engine purity is enforced two ways: an ESLint rule and `engine/engine-purity.spec.ts`. The
constraint that the engine may import only **types** from `core/` is why
`engine/dependencies/ecosystems.ts` and `engine/validation/external-input.ts` exist where they do
rather than in `core/config`. This is sound and should be preserved — it is the reason the scoring
engine is testable without HTTP mocks.

**Assessment: preserve.** The assignment's instruction not to redesign unnecessarily is correct
here. Every change this audit recommends fits inside the existing layering.

### 1.2 Execution path

| Stage                                                                         | File                                             | Function                 | In                | Out                                  | On error                                    |
| ----------------------------------------------------------------------------- | ------------------------------------------------ | ------------------------ | ----------------- | ------------------------------------ | ------------------------------------------- |
| URL validation                                                                | `core/utils/github-url.ts`                       | `parseRepositoryUrl`     | user string       | `RepositoryRef` or typed rejection   | typed rejection with remedy                 |
| Metadata                                                                      | `core/api/github-api.service.ts:93`              | `getRepository`          | ref               | `RepositoryMetadata`                 | **fails the scan** (only required request)  |
| Tree, workflows, release, contributors, languages, commit activity, raw files | `github-api.service.ts:134-261`                  | 6 methods + `getRawFile` | ref, branch       | typed or `null`                      | `null` via `RepositoryDataService.optional` |
| Snapshot assembly                                                             | `core/services/repository-data.service.ts:34`    | `loadSnapshot`           | ref               | `RepositorySnapshot`                 | partial snapshot                            |
| SBOM                                                                          | `github-api.service.ts:116`                      | `getSbom`                | ref               | `unknown` or `null`                  | `null` on 404                               |
| SBOM parse                                                                    | `engine/sbom/spdx-parser.ts:55`                  | `parseSbom`              | body, maxPackages | `parsed` / `unavailable` / `invalid` | total — never throws                        |
| Queryable filter                                                              | `spdx-parser.ts:328`                             | `queryablePackages`      | packages          | exact-version subset, deduped        | n/a                                         |
| OSV batch                                                                     | `core/api/osv-api.service.ts`                    | `queryPackages`          | packages          | matches + records + counts           | degrades to partial                         |
| Advisory processing                                                           | `engine/security/vulnerability-processor.ts:219` | `processVulnerabilities` | records, matches  | findings                             | skips malformed                             |
| Category scores                                                               | `engine/scoring/category-scorer.ts`              | 5 `score*` functions     | signals           | `scored` / `insufficient-data`       | n/a                                         |
| Overall score                                                                 | `engine/scoring/overall-scorer.ts:20`            | `calculateOverall`       | categories        | `scored` / `unavailable`             | n/a                                         |
| Report                                                                        | `engine/report/report-builder.ts`                | `buildReport`            | everything        | `HealthReport`                       | n/a                                         |

Orchestration is `core/services/repository-analysis.service.ts:61` (`analyse`), which emits
progress as work completes. Cancellation is by unsubscription and is tested.

**Request budget:** 8 quota-consuming requests per scan, asserted by a test against
`RATE_LIMIT.requestsPerScan`. File contents come from `raw.githubusercontent.com`, which costs no
quota — measured and confirmed in §2.3 below. This is the single most important architectural fact
for everything in the implementation plan.

---

## 2. Dependency discovery — the priority investigation

### 2.1 Why DepGuard could not analyse its own dependencies

**Measured, 14 November 2026:**

```
GET /repos/dukeofwest/depguard/dependency-graph/sbom      → 404  (anonymous)
GET /repos/dukeofwest/depguard/dependency-graph/sbom      → 404  (authenticated)
GET /repos/expressjs/express/dependency-graph/sbom        → 200, 38,798 bytes (anonymous)
GET /repos/Newtonsoft/Newtonsoft.Json/dependency-graph/sbom → 404 (anonymous)
```

**Conclusion: the implementation is not at fault.** The endpoint, headers, API version, 404
handling and `unavailable` reporting are all correct. GitHub has no dependency graph for this
repository, and no amount of client-side correctness changes that. The 404 persists with an
authenticated token, so it is not an anonymous-access limitation either.

Two consequences worth recording:

- The repository has working Dependabot _version_ updates (eight pull requests were raised and
  resolved on 13–14 November) while having no dependency graph. These are independent GitHub
  features. A reader of the report could reasonably conclude the opposite.
- `repository.security_and_analysis` reports `dependabot_security_updates: disabled`. The
  dependency graph has no field in that object at all, so DepGuard cannot distinguish "disabled by
  the owner" from "not yet generated" even with authentication. The report should not try.

### 2.2 What was actually available

`package-lock.json` is committed, and was served from `raw.githubusercontent.com` during this
audit:

```
GET raw.githubusercontent.com/dukeofwest/depguard/main/package-lock.json
→ 200, Content-Length: 318,984, Access-Control-Allow-Origin: *
```

Parsed:

|                                                  |                |
| ------------------------------------------------ | -------------: |
| `lockfileVersion`                                |              3 |
| `node_modules/` entries                          |            587 |
| entries with an **exact resolved** version       | **587 (100%)** |
| production                                       |              6 |
| development                                      |            581 |
| direct (root `dependencies` + `devDependencies`) |             17 |

So the report's "No dependency inventory was available" was true of GitHub's dependency graph and
false of the repository. A fully-resolved, 100%-queryable inventory — the best quality of inventory
DepGuard's model can represent — was one zero-quota request away.

This is **P1-1**, and it is the single highest-value change available to the product.

### 2.3 Fallback feasibility — measured, not assumed

The user specifically asked whether dependencies can be discovered when the dependency graph is
unavailable. Three things had to be true. All three are:

1. **Paths are discoverable without extra quota.** The recursive tree is _already fetched_ for
   every scan (`getTree`, used by the security and engineering checks). For
   `dotnet/machinelearning` it returned 4,955 entries, `truncated: false`, in one request.
2. **File contents are reachable from the browser.** `raw.githubusercontent.com` returns
   `Access-Control-Allow-Origin: *` and costs no API quota — measured above.
3. **Manifests exist in the wild in a parseable shape.** Confirmed below.

`dotnet/machinelearning`, manifests found in the already-fetched tree:

| Pattern                    | Count |
| -------------------------- | ----: |
| `*.csproj`                 |    83 |
| `*.fsproj`                 |     1 |
| `Directory.Packages.props` |     1 |
| `Directory.Build.props`    |    10 |
| `*.sln`                    |     1 |
| **`packages.lock.json`**   | **0** |
| `packages.config`          |     0 |

**This is the most important measurement in the audit for .NET.** The NuGet lockfile is opt-in
(`RestorePackagesWithLockFile`) and is largely absent from real repositories. .NET discovery will
therefore usually produce **declared** versions from `.csproj` plus Central Package Management,
and **no transitive dependencies at all**. §3.3 explains why that cannot be treated as resolved
data.

### 2.4 Discovery state handling (§4.5)

The current implementation collapses the eleven required states into three
(`parsed` / `unavailable` / `invalid`), and `RepositoryDataService.optional` flattens every
transport failure — rate limit, network error, 403 — into `null`, which `parseSbom` then reports as
`"GitHub has no dependency graph for this repository."`

That sentence is **wrong** when the real cause was a rate limit or a network failure. It asserts a
fact about GitHub's state from an absence of evidence. It does not inflate any score — both
dependency categories still report `insufficient-data` — so it is a reporting-accuracy defect
rather than a scoring one. Recorded as **P1-2**.

---

## 3. .NET / NuGet support

Each layer assessed independently, as instructed.

### 3.1 Layer 1 — SBOM ingestion: **works**

`engine/dependencies/ecosystems.ts:22` maps purl type `nuget` → OSV ecosystem `NuGet`. A GitHub
SBOM for a .NET repository would be normalised, classified and queried correctly. Not demonstrated
against a live .NET SBOM, because none of the .NET repositories sampled has a dependency graph.

### 3.2 Layer 2 — OSV matching for NuGet: **works, and the suspected defects do not exist**

The audit brief asks about name normalization and version matching (§5.8). Both were tested
directly against `POST https://api.osv.dev/v1/querybatch`:

| Query                                        |                Advisories |
| -------------------------------------------- | ------------------------: |
| `Newtonsoft.Json` @ `9.0.1`                  | 1 (`GHSA-5crp-9r3c-p9vr`) |
| `newtonsoft.json` @ `9.0.1`                  |                  1 (same) |
| `NEWTONSOFT.JSON` @ `9.0.1`                  |                  1 (same) |
| `Newtonsoft.Json` @ `9.0.1.0` (4-part)       |                  1 (same) |
| `System.Text.Encodings.Web` @ `4.5.0`        | 1 (`GHSA-ghhp-997w-qr28`) |
| `System.Text.Encodings.Web` @ `4.5` (2-part) |                  1 (same) |
| `Newtonsoft.Json` @ `13.0.3`                 |                         0 |

**OSV normalises NuGet package IDs case-insensitively and normalises NuGet version strings.** The
hypothesised defects — silent misses from casing, or from 2- and 4-part versions — are not real. No
normalization code is needed, and adding any would be speculative. `normalizeVersionForQuery`
strips a leading `v` for non-Go ecosystems, which NuGet versions never carry; harmless.

This result removes a whole class of work from the plan. It is recorded here so nobody re-derives
it, and so nobody "fixes" a problem that does not exist.

### 3.3 Layer 3 — manifest discovery: **absent, and the hard part is honesty, not parsing**

No `.csproj`, `.vbproj`, `.fsproj`, `packages.lock.json`, `packages.config`,
`Directory.Packages.props` or `.sln` parser exists. Nothing in the codebase reads any of them.
Per constraint 13 and §5.9, **NuGet must not be described as supported today.**

The XML parsing is the easy part. The correctness trap is this:

> In NuGet, `<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />` does **not** mean
> "13.0.1 is installed". A bare version is shorthand for the range `[13.0.1, )` — a _minimum_.
> NuGet resolves it to the lowest available version that satisfies it, which is usually 13.0.1 but
> is not guaranteed to be, and transitive resolution can lift it higher.

`classifyVersion` (`engine/dependencies/purl.ts:113`) sees the literal string `13.0.1`, matches
`EXACT_VERSION`, and returns `exact`. A naive .NET fallback would therefore send a _declared
minimum_ to OSV as a _resolved version_.

The consequence is the mirror image of the `lodash@^4.17.15` problem ADR-0002 was written about,
and it is worse, because it is silent in the other direction: if 13.0.1 has an advisory fixed in
13.0.2 and the project actually restored 13.0.3, DepGuard reports a **false positive** — a
confident, plausible, wrong vulnerability finding on a repository that is not vulnerable.

This is not a present defect, because no such parser exists. It is a **binding design constraint**
on the implementation, and the plan treats it as one: see
[DEPGUARD-IMPLEMENTATION-PLAN.md](DEPGUARD-IMPLEMENTATION-PLAN.md) Phase D.

### 3.4 Verdict against the §5.9 acceptance criteria

| #   | Criterion                                         | Status                                                                   |
| --- | ------------------------------------------------- | ------------------------------------------------------------------------ |
| 1   | Discovers NuGet dependencies from supported files | **No**                                                                   |
| 2   | Correctly extracts package identities             | **No** (no parser)                                                       |
| 3   | Identifies resolved versions when available       | **No**                                                                   |
| 4   | Distinguishes direct and transitive               | Partially — the model has `relationship`, nothing populates it for NuGet |
| 5   | Generates correct NuGet package identifiers       | **Yes**, for SBOM input                                                  |
| 6   | Queries OSV with the correct ecosystem            | **Yes**, verified live (§3.2)                                            |
| 7   | Reports matching vulnerabilities correctly        | **Yes**, for SBOM input                                                  |
| 8   | Handles unresolved versions honestly              | **Yes** — the mechanism exists and is strict                             |
| 9   | Handles malformed project files safely            | **Not applicable** (no parser)                                           |
| 10  | Displays dependency source and limitations        | **No** — the model carries no provenance field                           |

---

## 4. OSV vulnerability matching

### P0-1 — a failed advisory-detail request erases a confirmed vulnerability

**Files:** `core/api/osv-api.service.ts:183-192` (`fetchDetail`),
`core/api/osv-api.service.ts:160-180` (`fetchDetails`),
`engine/security/vulnerability-processor.ts:235` (`processVulnerabilities`).

**Mechanism.** `querybatch` returns advisory _identifiers_ only, so details are fetched in a second
pass. `fetchDetail` ends with `catchError(() => of(null))`, and the null is dropped by the
accumulating `reduce`. `processVulnerabilities` then iterates **`records`**, not `matches`:

```ts
for (const raw of records) {        // vulnerability-processor.ts:235
```

A match whose detail fetch failed therefore produces no finding. Crucially, nothing records the
loss: `packagesFailed` stays 0 and `failureReason` stays `null`, so
`repository-analysis.service.ts:157-168` builds `{ kind: 'completed', findings: [] }`, and
`category-scorer.ts:202` emits:

> "No known vulnerabilities were found in the N dependencies that could be checked."

**Evidence — the project's own test, `osv-api.service.spec.ts:204`:**

```ts
it('continues when a single advisory detail request fails', () => {
  // ... querybatch returns GHSA-1 and GHSA-2
  httpMock.expectOne('.../v1/vulns/GHSA-1').flush({ id: 'GHSA-1' });
  httpMock.expectOne('.../v1/vulns/GHSA-2').flush({}, { status: 500, ... });
  expect(result.records).toHaveLength(1);   // the only assertion
});
```

The test asserts that one record survives. It never asserts that the loss of the other is
reported — and it is not. With a single matched advisory whose detail request fails, the result is
a clean bill of health for a package OSV has just confirmed as vulnerable.

**Impact.** Severity: critical. This is "no response means no vulnerability", which §6 forbids
explicitly and which the project's own `docs/SECURITY.md` calls the most damaging thing DepGuard
could say. Likelihood is low per advisory but rises with advisory count, and any transient OSV 5xx
or timeout triggers it.

**Fix.** Count matched advisory IDs that produced no record; when non-zero, set `failureReason` and
force `kind: 'partial'`. The downstream partial-result plumbing already exists and is already
rendered — only the signal is missing. Roughly ten lines.

**Required tests.** Detail request fails for the _only_ matched advisory → result is `partial`, not
`completed`, and the summary does not claim cleanliness. Detail fails for one of two → `partial`,
one finding, loss named. Both as deterministic `HttpTestingController` cases.

### What is correct

Verified by reading, and recorded because the brief asks specifically about these assumptions:

- **No severity is not Low.** `readSeverity` yields `Unknown`, weighted as Medium
  (`weights.ts:43`), with the weighting disclosed in the category summary.
- **Unsupported is not clean.** Packages with no OSV ecosystem get `skipReason`
  `unsupported-ecosystem`, are never queried, and reduce `queryableRatio`.
- **A missing version is never matched.** `queryablePackages` admits only `exact`.
- **Withdrawn advisories are excluded** (`vulnerability-processor.ts:284`) — correct, and easy to
  get wrong.
- **Batch limits are measured, not guessed:** 1,000 accepted / 1,001 rejected, chunk size 500,
  detail concurrency 8, detail cap 400 with the omission surfaced as a partial reason.
- **Alias-based deduplication** merges GHSA and PYSEC records for one CVE, preferring the record
  that carries a severity.

---

## 5. Coverage and scoring

Formulas, worked examples and the full model are in [SCORING-MODEL.md](SCORING-MODEL.md). This
section records only the defects.

### 5.1 The 50% vs 60% question — resolved

Reproduced exactly from `overall-scorer.ts` with the report's inputs:

```
scorable: security-configuration (w .25, cov 1.00)
          maintenance            (w .20, cov 0.50)
          engineering            (w .15, cov 1.00)

scorableWeight = .25 + .20 + .15                      = 0.60  → explanation: "60%"
score          = (75(.25) + 100(.20) + 75(.15)) / .60  = 83.33 → 83
coverage       = ((1(.25) + .5(.20) + 1(.15)) / .60) × .60 = 0.50 → report: "50%"
```

Both figures are arithmetically correct and they measure **different quantities**:

- **60%** = the share of total intended analysis _weight_ that could be scored at all.
- **50%** = that same weight discounted by how thinly each scored category was evidenced.

They can never be equal unless every scored category has coverage 1.0. **This is not a bug in the
calculation.** It is a reporting defect: `overall.coverage` and the "60% of the intended analysis"
sentence appear side by side, both rendered as bare percentages, with nothing naming what either
measures. A careful reader concludes the report contradicts itself — which is what happened here.
**P1-3.**

Separately, `overall-scorer.ts:55-66` divides the weighted coverage sum by `scorableWeight` and
then multiplies the result by `scorableWeight` again:

```ts
const coverage = scorable.reduce(...) / scorableWeight;   // :55-59
...
coverage: coverage * scorableWeight,                      // :66
```

The two operations cancel exactly (verified numerically). The emitted value is simply
`Σ(coverage_i × weight_i)`. The intermediate is dead arithmetic that makes a subtle formula look
like a different, more subtle one. **P2-1.**

### 5.2 Maintenance 100/100 — explained

**Nothing is wrong with the arithmetic.** `scoreMaintenance` (`category-scorer.ts:287`) deducts
only for: archived (−70), no push for over a year (−40), no push in 90+ days (−15), and
`commitsLast52Weeks === 0` (−15). The repository was pushed the same day, so no deduction applies
and the score is 100.

Three real problems follow from that:

1. **The category measures push recency, not maintenance.** A one-day-old repository with a single
   commit and one contributor scores a perfect "Maintenance: 100/100". The score is defensible; the
   _label_ over-claims. **P1-4.**

2. **Two of the four coverage signals cannot affect the score at all.**
   `contributorCount` and `daysSinceLastRelease` are counted in the coverage denominator
   (`category-scorer.ts:325-330`) but appear in no deduction. They are pure coverage padding: they
   can only ever lower confidence in a number they never influence. **P1-5.**

3. **Missing data scores better than known-bad data.** This one matters, because it is exactly what
   §7.3 prohibits. `commitsLast52Weeks === 0` costs 15 points; `commitsLast52Weeks === null`
   costs nothing and drops coverage from 1.00 to 0.75 — still far above the 0.5 floor, so the
   category still scores. GitHub returns `202 Accepted` with an empty body for repositories whose
   statistics it has not yet computed, which is exactly the young-repository case. **A repository
   can score higher by being too new for GitHub to have counted its commits than by having
   genuinely made none.** `dukeofwest/depguard` is in precisely that state. **P1-6.**

   The honest fix is not to deduct for unknown. It is to stop letting a 15-point deduction hinge on
   data whose absence is common and uncorrelated with quality — either drop the deduction or make
   the coverage consequence strong enough to be visible.

### 5.3 Dependency health claims full coverage it does not have

`scoreDependencyHealth` (`category-scorer.ts:256-261`) passes `coverage: 1` as a literal, while the
category's own docblock states that version freshness and deprecation detection are out of scope
for lack of a data source. The category therefore reports complete coverage of an analysis it
performs about a third of. The report's own limitations list says freshness is unavailable, so the
report contradicts its own coverage figure. **P1-7.**

---

### 5.4 Finding a vulnerability can raise the score (P1-11)

Found while computing the worked examples in [SCORING-MODEL.md](SCORING-MODEL.md) §4, not by
reading the code — which is the argument for keeping worked examples beside the formulas.

The clean-but-partial cap at `category-scorer.ts:151` is guarded by `findings.length === 0`:

```ts
if (result.kind === 'scored' && findings.length === 0 && coverage.queryableRatio < 1) {
  const cap = Math.round(60 + 40 * coverage.queryableRatio);
```

So at an identical `queryableRatio` of 0.70:

|                 | Deductions | Cap applied?            |  Score |
| --------------- | ---------: | ----------------------- | -----: |
| no findings     |          0 | yes → 88                | **88** |
| one Low finding |          1 | **no** — `findings ≠ ∅` | **99** |

Discovering a vulnerability is worth **+11 points**. The cap's intent is correct — partial coverage
must not score 100 — but it is written as a special case for the clean path rather than as a
ceiling on the category, so any non-empty finding set escapes it entirely. Scoring is
non-monotonic in the number of findings, which is the opposite of what the category is for.

Fix: apply the ceiling after deductions, unconditionally.

```ts
score = Math.min(
  Math.max(0, 100 - totalDeductions),
  coverage.queryableRatio < 1 ? Math.round(60 + 40 * coverage.queryableRatio) : 100,
);
```

**Required test:** a property-style assertion that for fixed coverage, adding a finding never
raises the category score.

---

## 6. Security configuration and repository health checks

The general standard here is high. Every check reports `checked`, `found`, `source`, `explanation`
and often `limitation`; the distinctions §8 insists on (a config file is not an enabled feature; a
workflow is not a passing workflow; a test file is not coverage) are stated in the evidence text of
the checks they apply to. `absenceIsMeaningful` (`security-checks.ts:36`) correctly refuses to
report `Not detected` from a truncated tree.

Four defects.

### P1-8 — an Actions API failure is reported as "no CI"

`security-checks.ts:226-276`. The `Unknown` guard requires **both** sources to be unreadable:

```ts
if (snapshot.workflows === null && !absenceIsMeaningful(snapshot)) {   // :231
```

When the Actions API call fails but the tree is fine — the common case, since
`RepositoryDataService.optional` swallows every transport error to `null` — the check proceeds with
`actions = []` and then searches the tree for _six non-Actions CI files only_
(`.travis.yml`, `.circleci/config.yml`, `.gitlab-ci.yml`, `azure-pipelines.yml`, `Jenkinsfile`,
`.drone.yml`). It never looks for `.github/workflows/*`.

So a repository whose CI is GitHub Actions reports:

> "No CI configuration was found." — Continuous integration: **Not detected**, −15 points.

Unavailable data has become a failure, which constraint 11 forbids. The fix is small and the data
is already in hand: the tree lists `.github/workflows/ci.yml` perfectly well. Match it there, and
reserve `Unknown` for when neither source is readable.

### P1-9 — Dependabot reports "Configured" when its own evidence says otherwise

`security-checks.ts:124-136`. `declaresUpdates` is computed, used to pick the wording of `found`,
and then **not used in the status**:

```ts
const declaresUpdates = /^\s*updates\s*:/m.test(content);
return check(id, label, 'Configured', {
  found: declaresUpdates ? `Found ... declaring an "updates" section.`
                         : `Found ..., but no "updates" section was recognised.`,
```

A `.github/dependabot.yml` containing nothing but a comment scores the full 25 points — the
heaviest single check in the category — while the evidence beside it says no updates section was
recognised. §7.5 requires that the score and the explanation always agree. Here they contradict
each other in the same object.

### P1-10 — the CodeQL check's docblock describes verification it does not perform

`security-checks.ts:140-144` states:

> "Requires that a workflow actually references the CodeQL action, rather than inferring it from a
> filename — `codeql.yml` could contain anything."

The implementation (`:161-163`) regex-matches `workflow.name` and `workflow.path` — which is
inference from the filename and display name, exactly what the comment disclaims. Workflow _file
contents_ are never fetched; `INSPECTED_FILE_PATHS` covers only `dependabot.yml`/`.yaml` and
`SECURITY.md`. A workflow named "CodeQL" that does nothing earns 15 points.

The intent in the comment is achievable at zero quota cost by fetching the workflow file from
`raw.githubusercontent.com`, and is worth doing. Until then the comment should not claim it.

### P2-2 — the security-policy check under-reports what it searched

`security-checks.ts:65` sets `checked: 'SECURITY.md and .github/SECURITY.md'` while `:71` also
searches `docs/SECURITY.md`. The evidence understates the search, which is the benign direction,
but the evidence block is the product's core claim to trustworthiness and should be exact.

### Risk assessment of the remaining checks

| Check                       | False positive                                              | False negative                                         |
| --------------------------- | ----------------------------------------------------------- | ------------------------------------------------------ |
| Security policy             | A stub `SECURITY.md` counts                                 | Non-standard location                                  |
| Dependabot config           | **P1-9**; also cannot see settings-only enablement (stated) | Settings-only enablement (stated)                      |
| CodeQL                      | **P1-10**; name/path match only                             | Default-setup scanning with no workflow file (stated)  |
| Dependency review           | Name/path match only                                        | Action invoked from a differently-named workflow       |
| CI                          | Any workflow counts as CI                                   | **P1-8**                                               |
| Licence                     | GitHub metadata is authoritative; low risk                  | `NOASSERTION` falls through to a file search — correct |
| README / Contributing / CoC | Fixed filename lists                                        | Unusual names                                          |
| Tests                       | Any `*.spec.*` file counts                                  | Unusual layouts (stated)                               |
| Project description         | Exact                                                       | None                                                   |

---

## 7. Application security and resilience

Full detail in [SECURITY-REVIEW.md](SECURITY-REVIEW.md). In brief: this area was hardened
immediately before this audit and is in good shape. Input validation rejects embedded credentials
and non-default ports; the origin allowlist is enforced before every request and re-checked at the
transport layer; responses are taken as text and parsed under explicit size, depth, node and string
bounds; the CSP is enforced with Trusted Types and proved in real Chrome by 24 checks including
negative controls; 313 tests pass; no runtime dependency carries an advisory.

Two items from this audit's scope touch security directly:

- **P0-1 is a security finding as much as a correctness one.** A scanner that reports clean when
  it has lost data is worse than one that fails loudly.
- **The fallback in §2.3 requires a deliberate, documented widening of a stated security
  property** — from a _fixed path allowlist_ to a _fixed pattern allowlist over tree-listed paths_.
  This needs explicit sign-off, not a quiet commit. See
  [SECURITY-REVIEW.md](SECURITY-REVIEW.md) §2 and the plan's Phase C gate.

### P2-3 — `api.config.ts` documents a fallback that does not exist

`api.config.ts:46-49` justifies `minimumRemainingToStart: 10` as leaving "headroom for the
tree-truncation fallback, which costs up to 2 extra requests on very large repositories." No such
fallback exists anywhere in the codebase — a truncated tree is carried through as
`truncated: true` and turns checks into `Unknown`, which is the correct behaviour and costs no
extra requests. The constant is harmless; the justification is fiction and should be corrected or
the fallback built.

---

## 8. Testing

### Strengths

313 tests. Hostile input is pushed through the _real_ parser into the _real_ component rather than
through hand-built intermediate representations. Fuzzing is seeded xorshift (deterministic, 400
documents per parser, four fixed seeds) and asserts invariants rather than snapshots. Purity,
performance, CSP enforcement and the shipped artifact all have their own gates. Live API tests are
opt-in behind `DEPGUARD_LIVE=1` and excluded from CI, as §10 requires.

### Gaps, in priority order

| Gap                                                                                                                   | Priority | Note                                                                                                              |
| --------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Lost advisory detail must produce `partial`, never `completed`                                                        | **P0**   | The existing test at `osv-api.service.spec.ts:204` asserts the weaker property and must be extended, not replaced |
| Actions API `null` + readable tree → CI `Unknown` or `Configured`, never `Not detected`                               | P1       |                                                                                                                   |
| `dependabot.yml` without `updates:` → not full credit                                                                 | P1       |                                                                                                                   |
| `commitsLast52Weeks: null` must not outscore `0`                                                                      | P1       | Property-style assertion: unknown ≤ known-good                                                                    |
| Every one of the eleven §4.5 discovery states                                                                         | P1       | None are distinguishable today                                                                                    |
| npm lockfile parsing: v1/v2/v3, workspaces, aliases, `link:`/`file:`, missing `version`                               | P1       | With Phase C                                                                                                      |
| NuGet: all eight file types, CPM inheritance, project override, `$(Property)` refs, multi-targeting, conditional refs | P1       | With Phase D                                                                                                      |
| **Declared minimum must never be sent to OSV as a resolved version**                                                  | P1       | The single most important new test; see §3.3                                                                      |
| XML safety: entity expansion, deep nesting, oversized attributes                                                      | P1       | With Phase D                                                                                                      |
| Report-level: `overall.coverage` and the explanation percentage must be labelled distinctly                           | P2       |                                                                                                                   |

---

## 9. Confirmed defects

| ID    | Pri    | Defect                                                                                                                                                 | Location                                                   |
| ----- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------- |
| P0-1  | **P0** | Failed advisory detail erases a confirmed vulnerability; result still reported `completed`                                                             | `osv-api.service.ts:183`, `vulnerability-processor.ts:235` |
| P1-1  | P1     | No manifest/lockfile fallback; 587 resolvable packages reported as no inventory                                                                        | `repository-analysis.service.ts:106`                       |
| P1-2  | P1     | Rate limits and network errors reported as "GitHub has no dependency graph"                                                                            | `repository-data.service.ts:115`, `spdx-parser.ts:58`      |
| P1-3  | P1     | Two unlike percentages (50 / 60) presented as if comparable                                                                                            | `overall-scorer.ts:66`, `:89`                              |
| P1-4  | P1     | "Maintenance" measures push recency only                                                                                                               | `category-scorer.ts:287`                                   |
| P1-5  | P1     | `contributorCount`, `daysSinceLastRelease` affect coverage but no score                                                                                | `category-scorer.ts:325`                                   |
| P1-6  | P1     | Unknown commit activity outscores known-zero                                                                                                           | `category-scorer.ts:319`                                   |
| P1-7  | P1     | Dependency health hardcodes `coverage: 1` for a partial analysis                                                                                       | `category-scorer.ts:259`                                   |
| P1-8  | P1     | Actions API failure → CI "Not detected", −15                                                                                                           | `security-checks.ts:231`                                   |
| P1-9  | P1     | Dependabot "Configured" contradicts its own evidence; full 25 points                                                                                   | `security-checks.ts:124`                                   |
| P1-10 | P1     | CodeQL docblock claims content verification; code matches filenames                                                                                    | `security-checks.ts:140`                                   |
| P1-11 | P1     | Clean-but-partial cap applies only when `findings = ∅`, so finding one Low advisory scores 11 points **higher** than finding none at the same coverage | `category-scorer.ts:151`                                   |
| P2-1  | P2     | Dead divide-then-multiply obscures the coverage formula                                                                                                | `overall-scorer.ts:55-66`                                  |
| P2-2  | P2     | Security-policy evidence omits `docs/SECURITY.md`                                                                                                      | `security-checks.ts:65`                                    |
| P2-3  | P2     | Documented tree-truncation fallback does not exist                                                                                                     | `api.config.ts:46`                                         |
| P2-4  | P2     | `advisoriesOmitted` reaches the report only as prose                                                                                                   | `osv-api.service.ts:174`                                   |
| P2-5  | P2     | NuGet absent from `VERIFIED_ECOSYSTEMS` though now verified (§3.2)                                                                                     | `ecosystems.ts:34`                                         |

---

## 10. Unknowns and limitations of this audit

Stated because the brief asks for the limits of the assessment as well as its results.

1. **Why GitHub has no dependency graph for this repository is not established.** Measured that it
   does not; the API exposes no field explaining it. Owner setting, generation lag and an
   unrecognised manifest layout are all consistent with the evidence.
2. **No live .NET SBOM was examined.** Neither .NET repository sampled has a dependency graph, so
   §3.1 rests on code reading and the OSV measurements in §3.2, not on an end-to-end run.
3. **OSV's NuGet normalization is measured behaviour, not a documented contract.** It could change.
   The tests the plan specifies would detect that.
4. **Manifest prevalence comes from a small sample.** Two .NET repositories and one npm repository.
   The `packages.lock.json` finding (§2.3) is consistent with NuGet's opt-in design but is not a
   survey.
5. **The P0 was confirmed by code reading and by the project's own test, not by an induced live
   failure.** The mechanism is unambiguous; a regression test should still be written before the
   fix, so it is seen to fail first.
6. **Scoring weights were not independently validated.** `ADR-0003` documents the rationale and
   §13 constraint 14 forbids changing them without demonstrating impact. This audit proposes no
   weight change.
7. **No performance measurement of the proposed fallback.** Parsing a 319 KB lockfile in-browser
   is expected to be cheap (the 1.1 MB `npm/cli` SBOM parses in 2.8 ms) but has not been measured.

---

## 11. Does the report agree with the implementation?

Checked line by line against the supplied JSON. Every number in the report is reproducible from the
code, and no figure was found that the implementation could not produce:

| Report field                                               | Reproduced                                                                      |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `overall.score: 83`                                        | Yes — §5.1                                                                      |
| `overall.coverage: 0.5`                                    | Yes — §5.1                                                                      |
| `"60% of the intended analysis"`                           | Yes — §5.1; different quantity, correctly computed                              |
| `security-configuration: 75`, deductions 15 + 10           | Yes — `codeql-workflow` 15, `dependency-review` 10                              |
| `maintenance: 100`, coverage `0.5`                         | Yes — §5.2; 2 of 4 signals present                                              |
| `engineering: 75`, deductions 10 + 15                      | Yes — `code-of-conduct` 10, `project-description` 15                            |
| Both dependency categories `insufficient-data`, coverage 0 | Yes — SBOM 404 → `unavailable`                                                  |
| `vulnerabilities.kind: "unavailable"`                      | Yes                                                                             |
| `dataSources`: SBOM and OSV `unavailable`                  | Yes                                                                             |
| `ci-workflow: Configured`, "2 GitHub Actions workflows"    | Yes — and note this is the path that **P1-8** breaks when the Actions API fails |

The report is an accurate rendering of the implementation. Its problems are the implementation's
problems, not presentation errors — with the single exception of **P1-3**, which is purely
presentational.

---

## Deliverables

- [DEPGUARD-IMPLEMENTATION-PLAN.md](DEPGUARD-IMPLEMENTATION-PLAN.md) — prioritised plan, phases,
  dependencies, acceptance criteria, regression risks
- [DEPENDENCY-ECOSYSTEM-SUPPORT.md](DEPENDENCY-ECOSYSTEM-SUPPORT.md) — what is supported **today**
- [SCORING-MODEL.md](SCORING-MODEL.md) — exact formulas as implemented, with worked examples
- [SECURITY-REVIEW.md](SECURITY-REVIEW.md) — security findings and the fallback's security gate
