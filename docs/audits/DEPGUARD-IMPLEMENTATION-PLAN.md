# DepGuard implementation plan

> **Status: historical record.** The plan has been executed. Phases A–F are complete; see [AUDIT-REMEDIATION-REPORT.md](AUDIT-REMEDIATION-REPORT.md).

Derived from [DEPGUARD-TECHNICAL-AUDIT.md](DEPGUARD-TECHNICAL-AUDIT.md). Finding IDs (P0-1, P1-8 …)
refer to that document's §9 table.

**Status: awaiting approval. No application code has been changed.**

---

## 1. Shape of the work

Five phases. A and B are independent of everything else and can land immediately. C and D are the
feature work and depend on B. E is optional.

```
Phase A  Correctness fixes          no new concepts, no model changes      ◄── start here
Phase B  Provenance in the model    additive, defaulted                    ◄── gate for C and D
Phase C  npm fallback discovery     needs B + a security decision
Phase D  NuGet fallback discovery   needs B, C's harness
Phase E  Further ecosystems         needs D
```

Phase A is deliberately first and deliberately boring. It fixes a scanner that can report clean
when it has lost data. Nothing else should ship before it.

---

## 2. Phase A — correctness fixes

No new features, no model changes, no new dependencies. Each item is independent of every other.

### A1 — P0-1: never report `completed` after losing an advisory

**Severity:** critical. **Complexity:** low (~10 lines + tests).

`fetchDetails` already knows the matched advisory IDs. After the `reduce`, compare the IDs that
produced a record against `idsToFetch`; the difference is the set lost to transport failure. When
non-empty, set `failureReason`, which `repository-analysis.service.ts:157` already turns into
`kind: 'partial'`. The entire downstream path — partial rendering, the summary wording, the
category gate — exists and needs no change.

**Tests (write first, watch them fail):**

- The only matched advisory's detail request fails → `failureReason` is non-null; the report is
  `partial`; the summary does **not** say "No known vulnerabilities were found".
- One of two fails → `partial`, one finding, the loss named and counted.
- Extend `osv-api.service.spec.ts:204` to assert the reporting, not just the survival.

**Regression risk:** low. Repositories with flaky OSV detail requests will move from a clean score
to `insufficient-data` for Dependency Security. That is the point, and it is a visible change in
output that should be called out in the release note.

### A2 — P1-8: an Actions API failure must not read as "no CI"

**Complexity:** low. Match `.github/workflows/*.yml` and `*.yaml` in the already-fetched tree.
Status logic becomes: Actions API list, else tree-listed workflow files, else the six other CI
files, else `Unknown` when neither the workflow list nor an untruncated tree is available, else
`Not detected`. Record in the evidence which source was used.

**Tests:** workflows `null` + tree containing `.github/workflows/ci.yml` → `Configured`, sourced
from the tree. Workflows `null` + tree `null` → `Unknown`. Workflows `null` + untruncated tree with
no CI anywhere → `Not detected`.

### A3 — P1-9: Dependabot status must agree with its evidence

**Complexity:** low. A file with no recognisable `updates:` section is not full credit. Options,
in preference order:

1. `Configured` only with an `updates:` section; otherwise a partial-credit status.
2. Keep `Configured` but split the check so the points reflect the finding.

Option 1 needs no new `CheckStatus` member if the no-`updates` case maps to `Not detected` with
evidence explaining that a file was found but declared nothing — slightly harsh, and honest. **This
is a scoring-behaviour change and needs the user's decision**, since §13 constraint 14 requires
rationale and demonstrated impact for anything that moves a score.

### A4 — P1-6: unknown commit activity must not outscore known-zero

**Complexity:** low, but needs a decision. Today `commitsLast52Weeks === 0` costs 15 and `null`
costs nothing. Recommended: **remove the 15-point deduction entirely.** GitHub's `202` response is
common, uncorrelated with quality, and the signal is already fully carried by
`daysSinceLastPush`, which is always available and never ambiguous. A deduction that fires only
when GitHub happens to have finished a computation is not a measurement.

Alternative, if the signal is wanted: keep the deduction and treat `null` as a coverage penalty
heavy enough to push the category below the 0.5 floor on its own. That is worse — it would make
`insufficient-data` the normal outcome for Maintenance.

### A5 — P1-5 and P1-4: make the maintenance category say what it measures

**Complexity:** low. Two parts:

- Either give `contributorCount` and `daysSinceLastRelease` scoring effect, or stop counting them in
  the coverage denominator. **Recommended: remove them from the denominator** and report them as
  context. A signal that cannot change the score should not be able to reduce confidence in it.
  This raises the reported maintenance coverage for most repositories (for
  `dukeofwest/depguard`: 0.50 → 1.00) and therefore moves `overall.coverage`; the release note must
  say so.
- Retitle the category to name recency (for example "Activity"), or keep the name and state the
  narrowing in the category summary. **User's call** — it is a product-vocabulary decision, and the
  report schema is versioned.

### A6 — P1-3 and P2-1: label the two percentages, and delete the dead arithmetic

**Complexity:** low. Emit the two quantities under names that cannot be confused — for example
`overall.coverage` (evidence depth) alongside `overall.assessedWeight` (share of intended analysis)
— and have the explanation sentence name both. Replace `Σ(cov×w)/W × W` with `Σ(cov×w)` and a
comment saying what it is.

This is a **schema change** (`report/schema.ts`, `schemaVersion`), so it should land with A7.

### A7 — P1-7 and P1-2: stop over-claiming coverage and cause

- Dependency health: replace the literal `coverage: 1` with a figure reflecting the dimensions
  actually assessed, and name the unassessed ones in the summary.
- Distinguish discovery failures: thread the real cause (rate limit, network, 403, malformed,
  genuinely absent) through `RepositoryDataService.optional` instead of flattening to `null`, so
  the report stops asserting "GitHub has no dependency graph for this repository" when it was a
  rate limit. This is the §4.5 state machine in miniature, and doing it in Phase A means Phase C
  inherits it.

### A8 — P2-2, P2-3, P2-5: documentation and evidence accuracy

Add `docs/SECURITY.md` to the security-policy `checked` text. Either build the tree-truncation
fallback `api.config.ts:46` describes or correct the comment — correcting it is right; the current
behaviour is already correct and costs nothing. Promote `NuGet` into `VERIFIED_ECOSYSTEMS` **only
once Phase D's tests exist** — the §3.2 measurements verify OSV matching, not DepGuard's discovery.

### P1-10 — the CodeQL check

Two ways to make the code and its docblock agree. Fetching the candidate workflow from
`raw.githubusercontent.com` and requiring a real `github/codeql-action` reference costs no quota and
delivers what the comment promises; it also needs the same path-allowlist widening as Phase C, so
**defer it to Phase C** and in the meantime correct the docblock to describe filename inference.
Lowering the claim is a one-line change and should be in Phase A.

### A9 — P1-11: make the dependency-security ceiling unconditional

**Complexity:** low (a two-line change). The clean-but-partial cap currently applies only when
there are no findings, so at 70% coverage a repository with one Low advisory scores 99 while a
clean one scores 88. Apply the ceiling after deductions regardless of the finding set:

```ts
score = Math.min(
  Math.max(0, 100 - totalDeductions),
  coverage.queryableRatio < 1 ? Math.round(60 + 40 * coverage.queryableRatio) : 100,
);
```

**Tests:** property-style — for fixed coverage, adding a finding never raises the score. Plus the
boundary cases at `queryableRatio` 0.5, 0.7 and 1.0.

**Regression risk:** lowers the score for partially-covered repositories that do have findings.
Correct, and in the safe direction, but it is a published-score change and needs the constraint-14
before/after demonstration.

### Phase A acceptance criteria

1. No input can produce `kind: 'completed'` when any matched advisory lost its record.
2. No unavailable data source produces a deduction anywhere in the engine. Asserted by a test that
   walks every check with each source nulled in turn.
3. For every category, score(unknown signal) ≤ score(known-good signal). Property-style test.
4. Every percentage in the report has exactly one meaning, named where it appears.
5. No evidence block understates what was searched, and no docblock claims verification the code
   does not perform.
6. 313 existing tests still pass; the self-analysis still produces a report; the live site works.

---

## 3. Phase B — provenance in the dependency model

**Gate for C and D.** Additive only: every new field gets a value for the existing SBOM path, so
nothing downstream breaks. §4.4 requires provenance, and §13 constraint 12 forbids inventing
resolved versions — neither is expressible in today's model.

### B1 — `NormalizedPackage` additions

```ts
/** Where this dependency was discovered. Never inferred. */
type DependencySource =
  | 'github-sbom'
  | 'package-lock.json'
  | 'npm-shrinkwrap.json'
  | 'pnpm-lock.yaml'
  | 'yarn.lock'
  | 'packages.lock.json'
  | 'csproj'
  | 'vbproj'
  | 'fsproj'
  | 'packages.config'
  | 'directory-packages-props';

/**
 * How much the version string is worth.
 *
 * `resolved`          a lockfile or dependency graph stated the installed version
 * `declared-minimum`  a manifest stated a lower bound, e.g. NuGet Version="13.0.1" = [13.0.1, )
 * `declared-range`    a manifest stated a range, e.g. ^4.17.15
 * `unresolved`        a version exists but could not be determined statically, e.g. $(Prop)
 * `absent`            no version information at all
 */
type VersionResolution =
  'resolved' | 'declared-minimum' | 'declared-range' | 'unresolved' | 'absent';
```

Added to `NormalizedPackage`: `source`, `resolution`, `resolvedVersion: string | null`,
`scope: 'production' | 'development' | 'unknown'`, and `sourcePath: string | null` (the file it came
from, for the evidence block).

**The load-bearing rule — `queryablePackages` admits only `resolution === 'resolved'`.** This is
what prevents a NuGet declared minimum from reaching OSV as an installed version (audit §3.3), and
it is the single invariant most worth a test.

`declared-minimum` and `declared-range` get the existing `version-not-exact` skip reason, so they
reduce `queryableRatio` and are reported as uncheckable rather than guessed at. For a `.csproj`-only
.NET repository this means Dependency Security will usually report `insufficient-data`. **That is
the correct answer**, and the same answer DepGuard already gives for `request/request`.

### B2 — `DependencyCoverage` additions

`inventorySource: DependencySource`, `transitiveCoverage: 'full' | 'partial' | 'none'`,
`discoveryNotes: readonly string[]` (parse limitations, skipped files, unresolved properties).

### B3 — the §4.5 discovery states

One union replacing the current three-way result, so the report can tell these apart: retrieved /
retrieved-empty / partial / parse-failed / unsupported-manifest / no-manifest / graph-unavailable /
access-denied / rate-limited / network-error / limit-exceeded. A8/A7 does the transport half; this
does the engine half.

### Phase B acceptance criteria

1. Every `NormalizedPackage` from the SBOM path carries `source: 'github-sbom'` and
   `resolution: 'resolved'`; existing coverage figures are unchanged, asserted by the existing
   fixtures.
2. No package with `resolution !== 'resolved'` can be returned by `queryablePackages`. Exhaustive
   test over every member of the union.
3. All eleven discovery states are representable and distinguishable in the report.
4. No `any`. Strict mode clean.

---

## 4. Phase C — npm fallback discovery

**Depends on B. Needs a security decision before any code is written.**

### C0 — the security gate (approval required)

Today `api.config.ts:106-115` states that file paths are a **fixed allowlist** and "Paths are never
taken from repository content." Discovery requires fetching paths that vary per repository, which
narrows that property. The proposed replacement, and the reasoning:

- Paths come from the **GitHub git/trees API** — structured metadata about the repository, from an
  allowlisted origin — never from inside a file. A path found in a lockfile is still never fetched.
- A path is fetched only if its **basename matches a fixed pattern allowlist** compiled into the
  application (`package-lock.json`, `*.csproj`, …). The pattern list is as fixed as today's path
  list; only its arity changes.
- The URL is always built as
  `raw.githubusercontent.com/{validated owner}/{validated repo}/{branch}/{path}`, with each segment
  filtered as `getRawFile` already does (empty, `.` and `..` dropped, each segment
  percent-encoded), and `isAllowedUrl` still enforced at the transport layer.
- Bounded: at most N manifest files per scan, each capped by `maxFileContentBytes` (512 KB), with
  a total byte budget across the set. `raw.githubusercontent.com` costs no API quota but does cost
  the visitor's bandwidth and time.

Net effect: the set of reachable URLs grows from "4 fixed paths in this repository" to "paths in
this repository whose basename matches a compiled pattern". It does **not** become arbitrary URL
fetching, and no origin is added. This is a real reduction in a stated guarantee and should be
accepted explicitly, in writing, before implementation — see
[SECURITY-REVIEW.md](SECURITY-REVIEW.md) §2.

### C1 — manifest discovery service

A new `core/services/dependency-discovery.service.ts`: given a snapshot whose SBOM came back
unavailable, select candidate paths from `snapshot.tree`, fetch them within budget, hand the text to
pure engine parsers. It must refuse to run on a truncated tree without saying so — absence from a
truncated list is not absence, and the discovery state must be `partial`, not `no-manifest`.

### C2 — parsers (pure, in `engine/dependencies/npm/`)

Priority order, by value per unit of risk:

1. **`package-lock.json` v2/v3** — `packages` keyed by path, each with an exact `version`, `dev`,
   and `link`/`resolved`. Gives resolved versions, full transitive coverage, and dev/prod
   separation. This is the 587-package case and should be built first and alone.
2. **`package-lock.json` v1** — `dependencies`, nested, recursive. Needs the iterative-traversal
   treatment `checkJsonShape` already uses; a recursive walker would overflow on exactly the hostile
   input it should reject.
3. **`npm-shrinkwrap.json`** — same format, different name. Near-free.
4. **`pnpm-lock.yaml`** — **YAML, and therefore the decision point.** ADR-0005 declined a YAML
   parser for untrusted input. Options: a narrow purpose-built reader for the `packages:` key shape
   only; or skip pnpm and report it as an unsupported-but-recognised manifest. **Recommended:
   report as unsupported in Phase C** and revisit with evidence about prevalence. Do not add a
   general YAML dependency to parse untrusted input.
5. **`yarn.lock`** — custom format; Berry's v2+ is YAML. Same reasoning. Defer.
6. **`package.json` alone** — ranges only, so every entry is `declared-range` and nothing is
   queryable. Worth parsing anyway: it turns "no inventory" into "17 direct dependencies found, none
   checkable because no lockfile is committed", which is a far more useful and more honest report.

Documented handling required for: duplicate paths for one package at one version (keep in the
inventory, dedupe before querying — the existing SBOM rule); aliases (`npm:pkg@1.2.3`); workspace
and `link:`/`file:` entries (not registry packages, not queryable); and unsupported `lockfileVersion`
values (report the version, do not guess the shape).

### C3 — wiring

`repository-analysis.service.ts:108`: when `parseSbom` returns `unavailable`, attempt discovery
before building a no-inventory report. The SBOM stays the preferred source whenever present. The
report must state which source was used and what it does not cover.

### Phase C acceptance criteria

1. `dukeofwest/depguard` yields 587 packages, all `resolved`, `queryableRatio` 1.0, direct/transitive
   and dev/prod populated — matching the measurements in audit §2.2, as a committed fixture.
2. The report names `package-lock.json` as the inventory source wherever it is used.
3. A repository with `package.json` and no lockfile reports direct dependencies with
   `queryableRatio` 0 and `insufficient-data` for Dependency Security — never "no vulnerabilities
   found".
4. A truncated tree never produces `no-manifest`.
5. A recognised-but-unsupported lockfile is reported as such, by name and version.
6. Oversized, malformed, deeply nested and 20,000-package lockfiles are all handled without
   throwing; added to the existing seeded fuzz suite.
7. Scan request count is unchanged at 8. Asserted by the existing budget test.

---

## 5. Phase D — NuGet / .NET discovery

**Depends on B and C's harness.** Audit §3.2 established that OSV matching for NuGet already works,
so this phase is discovery and honesty only.

### D1 — priority order, and why it differs from the brief

The brief lists `.csproj` and `packages.lock.json` as equal-priority. The measurement in audit §2.3
argues otherwise: `dotnet/machinelearning` has 83 `.csproj` files, one
`Directory.Packages.props`, and **zero** `packages.lock.json`. NuGet lockfiles are opt-in and rare.

1. **`packages.lock.json`** — the only source of genuinely `resolved` versions and real transitive
   data. Build first because it is the only format that can make NuGet Dependency Security
   scorable. Extract target framework, package ID, `resolved`, `requested`, and
   `type: Direct|Transitive`. Never read `requested` as `resolved`.
2. **`.csproj` / `.vbproj` / `.fsproj`** — `PackageReference`, as both attribute and child element.
   Yields direct dependencies at `declared-minimum`, and **no transitive dependencies**.
3. **`Directory.Packages.props`** — Central Package Management. `PackageVersion` entries supply
   versions to `PackageReference` elements that omit one. Nearest-ancestor wins; project-level
   `VersionOverride` beats the central value.
4. **`packages.config`** — legacy, flat, `id` + `version` + `targetFramework`. Versions here are
   genuinely exact installed versions, so this is `resolved`. Cheap and worth having.
5. **`Directory.Build.props`, `.sln`** — property context and project discovery. Only if 1–4 prove
   insufficient; the tree already enumerates project files without parsing a solution.

### D2 — the resolution rules (the whole point of the phase)

| Source                                     | Version means             | `resolution`       | Queryable? |
| ------------------------------------------ | ------------------------- | ------------------ | ---------- |
| `packages.lock.json` `resolved`            | installed                 | `resolved`         | **yes**    |
| `packages.config` `version`                | installed                 | `resolved`         | **yes**    |
| `.csproj` `Version="13.0.1"`               | `[13.0.1, )`, a minimum   | `declared-minimum` | **no**     |
| `.csproj` `Version="[13.0.1]"`             | exactly 13.0.1            | `resolved`         | **yes**    |
| `.csproj` `Version="[1.0,2.0)"`            | a range                   | `declared-range`   | no         |
| `.csproj` `Version="13.0.*"`               | a wildcard                | `declared-range`   | no         |
| `.csproj` `Version="$(JsonVersion)"`       | unknown without MSBuild   | `unresolved`       | no         |
| CPM `PackageVersion`                       | as above, by its own form | as above           | as above   |
| `PackageReference` with no version, no CPM | unknown                   | `absent`           | no         |

The third row is the one that matters and the one a reasonable implementation gets wrong. A bare
NuGet `Version` is a lower bound; treating it as installed produces false-positive vulnerability
findings on repositories that are not vulnerable. Audit §3.3 has the full reasoning. The bracketed
form `[13.0.1]` is NuGet's exact-version syntax and is the only single-value form that may be
queried.

MSBuild is never executed (§5.2, constraint 7). Property references are resolved only when the
value is a literal in a file already parsed for another reason; otherwise `unresolved`. Imports are
never followed.

### D3 — XML safety

A new parser class for untrusted input, and the first XML in the product. Requirements: no entity
expansion (no DTD processing, no external entities — the billion-laughs and XXE classes); bounded
depth, node count, attribute count and attribute length, mirroring
`engine/validation/external-input.ts`; total over all inputs; no network access during parsing. The
browser's `DOMParser` in `application/xml` mode does not resolve external entities, which makes it
a defensible choice over a new dependency — but internal entity expansion still needs an explicit
bound, and that must be tested, not assumed.

### Phase D acceptance criteria

1. All of §5.9's ten criteria pass, with the parser layer included — not just SBOM ingestion.
2. A `.csproj` with `Version="13.0.1"` produces `declared-minimum` and is **never** sent to OSV.
   This is the phase's defining test.
3. A `packages.lock.json` produces `resolved` versions, correct direct/transitive classification,
   and real OSV findings, verified against a known-vulnerable package in a committed fixture.
4. CPM resolution is correct across multiple project directories, including nearest-ancestor
   selection and `VersionOverride`.
5. `$(Property)` references that cannot be resolved statically are `unresolved`, never guessed.
6. Malformed, entity-bombed, deeply nested and oversized XML all return a result and never throw;
   added to the fuzz suite.
7. `transitiveCoverage` reports `none` for `.csproj`-only discovery and `full` for
   `packages.lock.json`.
8. Only then may `NuGet` be added to `VERIFIED_ECOSYSTEMS` and the ecosystem document updated.

---

## 6. Phase E — further ecosystems

Python (`requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`), Go (`go.sum`, `go.mod`),
Rust (`Cargo.lock`), Java (`pom.xml`, Gradle lockfiles). Same shape as C and D; `Cargo.lock` and
`go.sum` are the cheapest and give fully resolved data. Not required for the core product.

---

## 7. Dependencies between tasks

```
A1 ─┐
A2 ─┤
A3 ─┼─► independent, any order, no shared files beyond category-scorer/security-checks
A4 ─┤
A5 ─┘
A6 ─┬─► schema change: land together, bump schemaVersion
A7 ─┘
A8 ──► independent
A9 ──► independent

B1 ──► B2 ──► B3 ──┬──► C1 ──► C2 ──► C3
                   └──► D1 ──► D2 ──► D3   (after C's fetch harness exists)
C0 (security approval) ──► C1              (hard gate)
D (tests) ──► A8's VERIFIED_ECOSYSTEMS promotion
C2.6 (package.json) ──► improves the no-lockfile report independently of C2.1
```

---

## 8. Regression risks

| Risk                                                                 | Where                               | Mitigation                                                                                        |
| -------------------------------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------- |
| A1 moves clean repositories to `insufficient-data` when OSV is flaky | Dependency Security                 | Intended. Call out in the release note; the partial state is already rendered                     |
| A4/A5 change Maintenance scores and coverage for most repositories   | Maintenance, `overall.coverage`     | Document before/after for the six §7.5 example repositories; demonstrate impact per constraint 14 |
| A3 changes a 25-point check                                          | Security configuration              | Needs the user's decision first                                                                   |
| A6 changes the report schema                                         | Export, UI, `report-export.service` | Bump `schemaVersion`; update the schema test; the export is versioned for exactly this            |
| Phase C narrows a stated security property                           | `api.config.ts`, `getRawFile`       | C0 gate; explicit written approval; documented in SECURITY-REVIEW                                 |
| Phase C/D add scan latency and bandwidth                             | Perceived performance               | Hard caps on file count and total bytes; measure before merging; quota cost stays 0               |
| A NuGet declared minimum leaks to OSV                                | Dependency Security                 | B1's `queryablePackages` invariant, with an exhaustive test                                       |
| XML parsing introduces a new untrusted-input surface                 | Phase D                             | D3's bounds; fuzz suite; no new dependency                                                        |
| Discovery disagrees with the SBOM where both exist                   | Dependency inventory                | SBOM stays authoritative; compare the two on repositories that have both, as a diagnostic         |

---

## 9. What this plan deliberately does not do

- **No weight changes.** `ADR-0003`'s rationale stands and the audit found no evidence against it.
- **No new runtime dependencies.** No YAML parser, no XML library, no semver library. Phase C defers
  pnpm and Yarn rather than taking a parser for untrusted input.
- **No backend, no Nx, no authentication.** Constraints 5, 6, and the v1.0 no-credentials decision.
- **No architectural redesign.** Every change above fits the existing layering; the engine stays
  pure and the discovery service sits beside `RepositoryDataService`, not through it.
- **No ecosystem claimed before its tests exist.** Constraint 13; this is why A8's
  `VERIFIED_ECOSYSTEMS` promotion is gated on Phase D.

---

## 10. Decisions needed before implementation starts

1. **C0 — the path-allowlist widening.** Fixed paths → fixed patterns over tree-listed paths.
   Required before any discovery code. The security reasoning is in §4 above and
   [SECURITY-REVIEW.md](SECURITY-REVIEW.md) §2.
2. **A3 — Dependabot without an `updates:` section.** Partial credit, or no credit?
3. **A4 — the `commitsLast52Weeks === 0` deduction.** Recommend removing it.
4. **A5 — the Maintenance category name.** Rename to "Activity", or keep and narrow the summary?
5. **Phase order.** Recommend A → B → C(npm) → D(NuGet). The brief asks for npm and NuGet both done
   properly; npm first delivers a verifiable 587-package result against a known fixture and builds
   the harness D needs.

Phase A items A1, A2, A6, A7 and A8 need no decision and can begin on approval.
