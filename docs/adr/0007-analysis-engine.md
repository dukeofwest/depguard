# ADR-0007: Analysis engine design

- **Status:** Accepted (Phase 3)
- **Date:** 2026-11-13

## Context

Phase 3 implements the pure TypeScript engine: SBOM parsing, dependency normalisation,
vulnerability processing, repository checks, scoring, recommendations and report
assembly. It must be deterministic, Angular-free and explainable (§4.4, §6.5).

## Decisions

### 1. Engine data lives in the engine

The purity test caught two real violations during implementation: `purl.ts` imported the
purl-to-ecosystem map, and `report-builder.ts` imported the report schema version, both as
_values_ from `core/models`. Type-only imports are erased at compile time and are
permitted; value imports are a genuine runtime dependency on the application layer.

Both constants moved into the engine (`engine/dependencies/ecosystems.ts` and
`engine/report/schema.ts`), which is also where they belong conceptually — they are
analysis data, not shared application vocabulary.

Worth recording because the violations were not obvious while writing the code. The
guardrail, not review, is what caught them.

### 2. Severity is read, never computed

DepGuard does not derive a CVSS base score from a vector string. Computing one would mean
publishing a severity the advisory never stated, and Phase 0 showed it would gain almost
nothing: GHSA records always carry a qualitative severity, while every PYSEC record
measured (22 of 22) had no severity data at all — not even a vector to compute from.

Severity therefore comes from `database_specific.severity` or is `Unknown`. CVSS vectors
are displayed unconverted as evidence. `SeveritySource` has no `cvss-vector` member,
so the code cannot drift back toward deriving one.

Unknown severities are scored as Medium rather than ignored — ignoring them would let
advisories from sources that publish no rating vanish from the score — and the category
summary states how many were scored that way.

### 3. Deduplication keys on the CVE

Real OSV data returns the same vulnerability from several databases. The fixtures include
`GHSA-v6rh-hp5x-86rv` and `PYSEC-2021-439`, both describing CVE-2021-44420. Findings are
keyed on the CVE alias where one exists, falling back to the advisory id.

Merging prefers the record that actually published a severity, so processing order cannot
decide the outcome. A test asserts order-independence explicitly.

### 4. Coverage floors are enforced in the type system

`CategoryResult` is a discriminated union of `scored` and `insufficient-data`. A category
that cannot be assessed has no `score` field at all, so it is structurally impossible to
render a missing category as zero.

The same applies to `VulnerabilityResult`, where `not-applicable` ("nothing could be
checked") is a distinct variant from `completed` with no findings ("checked, found
nothing"). The `request/request` case — 0 of 41 packages checkable — is the reason this
distinction exists, and is covered by end-to-end tests asserting the report says
"not evidence" rather than reporting a clean result.

### 5. `Unknown` checks reduce coverage instead of scoring

Checks with `Unknown` or `Not applicable` status are excluded from both the numerator and
denominator of a category score. A test asserts that a repository with two unknown checks
scores identically to one with those checks configured, while its coverage drops — unknown
neither penalises nor rewards.

A truncated file tree is what usually produces `Unknown`: a path absent from a truncated
listing is not evidence the file is missing. Crucially, no recommendation is generated
from an `Unknown` status, since advising someone to add a file that may already exist is
advice based on an assumption (§7.1).

### 6. No YAML parser

The Dependabot check confirms the file declares an `updates:` section using a line-level
regular expression rather than parsing YAML. The claim being made is narrow — that update
configuration is present — and it does not justify adding a parser dependency that
processes untrusted repository content (ADR-0005).

### 7. Time is a parameter

The engine never calls `Date.now()` or `new Date()`; the current instant is passed into
`buildReport`. This is what makes identical input produce byte-identical output, asserted
by comparing serialised reports. The purity test enforces it, so the rule cannot erode.

### 8. Recommendations group by package, not by advisory

A reader upgrades a package once even when five advisories affect it, so recommendations
are grouped per package with the highest severity driving priority. Priorities follow
§7.2: only real advisories reach Critical or High, a missing README is Low, and a missing
security policy is Medium — never presented as a confirmed vulnerability.

The lockfile recommendation is the one that distinguishes DepGuard: it turns the product's
main limitation into actionable advice, and is raised to High when low coverage blocks
security analysis entirely.
