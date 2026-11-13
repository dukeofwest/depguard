# Scoring methodology

DepGuard's score is a **heuristic assessment of observable repository signals**. It is not
a security certification, and a high score does not mean the code is secure. This document
describes exactly how it is produced, so that any number in a report can be traced back to
the finding that caused it.

The rules here are implemented in [`src/app/engine/scoring/`](../src/app/engine/scoring/)
and were approved in [ADR-0003](adr/0003-scoring-model.md).

## The two rules everything follows

1. **Unavailable data is neither zero nor full marks.** A check that could not be
   performed is excluded from the calculation and reduces _coverage_ instead.
2. **Every lost point is traceable.** A category score is 100 minus itemised deductions,
   each naming the finding that caused it.

## Category weights

| Category                        | Weight |
| ------------------------------- | -----: |
| Dependency Security             |    30% |
| Security Configuration          |    25% |
| Maintenance and Activity        |    20% |
| Engineering and Project Quality |    15% |
| Dependency Health               |    10% |

These differ from the specification's opening proposal (35/15/20/15/15). Phase 0 measured
that Dependency Security — the category the specification weighted highest — is the one
most often _unscorable_, while Maintenance and Security Configuration are the most
reliably observable. Weighting toward what can actually be measured keeps the overall
score stable across repositories instead of lurching when an SBOM is missing.

## Coverage, and why it is shown next to every score

Coverage is the proportion of the intended analysis that completed. It is displayed with
equal prominence to the score, because **a score of 92 at 45% coverage is not the same
claim as a score of 92 at 100% coverage**.

Each check resolves to one of four statuses:

| Status           | Meaning           | Effect on score                         |
| ---------------- | ----------------- | --------------------------------------- |
| `Configured`     | Found             | Counts toward the score                 |
| `Not detected`   | Looked, not found | Counts toward the score, as a deduction |
| `Unknown`        | Could not look    | **Excluded**; reduces coverage          |
| `Not applicable` | Does not apply    | **Excluded**; reduces coverage          |

`Unknown` usually means the repository's file list was truncated — GitHub returns a
partial tree for very large repositories — so a missing path is not evidence of absence.
No recommendation is ever generated from an `Unknown` status, because advising someone to
add a file that may already exist is advice based on an assumption.

## When a category produces no score

A category reports **Insufficient data** instead of a score when:

- its coverage is below **0.5**, or
- (Dependency Security only) fewer than **50% of dependencies** could be checked.

Its weight is then redistributed proportionally across the categories that _could_ be
scored, so absence neither inflates nor deflates the result. If less than 50% of total
weight remains scorable, **no overall score is shown at all** — a number nobody can stand
behind is worse than no number.

### Why Dependency Security has an extra gate

GitHub reports dependency versions as the manifest declares them. Without a committed
lockfile those are ranges (`^1.2.1`), not resolved versions, and a range cannot be matched
against an advisory database. Phase 0 measured OSV-queryable coverage ranging from 84.9%
(`npm/cli`, which commits a lockfile) down to **0%** (`request/request`, which does not).

A repository where nothing can be checked would otherwise display "no vulnerabilities
found" — the most damaging thing this product could say. Instead it reports insufficient
data and states plainly that this is _not evidence the dependencies are safe_.

## Dependency Security deductions

Starting from 100, per **deduplicated** advisory:

| Severity | Points |
| -------- | -----: |
| Critical |    −15 |
| High     |     −8 |
| Medium   |     −3 |
| Low      |     −1 |
| Unknown  |     −3 |

Total deductions are capped at **−60**.

`Unknown` is weighted as Medium rather than ignored. Ignoring it would let advisories from
sources that publish no severity vanish from the score entirely — and every PYSEC record
measured in Phase 0 (22 of 22) had no severity data at all. The category summary states
how many advisories were scored this way.

Advisories are deduplicated on their CVE alias, because the same vulnerability is
published by several databases. Three packages queried in Phase 0 returned 94 advisory IDs
across GHSA, PYSEC, GO and RUSTSEC, with GHSA and PYSEC describing the _same_ Django CVEs.

### A clean result is capped by how much was checked

A repository with no detected vulnerabilities does **not** automatically score 100. The
maximum is bounded by the proportion of dependencies actually examined, because unchecked
packages are unknown, not safe.

## Worked example: `npm/cli`

Measured against the live APIs:

```
1,026 of 1,208 packages queryable (84.9%)
54 deduplicated advisories: 3 Critical, 32 High, 15 Medium, 4 Low

raw deduction = 3(15) + 32(8) + 15(3) + 4(1) = 350
capped at 60                                 → score 40/100
coverage 0.849 ≥ 0.5                         → category is scorable
```

The cap is load-bearing. Without it, any large repository floors at 0 and the score stops
distinguishing "some problems" from "catastrophic". 40 still reads clearly as poor.

## Worked example: `request/request`

```
0 of 41 packages queryable (0% < 50% floor)
→ Dependency Security: INSUFFICIENT DATA, no score
→ its 30% weight redistributed across the other four categories
→ report states: "Most versions are declared as ranges, which usually means no lockfile
  is committed. This is not evidence that the dependencies are free of vulnerabilities."
```

## Other categories

**Security Configuration** — six checks, weighted by security consequence: Dependabot
config (25), security policy (20), CodeQL workflow (15), CI (15), licence (15), dependency
review (10).

**Maintenance and Activity** — archived repositories deduct 70 and are not additionally
penalised for staleness. Otherwise: no commits for over a year −40, none in 90 days −15,
no commit activity recorded in 52 weeks −15. Coverage reflects how many of the four
activity signals were available.

**Engineering and Project Quality** — README (30), test configuration (30), contributing
guide (15), project description (15), code of conduct (10).

**Dependency Health** — inventory completeness only. Deliberately thin, and weighted
lowest, because version freshness and deprecation detection are out of scope for this
release: no reliable free data source exists for them.

## Activity thresholds

Defined once, in [`thresholds.ts`](../src/app/engine/health/thresholds.ts):

| Classification    | Condition                |
| ----------------- | ------------------------ |
| Archived          | Repository is archived   |
| Recently active   | Pushed within 30 days    |
| Active            | Pushed within 90 days    |
| Limited activity  | Pushed within 365 days   |
| Potentially stale | Pushed over 365 days ago |
| Insufficient data | No usable date           |

A low commit count is **not** treated as evidence of poor quality. A mature project may
legitimately need very few changes, and the report says so.

## Score bands

| Range  | Label           |
| ------ | --------------- |
| 90–100 | Excellent       |
| 75–89  | Good            |
| 60–74  | Fair            |
| 40–59  | Needs attention |
| 0–39   | Poor            |

Always shown next to coverage and the disclaimer that this is DepGuard's heuristic
assessment, not a formal security rating.

## A known tension

Because an unscorable category is excluded and its weight redistributed, a repository
whose dependencies could not be checked at all can still score highly on the strength of
its documentation, licensing and activity. `psf/requests` scores 92 ("Excellent") with
Dependency Security reporting insufficient data.

The report states this in three places — the coverage figure, the explanation naming how
much of the analysis completed, and a "Needs attention first" entry — but the headline
number alone does not convey it. This follows the specification's own model (§6.2, §6.3);
capping the band when a security category is unassessable would be a defensible
alternative and is recorded in [ROADMAP.md](ROADMAP.md) as an open question.

## Determinism

The same snapshot, the same vulnerability data and the same timestamp always produce a
byte-identical report. The engine never reads the clock or a random source — the current
time is passed in as an argument — and this is enforced by a test, not by convention.
