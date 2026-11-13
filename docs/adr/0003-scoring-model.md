# ADR-0003: Scoring weights, coverage floors and weight redistribution

- **Status:** Proposed (Phase 0) — **requires approval**
- **Date:** 2026-11-13

## Context

Specification §6.1 proposes category weights and explicitly asks that Phase 0 evaluate
whether they are reasonable, recording the outcome in an ADR. §6.2 requires that
unavailable data is treated as neither zero nor full marks.

Phase 0 measurement changed what we know about reliability: the category the
specification weighted highest (Dependency Security, 35%) is the one most often
unavailable, while the categories weighted lowest are the most reliably measurable.

## Decision

### Weights

| Category               | Spec | Adopted | Reason                                                                |
| ---------------------- | ---: | ------: | --------------------------------------------------------------------- |
| Dependency Security    |  35% | **30%** | Most valuable when available, but frequently unscorable (ADR-0002)    |
| Dependency Health      |  15% | **10%** | Thin once freshness and deprecation are out of scope                  |
| Security Configuration |  20% | **25%** | Fully observable for every repository, at zero quota cost             |
| Maintenance & Activity |  15% | **20%** | Highest-reliability signals; the specification's named differentiator |
| Engineering Quality    |  15% | **15%** | Unchanged                                                             |

### Coverage floors and redistribution

- Each category reports `coverage = scorable checks ÷ applicable checks`.
- `Unknown` and `Not applicable` are excluded from **both** numerator and denominator and
  reduce coverage. They never score as 0 and never score as full marks.
- A category below **0.5** coverage returns `Insufficient data`, produces no score, and
  its weight is redistributed proportionally over the scorable categories.
- Dependency Security carries an **additional** floor: at least 50% of packages must be
  OSV-queryable.
- If under 50% of total weight is scorable, **no overall score is displayed** — findings
  only.
- Overall coverage is displayed at equal prominence to the score (§6.3).

### Deductions

Dependency Security starts at 100; per deduplicated advisory: Critical −15, High −8,
Medium −3, Low −1, Unknown −3. Floor 0, total cap −60. A repository with no detected
vulnerabilities cannot reach 100 — the maximum is capped by queryable coverage, because
unchecked packages are unknown, not safe. No finding is deducted in more than one category.

## Worked examples (from real measured data)

**`npm/cli`** — 1,026/1,208 queryable (84.9%); 54 deduplicated advisories: 3 Critical,
32 High, 15 Moderate, 4 Low.

```
3(15) + 32(8) + 15(3) + 4(1) = 350  →  capped at −60  →  40/100
coverage 0.849 ≥ 0.5  →  scorable, weight 30% applies
```

The cap is doing real work here: without it every large repository floors at 0 and the
score stops discriminating. 40/100 still reads correctly as poor.

**`request/request`** — 0/41 queryable.

```
0% < 50% floor  →  Dependency Security = INSUFFICIENT DATA
weight 30% redistributed across the other four
overall score computed from the remaining 70%, rescaled
```

## Consequences

**Positive**

- The overall score is computed from signals we can actually measure, making it stable
  across repositories rather than lurching when an SBOM is missing.
- `Insufficient data` is a distinct state in the type system (`CategoryResult` is a
  discriminated union), so a missing category cannot be accidentally rendered as 0.

**Negative**

- Redistribution means two repositories' overall scores may be computed from different
  weight bases. Mitigated by always showing coverage beside the score and naming which
  categories were excluded.
- The weights remain a judgement call. They are documented, centralised in one module, and
  revisable with evidence.
