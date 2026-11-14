# Scoring model

> **Status: historical record.** This documents the scoring model **before** the November 2026 remediation, including the defects in §5. For the model as implemented today see [../SCORING.md](../SCORING.md); for what changed see [AUDIT-REMEDIATION-REPORT.md](AUDIT-REMEDIATION-REPORT.md).

**This document describes the model as implemented** at `d7e6336`, not a proposed one. Every
formula was read from the code and every example below was computed from those formulas and
checked numerically.

Source: `engine/scoring/weights.ts`, `engine/scoring/category-scorer.ts`,
`engine/scoring/overall-scorer.ts`.

---

## 1. Constants

```
CATEGORY_WEIGHTS           dependency-security      0.30
                           dependency-health        0.10
                           security-configuration   0.25
                           maintenance              0.20
                           engineering              0.15
                                                    ────
                                                    1.00

SEVERITY_DEDUCTIONS        Critical 15   High 8   Medium 3   Low 1   Unknown 3
MAX_SECURITY_DEDUCTION     60
MINIMUM_CATEGORY_COVERAGE  0.5      below this, a category reports insufficient-data
MINIMUM_QUERYABLE_RATIO    0.5      below this, dependency-security reports insufficient-data
MINIMUM_SCORABLE_WEIGHT    0.5      below this, no overall score is produced at all

SCORE_BANDS                >= 90 Excellent   >= 75 Good   >= 60 Fair
                           >= 40 Needs attention   >= 0 Poor
```

`Unknown` severity is weighted as Medium rather than ignored — otherwise advisories from sources
publishing no severity (every PYSEC record measured in Phase 0) would vanish from the score. The
weighting is disclosed in the category summary.

Weights deviate from the specification's opening proposal (35/15/20/15/15) because Dependency
Security — the category weighted highest there — is the one most often unscorable, while Security
Configuration and Maintenance are the most reliably observable. Rationale in `ADR-0003`. **This
audit proposes no change to them.**

---

## 2. Category formulas

### 2.1 Check-based categories (security-configuration, engineering)

```
scorable(C)   = { c in C : status(c) in { Configured, Not detected } }
applicable(C) = { c in C : status(c) != Not applicable }

coverage      = |scorable(C)| / |applicable(C)|            (0 if |applicable| = 0)

if coverage < 0.5 or |scorable(C)| = 0:
    → insufficient-data

deductions    = [ points(c) for c in scorable(C) if status(c) = Not detected ]
score         = clamp(0, 100, 100 - Σ deductions)
```

`Unknown` and `Not applicable` are in neither numerator nor denominator of the score — they reduce
coverage instead. This is the mechanism that keeps "we do not know" from becoming either a pass or
a failure.

Per-check points:

| security-configuration |         | engineering           |         |
| ---------------------- | ------: | --------------------- | ------: |
| `security-policy`      |      20 | `readme`              |      30 |
| `dependabot-config`    |      25 | `contributing`        |      15 |
| `codeql-workflow`      |      15 | `code-of-conduct`     |      10 |
| `dependency-review`    |      10 | `tests`               |      30 |
| `ci-workflow`          |      15 | `project-description` |      15 |
| `license`              |      15 |                       |         |
| **total**              | **100** | **total**             | **100** |

### 2.2 dependency-security

```
if inventory is null                      → insufficient-data (coverage 0)
if vulnerabilities.kind = unavailable     → insufficient-data (coverage 0)
if kind = not-applicable
   or queryableRatio < 0.5                → insufficient-data (coverage = queryableRatio)

raw      = Σ SEVERITY_DEDUCTIONS[severity(f)]  for each deduplicated finding f
if raw > 60:  append one visible adjustment of (60 - raw), so the total becomes exactly 60

score    = clamp(0, 100, 100 - total)
coverage = queryableRatio

# clean-but-partial cap
if findings = ∅ and queryableRatio < 1:
    cap = round(60 + 40 × queryableRatio)
    if score > cap: score = cap, with the shortfall shown as a named deduction
```

The cap exists because unchecked packages are unknown, not safe: a repository where only half the
inventory could be checked must not score 100 for the half that was.

### 2.3 dependency-health

```
if inventory is null or totalPackages = 0 → insufficient-data (coverage 0)

deductions:  no-version         → min(25, round(count / total × 60))
             version-not-exact  → min(35, round(count / total × 50))
             no-purl            → min(15, round(count / total × 30))

score    = clamp(0, 100, 100 - Σ deductions)
coverage = 1                                  ← literal; see §5.3
```

### 2.4 maintenance

```
if classification = Insufficient data → insufficient-data (coverage 0)

deductions:  archived                                      → 70
             else if daysSinceLastPush > 365               → 40
             else if daysSinceLastPush > 90                → 15
             and  if commitsLast52Weeks = 0 (not null)     → 15

score    = clamp(0, 100, 100 - Σ deductions)

coverage = |{ daysSinceLastPush, commitsLast52Weeks,
              contributorCount, daysSinceLastRelease } that are non-null| / 4
```

Note what is absent: no deduction references `contributorCount` or `daysSinceLastRelease`. Both
appear only in the coverage denominator. See §5.2.

Activity classification (`maintenance-analyzer.ts`), from `daysSinceLastPush`:
archived → `Archived`; null or negative → `Insufficient data`; ≤30 → `Recently active`;
≤90 → `Active`; ≤365 → `Limited activity`; else `Potentially stale`.

---

## 3. Overall formulas

Let `S` be the scored categories and `W(i)` the weight of category `i`.

```
assessedWeight = Σ_{i in S} W(i)

if S = ∅ or assessedWeight < 0.5:
    → overall = unavailable

score          = round( Σ_{i in S} score(i) × W(i)  /  assessedWeight )

coverage       = ( Σ_{i in S} coverage(i) × W(i) / assessedWeight ) × assessedWeight
               = Σ_{i in S} coverage(i) × W(i)

band           = first SCORE_BANDS entry whose min <= score
```

Dividing by `assessedWeight` rescales the surviving categories to sum to 1, which is exactly
equivalent to redistributing the excluded weight proportionally. Absence therefore neither inflates
nor deflates the score.

**The coverage line as written in `overall-scorer.ts:55-66` divides by `assessedWeight` and then
multiplies by it again.** The operations cancel; the emitted value is simply `Σ coverage(i) × W(i)`.
Verified numerically. The intermediate is dead arithmetic — see §5.1.

### The two percentages

| Quantity            | Formula                         | In the report                                          | For the depguard self-scan |
| ------------------- | ------------------------------- | ------------------------------------------------------ | -------------------------- |
| **Assessed weight** | `Σ W(i)` over scored categories | the explanation sentence, "% of the intended analysis" | **60%**                    |
| **Coverage**        | `Σ coverage(i) × W(i)`          | `overall.coverage`                                     | **50%**                    |

They measure different things and are equal only when every scored category has coverage 1.0. The
first asks _how much of the analysis ran_; the second asks _how well-evidenced the part that ran
was_. The report presents both as bare percentages with nothing naming either, which is why it
reads as self-contradictory. That is a labelling defect, not a calculation one.

---

## 4. Worked examples

### 4.1 Complete information, no known vulnerabilities

| Category               | Score | Coverage | Weight |
| ---------------------- | ----: | -------: | -----: |
| dependency-security    |   100 |     1.00 |    .30 |
| dependency-health      |   100 |     1.00 |    .10 |
| security-configuration |   100 |     1.00 |    .25 |
| maintenance            |   100 |     1.00 |    .20 |
| engineering            |   100 |     1.00 |    .15 |

`assessedWeight` = 1.00 · **score = 100** · **coverage = 1.00** · band **Excellent**

### 4.2 Known critical vulnerabilities

3 Critical + 2 High ⇒ raw = 3(15) + 2(8) = 61 ⇒ exceeds the 60 cap ⇒ adjustment −1 ⇒ total 60 ⇒
**dependency-security = 40**, coverage 0.90.

| Category               | Score | Coverage | Weight | Contribution |
| ---------------------- | ----: | -------: | -----: | -----------: |
| dependency-security    |    40 |      .90 |    .30 |        12.00 |
| dependency-health      |    90 |     1.00 |    .10 |         9.00 |
| security-configuration |    75 |     1.00 |    .25 |        18.75 |
| maintenance            |   100 |     1.00 |    .20 |        20.00 |
| engineering            |    75 |     1.00 |    .15 |        11.25 |

**score = 71** · **coverage = 0.97** · band **Fair**

### 4.3 No dependency inventory — the actual self-analysis report

Both dependency categories `insufficient-data`, so weight 0.30 + 0.10 = 0.40 is redistributed.

| Category                | Score | Coverage |   Weight |
| ----------------------- | ----: | -------: | -------: |
| ~~dependency-security~~ |     — |        0 | excluded |
| ~~dependency-health~~   |     — |        0 | excluded |
| security-configuration  |    75 |     1.00 |      .25 |
| maintenance             |   100 |     0.50 |      .20 |
| engineering             |    75 |     1.00 |      .15 |

```
assessedWeight = .25 + .20 + .15                             = 0.60   → "60%"
score          = (75(.25) + 100(.20) + 75(.15)) / .60 = 83.33 → 83
coverage       = 1(.25) + .5(.20) + 1(.15)                   = 0.50   → "50%"
```

**score = 83 · coverage = 0.50 · assessed 60% · band Good** — reproduces the supplied report
exactly.

### 4.4 Partially available dependency data

`queryableRatio` = 0.70, no findings ⇒ cap = round(60 + 40(0.70)) = 88 ⇒ score 88, with the
12-point shortfall shown as "N of M dependencies could not be checked".

| Category               | Score | Coverage | Weight | Contribution |
| ---------------------- | ----: | -------: | -----: | -----------: |
| dependency-security    |    88 |      .70 |    .30 |        26.40 |
| dependency-health      |    85 |     1.00 |    .10 |         8.50 |
| security-configuration |    75 |     1.00 |    .25 |        18.75 |
| maintenance            |   100 |      .50 |    .20 |        20.00 |
| engineering            |    75 |     1.00 |    .15 |        11.25 |

**score = 85** · **coverage = 0.81** · band **Good**

### 4.5 Missing security configuration

All six checks `Not detected` ⇒ 20+25+15+10+15+15 = 100 ⇒ **security-configuration = 0**,
coverage 1.0 (the checks all completed; they simply failed).

| Category               | Score | Weight | Contribution |
| ---------------------- | ----: | -----: | -----------: |
| dependency-security    |   100 |    .30 |        30.00 |
| dependency-health      |   100 |    .10 |        10.00 |
| security-configuration |     0 |    .25 |         0.00 |
| maintenance            |   100 |    .20 |        20.00 |
| engineering            |    75 |    .15 |        11.25 |

**score = 71** · band **Fair**. Note the distinction the model preserves: coverage is 1.0 because
everything was assessed. Full coverage, bad result.

### 4.6 A newly created repository — and the asymmetry it exposes

Pushed today, one contributor, no releases, and GitHub has not yet computed commit statistics
(`202 Accepted`, so `commitsLast52Weeks = null`):

|             |   Score | Coverage |
| ----------- | ------: | -------: |
| maintenance | **100** |     0.50 |

No deduction applies. Now the same repository where GitHub _has_ computed statistics and they show
zero commits in 52 weeks:

|             |  Score | Coverage |
| ----------- | -----: | -------: |
| maintenance | **85** |     0.75 |

**Not knowing scores 15 points higher than knowing the answer is bad**, and the coverage penalty
(0.50) is still comfortably above the 0.5 floor, so the category scores either way. §7.3 prohibits
exactly this. See §5.2.

### 4.7 Too little assessed for any overall score

Only dependency-health (0.10) and engineering (0.15) scorable ⇒ `assessedWeight` = 0.25 < 0.50 ⇒

```
overall = { kind: 'unavailable',
            reason: 'Only 25% of the analysis could be completed, which is too little to
                     support an overall score. The individual findings below are still accurate.' }
```

No number is produced. A number nobody can stand behind is worse than no number — and the category
findings are still shown.

---

## 5. Defects in the model as implemented

### 5.1 Dead arithmetic in the coverage formula (P2-1)

`overall-scorer.ts:55-66` computes `Σ(cov×W) / assessedWeight` and then multiplies the result by
`assessedWeight`. The emitted figure is `Σ(cov×W)`. Harmless, but it makes a simple formula look
like a subtler one and invites a "fix" that would change behaviour.

### 5.2 Maintenance: unknown outscores known-bad (P1-6), and two signals cannot score (P1-5)

Demonstrated in §4.6. Two distinct problems:

- `commitsLast52Weeks === 0` costs 15; `null` costs nothing. GitHub returns `202` for repositories
  whose statistics it has not computed — common, and uncorrelated with quality.
- `contributorCount` and `daysSinceLastRelease` are in the coverage denominator but in no
  deduction. They can lower confidence in a number they cannot influence.

The category also measures **push recency only**, so a one-day-old repository with a single commit
scores "Maintenance: 100/100" (P1-4). The arithmetic is right; the label over-claims.

### 5.3 dependency-health claims coverage it does not have (P1-7)

`coverage: 1` is a literal (`category-scorer.ts:259`) while the category's own docblock records that
version freshness and deprecation detection are out of scope for want of a data source. The report's
`limitations` block says freshness is unavailable, so the report contradicts its own coverage
figure.

### 5.4 The clean-but-partial cap makes scoring non-monotonic (P1-11)

The cap in §2.2 applies **only when `findings = ∅`**. At identical coverage, finding a
low-severity vulnerability therefore scores _higher_ than finding none:

| At `queryableRatio` = 0.70 | Deductions | Cap applied?            |  Score |
| -------------------------- | ---------: | ----------------------- | -----: |
| no findings                |          0 | yes, 88                 | **88** |
| one Low finding            |          1 | **no** (`findings ≠ ∅`) | **99** |

An 11-point reward for discovering a vulnerability. The cap's intent is right — partial coverage
must not score 100 — but it is implemented as a special case for the clean path instead of as a
ceiling on the category. The fix is to apply the ceiling after deductions regardless of whether any
finding exists:

```
score = min( clamp(0, 100, 100 - Σ deductions),
             queryableRatio < 1 ? round(60 + 40 × queryableRatio) : 100 )
```

Under that formula the second row scores 88, and more findings always score lower. Found by
computing §4.4 rather than by reading the code — which is the argument for worked examples living
beside the formulas.

---

## 6. What the model gets right

Recorded because the audit brief asks specifically whether missing information can inflate a score,
and with the exceptions above it cannot:

- **Excluded categories are removed, not zeroed.** Weight redistribution means an unscorable
  category neither helps nor hurts.
- **`Unknown` is in neither the numerator nor the denominator** of a check-based score. It reduces
  coverage, which is reported.
- **Every deduction is itemised and traceable** to the finding that caused it; a score is only ever
  100 minus explicit, named deductions.
- **Two independent floors** prevent confident nonsense: a category below 0.5 coverage reports
  `insufficient-data`, and an overall below 0.5 assessed weight produces no number.
- **A third floor is specific to the most dangerous claim:** below 0.5 `queryableRatio`, Dependency
  Security refuses to score, because "no vulnerabilities found" over an unqueryable inventory is the
  single most damaging thing the product could say.
- **The deduction cap is visible**, applied as one named adjustment rather than by silently
  rescaling each finding.
- **Severity-less advisories are weighted, not dropped**, and the weighting is disclosed.

---

## 7. Changes this audit proposes

None to the weights (constraint 14; `ADR-0003`'s rationale stands and no evidence was found against
it).

| Proposal                                                  | Reference |
| --------------------------------------------------------- | --------- |
| Report assessed weight and coverage under distinct names  | plan A6   |
| Remove the dead divide-then-multiply                      | plan A6   |
| Make the dependency-security ceiling unconditional (§5.4) | plan A9   |
| Remove the `commitsLast52Weeks === 0` deduction           | plan A4   |
| Remove unscoring signals from the maintenance denominator | plan A5   |
| Report dependency-health coverage honestly                | plan A7   |
| Rename maintenance, or narrow its stated claim            | plan A5   |

Each changes at least one published score, so each needs the before/after demonstration constraint
14 requires. §4's examples are the template for that comparison.
