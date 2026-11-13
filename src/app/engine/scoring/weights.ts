import type { CategoryId, Severity } from '../../core/models/analysis.model';

/**
 * Scoring constants, as approved in ADR-0003.
 *
 * Pure data, no behaviour. Kept in one module so the scoring model can be reviewed and
 * changed in a single place rather than being rediscovered across components (§5.4, §6.5).
 *
 * NOTE: this file imports only `type`s from core/models. Type-only imports are erased at
 * compile time, so the engine remains free of runtime application dependencies (§4.4).
 */

/**
 * Category weights.
 *
 * These differ from the specification's opening proposal (35/15/20/15/15). Phase 0
 * measured that Dependency Security — the category the spec weighted highest — is the one
 * most often unscorable, while Maintenance and Security Configuration are the most
 * reliably observable. Weighting toward what can actually be measured makes the overall
 * score stable across repositories instead of lurching when an SBOM is missing.
 */
export const CATEGORY_WEIGHTS: Readonly<Record<CategoryId, number>> = {
  'dependency-security': 0.3,
  'dependency-health': 0.1,
  'security-configuration': 0.25,
  maintenance: 0.2,
  engineering: 0.15,
} as const;

/**
 * Points deducted per deduplicated advisory.
 *
 * `Unknown` is weighted as Medium rather than ignored. Ignoring it would let advisories
 * from sources that publish no severity — every PYSEC record measured in Phase 0 — vanish
 * from the score entirely. The explanation flags these as unscored severities so the
 * weighting is visible rather than silent.
 */
export const SEVERITY_DEDUCTIONS: Readonly<Record<Severity, number>> = {
  Critical: 15,
  High: 8,
  Medium: 3,
  Low: 1,
  Unknown: 3,
} as const;

/**
 * Maximum total deduction for the dependency security category.
 *
 * Without a cap, any large repository floors at 0 and the score stops discriminating
 * between "some problems" and "catastrophic". Measured example: `npm/cli`'s 54 advisories
 * produce a raw deduction of 350, which the cap turns into a score of 40 — still clearly
 * poor, but comparable against other repositories.
 */
export const MAX_SECURITY_DEDUCTION = 60;

/**
 * Minimum coverage for a category to produce a score at all.
 *
 * Below this, the category reports `insufficient-data` and its weight is redistributed
 * across the categories that could be scored.
 */
export const MINIMUM_CATEGORY_COVERAGE = 0.5;

/**
 * Minimum share of packages that must be OSV-queryable before Dependency Security scores.
 *
 * This exists because of `request/request`: 0 of its 41 packages carry an exact version,
 * so a naive implementation would report "no vulnerabilities found" for an abandoned
 * repository. Reporting insufficient data is the only honest outcome (§2.4).
 */
export const MINIMUM_QUERYABLE_RATIO = 0.5;

/**
 * Minimum total weight that must be scorable before an overall score is shown at all.
 */
export const MINIMUM_SCORABLE_WEIGHT = 0.5;

/** Score band thresholds (§6.4), as inclusive lower bounds. */
export const SCORE_BANDS = [
  { min: 90, band: 'Excellent' },
  { min: 75, band: 'Good' },
  { min: 60, band: 'Fair' },
  { min: 40, band: 'Needs attention' },
  { min: 0, band: 'Poor' },
] as const;
