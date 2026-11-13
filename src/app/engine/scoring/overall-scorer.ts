import type { CategoryId } from '../../core/models/analysis.model';
import type {
  CategoryResult,
  OverallResult,
  ScoreBand,
} from '../../core/models/health-report.model';
import { CATEGORY_WEIGHTS, MINIMUM_SCORABLE_WEIGHT, SCORE_BANDS } from './weights';

/**
 * Overall score with weight redistribution (§6.2, §6.3).
 *
 * The rule the specification insists on: unavailable data is neither zero nor full marks.
 * A category that could not be scored is removed from the calculation entirely and its
 * weight is spread proportionally across the categories that could — so absence neither
 * inflates nor deflates the result.
 *
 * When too little could be scored to justify any headline number, no score is produced at
 * all. A number nobody can stand behind is worse than no number.
 */
export function calculateOverall(categories: readonly CategoryResult[]): OverallResult {
  const scorable = categories.filter(
    (category): category is Extract<CategoryResult, { kind: 'scored' }> =>
      category.kind === 'scored',
  );

  const excluded = categories
    .filter((category) => category.kind === 'insufficient-data')
    .map((category) => category.id);

  const scorableWeight = scorable.reduce(
    (total, category) => total + CATEGORY_WEIGHTS[category.id],
    0,
  );

  if (scorable.length === 0 || scorableWeight < MINIMUM_SCORABLE_WEIGHT) {
    return {
      kind: 'unavailable',
      reason:
        scorable.length === 0
          ? 'None of the five analysis categories could be completed, so no overall score can be given.'
          : `Only ${Math.round(scorableWeight * 100)}% of the analysis could be completed, which is too little to support an overall score. The individual findings below are still accurate.`,
    };
  }

  // Redistribution: dividing by the scorable weight rescales the remaining categories to
  // sum to 1, which is equivalent to spreading the excluded weight proportionally.
  const weighted = scorable.reduce(
    (total, category) => total + category.score * CATEGORY_WEIGHTS[category.id],
    0,
  );
  const score = Math.round(weighted / scorableWeight);

  // Coverage is weighted the same way, so a confident score over thin data still reads
  // as thin.
  const coverage =
    scorable.reduce(
      (total, category) => total + category.coverage * CATEGORY_WEIGHTS[category.id],
      0,
    ) / scorableWeight;

  return {
    kind: 'scored',
    score,
    band: bandFor(score),
    // Overall coverage is reduced by excluded categories as well as by thin ones.
    coverage: coverage * scorableWeight,
    excludedCategories: excluded,
    explanation: explain(score, scorableWeight, excluded),
  };
}

export function bandFor(score: number): ScoreBand {
  for (const entry of SCORE_BANDS) {
    if (score >= entry.min) {
      return entry.band;
    }
  }
  return 'Poor';
}

function explain(score: number, scorableWeight: number, excluded: readonly CategoryId[]): string {
  const band = bandFor(score).toLowerCase();
  const base = `DepGuard rates this repository ${score} out of 100 (${band}).`;

  if (excluded.length === 0) {
    return `${base} All five analysis categories completed.`;
  }

  const percentage = Math.round(scorableWeight * 100);
  return (
    `${base} ${excluded.length} of 5 categories could not be assessed, so this score reflects ` +
    `${percentage}% of the intended analysis. Excluded categories are not counted as failures, ` +
    `but their absence means less is known about this repository.`
  );
}
