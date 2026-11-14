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

  // Evidence depth, weighted the same way, so a confident score over thin data still
  // reads as thin. Reduced by excluded categories as well as by thinly-evidenced ones.
  //
  // P2-1: this was previously divided by `scorableWeight` and then multiplied by it
  // again. The operations cancel exactly, so the emitted value was always this sum — the
  // intermediate made a simple formula look like a subtler one and invited a "fix" that
  // would have changed behaviour.
  const coverage = scorable.reduce(
    (total, category) => total + category.coverage * CATEGORY_WEIGHTS[category.id],
    0,
  );

  return {
    kind: 'scored',
    score,
    band: bandFor(score),
    coverage,
    // P1-3: the share of intended analysis that could be scored at all, reported as its
    // own field. It was previously computed only inside the explanation sentence, where
    // it sat beside `coverage` as a bare percentage with nothing naming either — so a
    // report showing 60% and 50% read as self-contradictory when both were correct and
    // measuring different things.
    assessedWeight: scorableWeight,
    excludedCategories: excluded,
    explanation: explain(score, scorableWeight, coverage, excluded),
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

/**
 * Writes the explanation, naming what each percentage measures.
 *
 * The two figures are different quantities and are equal only when every scored category
 * is fully evidenced, so they must never be presented as comparable numbers:
 *
 * - **assessed weight** — how much of the intended analysis could be scored at all.
 * - **evidence coverage** — how well-evidenced the part that ran actually was.
 */
function explain(
  score: number,
  scorableWeight: number,
  coverage: number,
  excluded: readonly CategoryId[],
): string {
  const band = bandFor(score).toLowerCase();
  const assessed = Math.round(scorableWeight * 100);
  const evidence = Math.round(coverage * 100);
  const base = `DepGuard rates this repository ${score} out of 100 (${band}).`;

  const depth =
    `Evidence coverage is ${evidence}% of the full analysis — that is how much of the intended ` +
    `evidence DepGuard actually obtained, which is a different measure from how many ` +
    `categories ran.`;

  if (excluded.length === 0) {
    return (
      `${base} All five analysis categories were scored, covering 100% of the intended ` +
      `analysis by weight. ${depth}`
    );
  }

  return (
    `${base} ${excluded.length} of 5 categories could not be assessed, so the categories that ` +
    `were scored account for ${assessed}% of the intended analysis by weight. Excluded ` +
    `categories are not counted as failures, but their absence means less is known about this ` +
    `repository. ${depth}`
  );
}
