import { describe, expect, it } from 'vitest';

import {
  scoreDependencyHealth,
  scoreDependencySecurity,
  scoreEngineering,
  scoreMaintenance,
  scoreSecurityConfiguration,
} from './category-scorer';
import { bandFor, calculateOverall } from './overall-scorer';
import { CATEGORY_WEIGHTS } from './weights';
import type { CategoryId, Severity } from '../../core/models/analysis.model';
import type { DependencyCoverage } from '../../core/models/dependency.model';
import type {
  CategoryResult,
  MaintenanceSignals,
  SecurityCheck,
} from '../../core/models/health-report.model';
import type {
  VulnerabilityFinding,
  VulnerabilityResult,
} from '../../core/models/vulnerability.model';

function coverage(partial: Partial<DependencyCoverage> = {}): DependencyCoverage {
  return {
    totalPackages: 100,
    queryablePackages: 100,
    queryableRatio: 1,
    skippedByReason: {
      'no-purl': 0,
      'unsupported-ecosystem': 0,
      'no-version': 0,
      'version-not-exact': 0,
    },
    rangeVersionsDominant: false,
    duplicateEntries: 0,
    inventorySource: 'github-sbom',
    transitiveCoverage: 'full',
    discoveryNotes: [],
    ...partial,
  };
}

function finding(severity: Severity, key: string): VulnerabilityFinding {
  return {
    key,
    advisoryIds: [key],
    cveId: null,
    ghsaId: null,
    summary: `${severity} issue`,
    details: null,
    severity,
    severitySource: severity === 'Unknown' ? 'none' : 'database-qualitative',
    cvss: [],
    publishedAt: null,
    modifiedAt: null,
    withdrawn: false,
    affected: [],
    references: [],
  };
}

function completed(
  findings: readonly VulnerabilityFinding[],
  packagesChecked = 100,
): VulnerabilityResult {
  return { kind: 'completed', findings, packagesChecked };
}

function check(id: string, status: SecurityCheck['status']): SecurityCheck {
  return {
    id,
    label: id,
    status,
    evidence: { checked: 'x', found: 'y', source: 'z', explanation: 'e' },
  };
}

function scoredResult(id: CategoryId, score: number, cov = 1): CategoryResult {
  return { kind: 'scored', id, score, coverage: cov, deductions: [], summary: '' };
}

describe('scoreDependencySecurity', () => {
  it('reproduces the npm/cli worked example from ADR-0003', () => {
    // Real measured data: 1,026 of 1,208 packages queryable; 54 deduplicated advisories
    // of 3 Critical, 32 High, 15 Moderate, 4 Low.
    const findings = [
      ...Array.from({ length: 3 }, (_, i) => finding('Critical', `c${i}`)),
      ...Array.from({ length: 32 }, (_, i) => finding('High', `h${i}`)),
      ...Array.from({ length: 15 }, (_, i) => finding('Medium', `m${i}`)),
      ...Array.from({ length: 4 }, (_, i) => finding('Low', `l${i}`)),
    ];

    const result = scoreDependencySecurity(
      completed(findings),
      coverage({ totalPackages: 1208, queryablePackages: 1026, queryableRatio: 0.849 }),
    );

    expect(result.kind).toBe('scored');
    if (result.kind !== 'scored') return;

    // 3(15) + 32(8) + 15(3) + 4(1) = 350, capped at 60 → 40/100.
    expect(result.score).toBe(40);
    expect(result.coverage).toBeCloseTo(0.849, 3);

    // The cap must be visible as a deduction, not applied silently.
    const capLine = result.deductions.find((d) => d.reason.includes('capped'));
    expect(capLine).toBeDefined();

    // Every deduction traces to a finding (§6.5).
    const itemised = result.deductions.filter((d) => d.relatedFindingKey !== undefined);
    expect(itemised).toHaveLength(54);
  });

  it('reproduces the request/request worked example — insufficient data, never "clean"', () => {
    // 0 of 41 packages queryable: an abandoned repository with no lockfile.
    const result = scoreDependencySecurity(
      { kind: 'not-applicable', reason: 'No package had an exact version.' },
      coverage({
        totalPackages: 41,
        queryablePackages: 0,
        queryableRatio: 0,
        rangeVersionsDominant: true,
        skippedByReason: {
          'no-purl': 0,
          'unsupported-ecosystem': 1,
          'no-version': 0,
          'version-not-exact': 40,
        },
      }),
    );

    expect(result.kind).toBe('insufficient-data');
    if (result.kind !== 'insufficient-data') return;

    // The wording must rule out the dangerous reading.
    expect(result.reason).toContain('not evidence');
    expect(result.reason).toContain('0 of 41');
    expect(result.reason).toContain('lockfile');
  });

  it('refuses to score below the queryable-package floor', () => {
    // 49% checked: just under the floor. A score here would be built on half the data.
    const result = scoreDependencySecurity(
      completed([]),
      coverage({ totalPackages: 100, queryablePackages: 49, queryableRatio: 0.49 }),
    );
    expect(result.kind).toBe('insufficient-data');
  });

  it('does not award 100 when some packages went unchecked', () => {
    // No findings, but only 60% checked. Unchecked is unknown, not safe (§6.5).
    const result = scoreDependencySecurity(
      completed([]),
      coverage({ totalPackages: 100, queryablePackages: 60, queryableRatio: 0.6 }),
    );
    expect(result.kind).toBe('scored');
    if (result.kind !== 'scored') return;
    expect(result.score).toBeLessThan(100);
    expect(result.deductions.some((d) => d.reason.includes('could not be checked'))).toBe(true);
  });

  it('awards 100 only when everything was checked and nothing was found', () => {
    const result = scoreDependencySecurity(completed([]), coverage());
    expect(result.kind).toBe('scored');
    if (result.kind !== 'scored') return;
    expect(result.score).toBe(100);
  });

  it('treats unavailable OSV data as insufficient, not as clean', () => {
    const result = scoreDependencySecurity(
      { kind: 'unavailable', reason: 'OSV could not be reached.' },
      coverage(),
    );
    expect(result.kind).toBe('insufficient-data');
  });

  it('scores an unrated advisory as medium and says so', () => {
    const result = scoreDependencySecurity(completed([finding('Unknown', 'u1')]), coverage());
    expect(result.kind).toBe('scored');
    if (result.kind !== 'scored') return;
    expect(result.score).toBe(97);
    expect(result.summary).toContain('no severity rating');
  });

  it('never returns a score outside 0–100', () => {
    const many = Array.from({ length: 500 }, (_, i) => finding('Critical', `c${i}`));
    const result = scoreDependencySecurity(completed(many), coverage());
    if (result.kind !== 'scored') throw new Error('expected a score');
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
  });
});

describe('unknown handling (§6.2)', () => {
  it('excludes unknown checks from the score rather than counting them as failures', () => {
    const allConfigured = scoreSecurityConfiguration([
      check('security-policy', 'Configured'),
      check('dependabot-config', 'Configured'),
      check('license', 'Configured'),
      check('ci-workflow', 'Configured'),
    ]);

    const withUnknowns = scoreSecurityConfiguration([
      check('security-policy', 'Configured'),
      check('dependabot-config', 'Configured'),
      check('license', 'Unknown'),
      check('ci-workflow', 'Unknown'),
    ]);

    if (allConfigured.kind !== 'scored' || withUnknowns.kind !== 'scored') {
      throw new Error('expected scores');
    }

    // Same score — unknowns neither penalise nor reward.
    expect(withUnknowns.score).toBe(allConfigured.score);
    // But coverage falls, which is how the loss is communicated.
    expect(withUnknowns.coverage).toBeLessThan(allConfigured.coverage);
    expect(withUnknowns.coverage).toBe(0.5);
  });

  it('reports insufficient data when most checks are unknown', () => {
    const result = scoreSecurityConfiguration([
      check('security-policy', 'Configured'),
      check('dependabot-config', 'Unknown'),
      check('license', 'Unknown'),
      check('ci-workflow', 'Unknown'),
    ]);
    expect(result.kind).toBe('insufficient-data');
  });
});

// ---- P1-11: the partial-coverage ceiling, and monotonicity --------------

describe('partial-coverage ceiling (P1-11)', () => {
  const partial = coverage({ queryablePackages: 70, queryableRatio: 0.7 });

  /** The documented ceiling: 60 + 40 × ratio, or 100 at full coverage. */
  const ceiling = (ratio: number): number => (ratio < 1 ? Math.round(60 + 40 * ratio) : 100);

  function scoreOf(result: CategoryResult): number {
    if (result.kind !== 'scored') throw new Error('expected a score');
    return result.score;
  }

  it('applies the ceiling when there are no findings', () => {
    expect(scoreOf(scoreDependencySecurity(completed([], 70), partial))).toBe(88);
  });

  it('applies the ceiling when there ARE findings', () => {
    // The defect: this previously scored 99, because the ceiling was guarded by
    // `findings.length === 0`. Finding a vulnerability raised the score by 11 points.
    const result = scoreDependencySecurity(completed([finding('Low', 'GHSA-low')], 70), partial);
    expect(scoreOf(result)).toBe(88);
    expect(scoreOf(result)).toBeLessThanOrEqual(ceiling(0.7));
  });

  it('still deducts below the ceiling when findings are severe enough', () => {
    // Two Criticals = 30 points, taking the score to 70, which is below the 88 ceiling.
    // The ceiling is a maximum, not a floor, and must not raise a score.
    const result = scoreDependencySecurity(
      completed([finding('Critical', 'a'), finding('Critical', 'b')], 70),
      partial,
    );
    expect(scoreOf(result)).toBe(70);
  });

  it('does not cap a fully covered repository', () => {
    expect(scoreOf(scoreDependencySecurity(completed([]), coverage()))).toBe(100);
    expect(scoreOf(scoreDependencySecurity(completed([finding('Low', 'x')]), coverage()))).toBe(99);
  });

  it('never exceeds the ceiling at any coverage ratio', () => {
    for (const ratio of [0.5, 0.6, 0.7, 0.8, 0.9, 0.99, 1]) {
      const cov = coverage({
        queryablePackages: Math.round(ratio * 100),
        queryableRatio: ratio,
      });
      for (const findings of [
        [],
        [finding('Low', 'a')],
        [finding('Medium', 'a'), finding('Low', 'b')],
      ]) {
        const result = scoreDependencySecurity(completed(findings, cov.queryablePackages), cov);
        expect(scoreOf(result)).toBeLessThanOrEqual(ceiling(ratio));
      }
    }
  });

  /**
   * The invariant §10.3 and §11.3 require, stated directly.
   *
   * Adding a finding must never raise the score, at any coverage. The old
   * implementation violated this at every ratio below 1.
   */
  it('INVARIANT: at fixed coverage, adding findings never increases the score', () => {
    const severities: readonly Severity[] = ['Low', 'Medium', 'Unknown', 'High', 'Critical'];

    for (const ratio of [0.5, 0.7, 0.9, 1]) {
      const cov = coverage({
        queryablePackages: Math.round(ratio * 100),
        queryableRatio: ratio,
      });

      const findings: VulnerabilityFinding[] = [];
      let previous = scoreOf(scoreDependencySecurity(completed([], cov.queryablePackages), cov));

      // Add findings one at a time, in every severity, and assert the score only ever
      // falls or stays level.
      for (let index = 0; index < 12; index += 1) {
        const severity = severities[index % severities.length] as Severity;
        findings.push(finding(severity, `GHSA-${index}`));
        const next = scoreOf(
          scoreDependencySecurity(completed([...findings], cov.queryablePackages), cov),
        );
        expect(next).toBeLessThanOrEqual(previous);
        previous = next;
      }
    }
  });

  it('INVARIANT: more severe findings never score higher than less severe ones', () => {
    const cov = coverage();
    const ordered: readonly Severity[] = ['Low', 'Medium', 'High', 'Critical'];
    let previous = 101;
    for (const severity of ordered) {
      const score = scoreOf(scoreDependencySecurity(completed([finding(severity, 'x')]), cov));
      expect(score).toBeLessThan(previous);
      previous = score;
    }
  });
});

describe('scoreMaintenance', () => {
  function signals(partial: Partial<MaintenanceSignals> = {}): MaintenanceSignals {
    return {
      classification: 'Recently active',
      daysSinceLastPush: 5,
      daysSinceLastRelease: 30,
      commitsLast52Weeks: 100,
      contributorCount: 10,
      isArchived: false,
      ...partial,
    };
  }

  it('scores an active repository highly', () => {
    const result = scoreMaintenance(signals());
    if (result.kind !== 'scored') throw new Error('expected a score');
    expect(result.score).toBe(100);
  });

  it('penalises an archived repository heavily', () => {
    const result = scoreMaintenance(
      signals({ isArchived: true, classification: 'Archived', daysSinceLastPush: 900 }),
    );
    if (result.kind !== 'scored') throw new Error('expected a score');
    expect(result.score).toBe(30);
    // Archived must not be double-counted with staleness.
    expect(result.deductions).toHaveLength(1);
  });

  it('returns insufficient data when the date is unknown, not a low score', () => {
    const result = scoreMaintenance(
      signals({ classification: 'Insufficient data', daysSinceLastPush: null }),
    );
    expect(result.kind).toBe('insufficient-data');
  });

  // ---- P1-5: coverage counts only signals that can affect the score --------

  it('does not reduce coverage for signals that cannot affect the score', () => {
    // `contributorCount` and `daysSinceLastRelease` appear in no deduction, so their
    // absence must not lower confidence in a number they have no power to change. They
    // were previously in the coverage denominator, where they could only mislead.
    const result = scoreMaintenance(
      signals({ commitsLast52Weeks: null, contributorCount: null, daysSinceLastRelease: null }),
    );
    if (result.kind !== 'scored') throw new Error('expected a score');
    expect(result.coverage).toBe(1);
  });

  it('reports no coverage when the push date is unusable', () => {
    const result = scoreMaintenance(signals({ classification: 'Insufficient data' }));
    expect(result.kind).toBe('insufficient-data');
    expect(result.coverage).toBe(0);
  });

  // ---- P1-6: unknown activity must not outscore known activity ------------

  it('does not reward unknown commit activity over known zero activity', () => {
    const unknown = scoreMaintenance(signals({ commitsLast52Weeks: null }));
    const knownZero = scoreMaintenance(signals({ commitsLast52Weeks: 0 }));
    const knownPositive = scoreMaintenance(signals({ commitsLast52Weeks: 40 }));

    if (
      unknown.kind !== 'scored' ||
      knownZero.kind !== 'scored' ||
      knownPositive.kind !== 'scored'
    ) {
      throw new Error('expected scores');
    }

    // The defect: unknown previously scored 100 while known-zero scored 85, so a
    // repository scored better by GitHub not having finished counting its commits.
    expect(unknown.score).toBeLessThanOrEqual(knownZero.score);
    expect(unknown.score).toBeLessThanOrEqual(knownPositive.score);
    expect(unknown.coverage).toBeLessThanOrEqual(knownPositive.coverage);
  });

  // ---- P1-4: the summary must state what was measured --------------------

  it('states what the score measures and what it does not', () => {
    const result = scoreMaintenance(signals({ commitsLast52Weeks: 1, contributorCount: 1 }));
    if (result.kind !== 'scored') throw new Error('expected a score');

    // A one-commit repository can legitimately score 100 here, so the summary must say
    // the score is about recency rather than maintenance quality.
    expect(result.score).toBe(100);
    expect(result.summary).toContain('not a judgement of maintenance quality');
    // Informational signals are preserved as context rather than discarded.
    expect(result.summary).toContain('1 commits in the last 52 weeks');
    expect(result.summary).toContain('1 contributor');
  });
});

describe('calculateOverall', () => {
  it('weights categories as ADR-0003 specifies', () => {
    const result = calculateOverall([
      scoredResult('dependency-security', 100),
      scoredResult('dependency-health', 100),
      scoredResult('security-configuration', 100),
      scoredResult('maintenance', 100),
      scoredResult('engineering', 100),
    ]);
    if (result.kind !== 'scored') throw new Error('expected a score');
    expect(result.score).toBe(100);
    expect(result.coverage).toBe(1);
    expect(result.excludedCategories).toEqual([]);
  });

  it('redistributes the weight of an excluded category', () => {
    // Dependency security (30%) excluded; the rest score 80.
    const result = calculateOverall([
      { kind: 'insufficient-data', id: 'dependency-security', coverage: 0, reason: 'no lockfile' },
      scoredResult('dependency-health', 80),
      scoredResult('security-configuration', 80),
      scoredResult('maintenance', 80),
      scoredResult('engineering', 80),
    ]);

    if (result.kind !== 'scored') throw new Error('expected a score');
    // Rescaled across the remaining 70% of weight — not dragged to zero by the gap.
    expect(result.score).toBe(80);
    expect(result.excludedCategories).toEqual(['dependency-security']);
    // Coverage shows the analysis was only 70% complete.
    expect(result.coverage).toBeCloseTo(0.7, 5);
    expect(result.explanation).toContain('70%');
  });

  it('never treats a missing category as zero', () => {
    const withGap = calculateOverall([
      { kind: 'insufficient-data', id: 'dependency-security', coverage: 0, reason: 'x' },
      scoredResult('dependency-health', 90),
      scoredResult('security-configuration', 90),
      scoredResult('maintenance', 90),
      scoredResult('engineering', 90),
    ]);
    const asZero = calculateOverall([
      scoredResult('dependency-security', 0),
      scoredResult('dependency-health', 90),
      scoredResult('security-configuration', 90),
      scoredResult('maintenance', 90),
      scoredResult('engineering', 90),
    ]);

    if (withGap.kind !== 'scored' || asZero.kind !== 'scored') throw new Error('expected scores');
    expect(withGap.score).toBe(90);
    expect(asZero.score).toBe(63);
    expect(withGap.score).toBeGreaterThan(asZero.score);
  });

  it('refuses an overall score when too little could be assessed', () => {
    // Only engineering (15%) scorable — below the 50% floor.
    const result = calculateOverall([
      { kind: 'insufficient-data', id: 'dependency-security', coverage: 0, reason: 'x' },
      { kind: 'insufficient-data', id: 'dependency-health', coverage: 0, reason: 'x' },
      { kind: 'insufficient-data', id: 'security-configuration', coverage: 0, reason: 'x' },
      { kind: 'insufficient-data', id: 'maintenance', coverage: 0, reason: 'x' },
      scoredResult('engineering', 90),
    ]);

    expect(result.kind).toBe('unavailable');
    if (result.kind !== 'unavailable') return;
    expect(result.reason).toContain('15%');
  });

  // ---- P1-3 / P2-1: the two percentages ----------------------------------

  it('reports assessed weight and evidence coverage as separate figures', () => {
    // The exact configuration from the 14 November 2026 self-analysis report, which
    // showed "60%" and "50%" side by side and read as a contradiction.
    const result = calculateOverall([
      { kind: 'insufficient-data', id: 'dependency-security', coverage: 0, reason: 'x' },
      { kind: 'insufficient-data', id: 'dependency-health', coverage: 0, reason: 'x' },
      scoredResult('security-configuration', 75, 1),
      scoredResult('maintenance', 100, 0.5),
      scoredResult('engineering', 75, 1),
    ]);
    if (result.kind !== 'scored') throw new Error('expected a score');

    expect(result.score).toBe(83);
    // Both figures are correct and they measure different things.
    expect(result.assessedWeight).toBeCloseTo(0.6, 5);
    expect(result.coverage).toBeCloseTo(0.5, 5);

    // The explanation must name what each one measures, so neither can be mistaken for
    // the other.
    expect(result.explanation).toContain('of the intended analysis by weight');
    expect(result.explanation).toContain('Evidence coverage is');
  });

  it('reports full assessed weight when every category scores', () => {
    const result = calculateOverall([
      scoredResult('dependency-security', 90, 1),
      scoredResult('dependency-health', 90, 1),
      scoredResult('security-configuration', 90, 1),
      scoredResult('maintenance', 90, 1),
      scoredResult('engineering', 90, 1),
    ]);
    if (result.kind !== 'scored') throw new Error('expected a score');
    expect(result.assessedWeight).toBe(1);
    expect(result.coverage).toBeCloseTo(1, 5);
  });

  it('coverage equals the weighted sum of category coverage (P2-1)', () => {
    // The simplified formula must be equivalent to the intended one: the old code
    // divided this sum by the scorable weight and then multiplied it back.
    const categories: readonly CategoryResult[] = [
      scoredResult('security-configuration', 80, 0.4),
      scoredResult('maintenance', 80, 0.9),
      scoredResult('engineering', 80, 1),
    ];
    const result = calculateOverall(categories);
    if (result.kind !== 'scored') throw new Error('expected a score');

    const expected =
      0.4 * CATEGORY_WEIGHTS['security-configuration'] +
      0.9 * CATEGORY_WEIGHTS.maintenance +
      1 * CATEGORY_WEIGHTS.engineering;
    expect(result.coverage).toBeCloseTo(expected, 10);
  });

  it('INVARIANT: missing evidence never increases coverage', () => {
    // Four categories, weighing 0.70 in total, so every variant below stays above the
    // 0.5 minimum scorable weight and a real score is produced in each case.
    const full = calculateOverall([
      scoredResult('dependency-health', 80, 1),
      scoredResult('security-configuration', 80, 1),
      scoredResult('maintenance', 80, 1),
      scoredResult('engineering', 80, 1),
    ]);
    // Same categories, thinner evidence in one of them.
    const thin = calculateOverall([
      scoredResult('dependency-health', 80, 1),
      scoredResult('security-configuration', 80, 0.5),
      scoredResult('maintenance', 80, 1),
      scoredResult('engineering', 80, 1),
    ]);
    // One category unscorable entirely.
    const excluded = calculateOverall([
      { kind: 'insufficient-data', id: 'dependency-health', coverage: 0, reason: 'x' },
      scoredResult('security-configuration', 80, 1),
      scoredResult('maintenance', 80, 1),
      scoredResult('engineering', 80, 1),
    ]);

    if (full.kind !== 'scored' || thin.kind !== 'scored' || excluded.kind !== 'scored') {
      throw new Error('expected scores');
    }

    // Less evidence lowers coverage but not the share of categories assessed.
    expect(thin.coverage).toBeLessThan(full.coverage);
    expect(thin.assessedWeight).toBe(full.assessedWeight);

    // An excluded category lowers both.
    expect(excluded.coverage).toBeLessThan(full.coverage);
    expect(excluded.assessedWeight).toBeLessThan(full.assessedWeight);

    // And in no case does a gap in the evidence improve either figure.
    for (const variant of [thin, excluded]) {
      expect(variant.coverage).toBeLessThanOrEqual(full.coverage);
      expect(variant.assessedWeight).toBeLessThanOrEqual(full.assessedWeight);
    }
  });

  it('weights sum to 1', () => {
    const total = Object.values(CATEGORY_WEIGHTS).reduce((sum, weight) => sum + weight, 0);
    expect(total).toBeCloseTo(1, 10);
  });

  it('maps scores to the documented bands', () => {
    expect(bandFor(100)).toBe('Excellent');
    expect(bandFor(90)).toBe('Excellent');
    expect(bandFor(89)).toBe('Good');
    expect(bandFor(75)).toBe('Good');
    expect(bandFor(74)).toBe('Fair');
    expect(bandFor(60)).toBe('Fair');
    expect(bandFor(59)).toBe('Needs attention');
    expect(bandFor(40)).toBe('Needs attention');
    expect(bandFor(39)).toBe('Poor');
    expect(bandFor(0)).toBe('Poor');
  });
});

describe('determinism', () => {
  it('produces identical results for identical input', () => {
    const findings = [finding('High', 'a'), finding('Low', 'b'), finding('Unknown', 'c')];
    const first = scoreDependencySecurity(completed(findings), coverage());
    const second = scoreDependencySecurity(completed(findings), coverage());
    expect(first).toEqual(second);
  });
});

describe('scoreDependencyHealth and scoreEngineering', () => {
  it('reports insufficient data when there is no inventory', () => {
    expect(scoreDependencyHealth(null).kind).toBe('insufficient-data');
    expect(scoreDependencyHealth(coverage({ totalPackages: 0 })).kind).toBe('insufficient-data');
  });

  // ---- P1-7: coverage must not claim dimensions that are not assessed -----

  it('does not claim full coverage for an analysis it only partly performs', () => {
    const result = scoreDependencyHealth(coverage());
    if (result.kind !== 'scored') throw new Error('expected a score');

    // Previously a hardcoded `1`, which told the reader the dependency-health analysis
    // was complete while the same report's limitations said freshness was unavailable.
    expect(result.coverage).toBeLessThan(1);
    expect(result.coverage).toBeGreaterThan(0);
    expect(result.summary).toContain('version freshness and deprecation status are not');
  });

  it('penalises an inventory dominated by ranges', () => {
    const result = scoreDependencyHealth(
      coverage({
        totalPackages: 50,
        queryablePackages: 5,
        queryableRatio: 0.1,
        skippedByReason: {
          'no-purl': 0,
          'unsupported-ecosystem': 0,
          'no-version': 5,
          'version-not-exact': 40,
        },
      }),
    );
    if (result.kind !== 'scored') throw new Error('expected a score');
    expect(result.score).toBeLessThan(70);
  });

  it('scores engineering signals from the checks', () => {
    const result = scoreEngineering([
      check('readme', 'Configured'),
      check('tests', 'Not detected'),
      check('contributing', 'Not detected'),
      check('code-of-conduct', 'Configured'),
      check('project-description', 'Configured'),
    ]);
    if (result.kind !== 'scored') throw new Error('expected a score');
    // 100 - 30 (tests) - 15 (contributing) = 55.
    expect(result.score).toBe(55);
  });
});
