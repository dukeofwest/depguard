import type { CategoryId, CheckStatus, Severity } from '../../core/models/analysis.model';
import type { DependencyCoverage } from '../../core/models/dependency.model';
import type {
  CategoryResult,
  Deduction,
  MaintenanceSignals,
  SecurityCheck,
} from '../../core/models/health-report.model';
import type {
  VulnerabilityFinding,
  VulnerabilityResult,
} from '../../core/models/vulnerability.model';
import { ACTIVITY_THRESHOLDS } from '../health/thresholds';
import {
  MAX_SECURITY_DEDUCTION,
  MINIMUM_CATEGORY_COVERAGE,
  MINIMUM_QUERYABLE_RATIO,
  SEVERITY_DEDUCTIONS,
} from './weights';

/**
 * Category scoring (§6.2, §6.5).
 *
 * Two rules govern everything here:
 *
 * 1. **Unknown is neither zero nor full marks.** Checks with an unknown or inapplicable
 *    status are excluded from both the numerator and the denominator, and reduce coverage
 *    instead.
 * 2. **Every deduction is traceable.** A score is only ever 100 minus explicit, itemised
 *    deductions, each naming the finding that caused it.
 */

/** Checks that count toward a score. Unknown and Not applicable are excluded. */
function scorableChecks(checks: readonly SecurityCheck[]): readonly SecurityCheck[] {
  return checks.filter((check) => check.status === 'Configured' || check.status === 'Not detected');
}

function coverageOf(checks: readonly SecurityCheck[]): number {
  const applicable = checks.filter((check) => check.status !== 'Not applicable');
  if (applicable.length === 0) {
    return 0;
  }
  return scorableChecks(checks).length / applicable.length;
}

function insufficient(id: CategoryId, coverage: number, reason: string): CategoryResult {
  return { kind: 'insufficient-data', id, coverage, reason };
}

function scored(
  id: CategoryId,
  deductions: readonly Deduction[],
  coverage: number,
  summary: string,
): CategoryResult {
  const total = deductions.reduce((sum, deduction) => sum + deduction.points, 0);
  const score = Math.max(0, Math.min(100, 100 - total));
  return { kind: 'scored', id, score, coverage, deductions, summary };
}

/**
 * Scores checks by how many are configured, with a stated weight per check.
 *
 * Used for the configuration-style categories, where each missing item is an independent,
 * individually explainable deduction.
 */
function scoreChecks(
  id: CategoryId,
  checks: readonly SecurityCheck[],
  pointsPerCheck: Readonly<Record<string, number>>,
  summaryFor: (configured: number, scorable: number) => string,
): CategoryResult {
  const coverage = coverageOf(checks);
  const scorable = scorableChecks(checks);

  if (coverage < MINIMUM_CATEGORY_COVERAGE || scorable.length === 0) {
    return insufficient(
      id,
      coverage,
      'Too few checks could be completed to produce a meaningful score. This usually means the repository file list could not be read in full.',
    );
  }

  const deductions: Deduction[] = [];
  for (const check of scorable) {
    if (check.status === 'Not detected') {
      const points = pointsPerCheck[check.id] ?? 10;
      deductions.push({ reason: `${check.label} not detected`, points });
    }
  }

  const configured = scorable.filter((check) => check.status === 'Configured').length;
  return scored(id, deductions, coverage, summaryFor(configured, scorable.length));
}

/**
 * Dependency security.
 *
 * The category with the strictest gate. Beyond the usual coverage floor, it requires that
 * at least half the inventory could actually be checked — because a repository with no
 * lockfile yields zero checkable packages, and reporting "no vulnerabilities found" for
 * it would be the single most damaging thing DepGuard could say (§2.4, ADR-0002).
 */
export function scoreDependencySecurity(
  vulnerabilities: VulnerabilityResult,
  coverage: DependencyCoverage | null,
): CategoryResult {
  const id: CategoryId = 'dependency-security';

  if (coverage === null) {
    return insufficient(
      id,
      0,
      'No dependency inventory was available, so no dependency could be checked for known vulnerabilities. This is not evidence that the dependencies are free of vulnerabilities.',
    );
  }

  if (vulnerabilities.kind === 'unavailable') {
    return insufficient(id, 0, `Vulnerability data was unavailable: ${vulnerabilities.reason}`);
  }

  if (
    vulnerabilities.kind === 'not-applicable' ||
    coverage.queryableRatio < MINIMUM_QUERYABLE_RATIO
  ) {
    const checked = coverage.queryablePackages;
    const total = coverage.totalPackages;
    return insufficient(
      id,
      coverage.queryableRatio,
      total === 0
        ? 'No dependencies were identified, so none could be checked.'
        : `Only ${checked} of ${total} dependencies had an exact version that could be checked against vulnerability databases. ` +
            (coverage.rangeVersionsDominant
              ? 'Most versions are declared as ranges, which usually means no lockfile is committed. '
              : '') +
            'This is not evidence that the dependencies are free of vulnerabilities.',
    );
  }

  const findings = vulnerabilities.findings;

  // Advisories OSV confirmed but whose details never arrived. They are not findings —
  // DepGuard will not invent advisory details from an id — but they are known
  // vulnerabilities, so they must cost score and must appear in the summary. Weighted at
  // the `Unknown` severity rate, which is the model's existing treatment for a confirmed
  // advisory whose severity is not available (P0-1, §4.3).
  const unretrieved =
    vulnerabilities.kind === 'partial' ? vulnerabilities.advisoriesUnretrieved : [];

  const deductions = deductionsForFindings(findings, unretrieved);

  const unknownSeverityCount = findings.filter((f) => f.severity === 'Unknown').length;
  const summary = summariseSecurity(findings, coverage, unknownSeverityCount, unretrieved);

  // A score is capped by how much was actually checked. Unchecked packages are unknown,
  // not safe, so a partially checked repository cannot score 100 (§6.5).
  //
  // P1-11: the ceiling is applied **after** deductions and **regardless of whether any
  // finding exists**. It was previously guarded by `findings.length === 0`, so any
  // non-empty finding set escaped it entirely — at a queryable ratio of 0.70 a clean
  // repository scored 88 while one with a single Low advisory scored 99. Discovering a
  // vulnerability raised the score by 11 points, which is the exact opposite of what the
  // category is for.
  const ceiling = coverage.queryableRatio < 1 ? Math.round(60 + 40 * coverage.queryableRatio) : 100;

  const uncheckedDeduction: readonly Deduction[] =
    ceiling < 100
      ? [
          {
            reason: `${coverage.totalPackages - coverage.queryablePackages} of ${coverage.totalPackages} dependencies could not be checked`,
            points: 100 - ceiling,
          },
        ]
      : [];

  const fromDeductions = deductions.reduce((sum, deduction) => sum + deduction.points, 0);
  const score = Math.min(Math.max(0, 100 - fromDeductions), ceiling);

  return {
    kind: 'scored',
    id,
    score,
    coverage: coverage.queryableRatio,
    // The ceiling is itemised only when it actually bound the score, so the deductions
    // continue to explain the number rather than over-explaining it.
    deductions:
      score === ceiling && ceiling < 100 ? [...deductions, ...uncheckedDeduction] : deductions,
    summary,
  };
}

/** One capped deduction per deduplicated advisory, each traceable to its finding. */
function deductionsForFindings(
  findings: readonly VulnerabilityFinding[],
  unretrieved: readonly string[],
): readonly Deduction[] {
  const raw: Deduction[] = findings.map((finding) => ({
    reason: `${finding.severity} severity: ${finding.summary ?? finding.key}`,
    points: SEVERITY_DEDUCTIONS[finding.severity],
    relatedFindingKey: finding.key,
  }));

  for (const advisoryId of unretrieved) {
    raw.push({
      reason: `Confirmed advisory ${advisoryId} could not be retrieved, so its severity is unknown`,
      points: SEVERITY_DEDUCTIONS.Unknown,
    });
  }

  const total = raw.reduce((sum, deduction) => sum + deduction.points, 0);
  if (total <= MAX_SECURITY_DEDUCTION) {
    return raw;
  }

  // Without a cap, any large repository floors at 0 and the score stops distinguishing
  // "some problems" from "catastrophic". The cap is applied as a single visible
  // adjustment rather than by silently rescaling each deduction.
  return [
    ...raw,
    {
      reason: `Deduction capped at ${MAX_SECURITY_DEDUCTION} points (${total} points of findings)`,
      points: MAX_SECURITY_DEDUCTION - total,
    },
  ];
}

function summariseSecurity(
  findings: readonly VulnerabilityFinding[],
  coverage: DependencyCoverage,
  unknownSeverityCount: number,
  unretrieved: readonly string[],
): string {
  // An unretrieved advisory is a *known* vulnerability. The summary must never read as
  // clean while one exists, whatever the findings list says (§4.3 Scenario B).
  const lost =
    unretrieved.length === 0
      ? ''
      : ` A further ${unretrieved.length} confirmed ${unretrieved.length === 1 ? 'advisory' : 'advisories'} ` +
        `could not be retrieved in full, so ${unretrieved.length === 1 ? 'it is' : 'they are'} not described above. ` +
        `${unretrieved.length === 1 ? 'It was' : 'They were'} scored as medium.`;

  if (findings.length === 0) {
    const base =
      unretrieved.length === 0
        ? `No known vulnerabilities were found in the ${coverage.queryablePackages} dependencies that could be checked.`
        : `No vulnerability could be described in full for the ${coverage.queryablePackages} dependencies that could be checked.`;
    return `${base}${lost}`;
  }

  const base = `${findings.length} known ${findings.length === 1 ? 'vulnerability' : 'vulnerabilities'} affecting ${coverage.queryablePackages} checked dependencies.`;
  if (unknownSeverityCount > 0) {
    return `${base} ${unknownSeverityCount} ${unknownSeverityCount === 1 ? 'advisory' : 'advisories'} published no severity rating and ${unknownSeverityCount === 1 ? 'was' : 'were'} scored as medium.${lost}`;
  }
  return `${base}${lost}`;
}

/**
 * Dependency health — inventory quality rather than vulnerabilities.
 *
 * Deliberately thin, because version freshness and deprecation detection are out of MVP
 * scope (no reliable free data source), which is why ADR-0003 reduced this category's
 * weight to 10%.
 */
export function scoreDependencyHealth(coverage: DependencyCoverage | null): CategoryResult {
  const id: CategoryId = 'dependency-health';

  if (coverage === null || coverage.totalPackages === 0) {
    return insufficient(
      id,
      0,
      'No dependency inventory was available. GitHub provides a dependency graph only for repositories with recognised manifest files.',
    );
  }

  const deductions: Deduction[] = [];
  const skipped = coverage.skippedByReason;

  const missingVersions = skipped['no-version'];
  if (missingVersions > 0) {
    deductions.push({
      reason: `${missingVersions} ${missingVersions === 1 ? 'dependency has' : 'dependencies have'} no version information`,
      points: Math.min(25, Math.round((missingVersions / coverage.totalPackages) * 60)),
    });
  }

  const inexact = skipped['version-not-exact'];
  if (inexact > 0) {
    deductions.push({
      reason: `${inexact} ${inexact === 1 ? 'dependency is' : 'dependencies are'} declared as a version range rather than a resolved version`,
      points: Math.min(35, Math.round((inexact / coverage.totalPackages) * 50)),
    });
  }

  const noPurl = skipped['no-purl'];
  if (noPurl > 0) {
    deductions.push({
      reason: `${noPurl} ${noPurl === 1 ? 'dependency has' : 'dependencies have'} incomplete package metadata`,
      points: Math.min(15, Math.round((noPurl / coverage.totalPackages) * 30)),
    });
  }

  return scored(
    id,
    deductions,
    DEPENDENCY_HEALTH_COVERAGE,
    `${coverage.totalPackages} dependencies identified, ${coverage.queryablePackages} with a resolved version. ` +
      'Only inventory quality is assessed: version freshness and deprecation status are not ' +
      'checked in this release, because no reliable free data source for them is integrated.',
  );
}

/**
 * The share of the intended dependency-health analysis this release can perform.
 *
 * Previously hardcoded to `1`, which claimed complete coverage of an analysis that
 * assesses one of three intended dimensions (P1-7). The category was designed around
 * inventory quality, version freshness and deprecation status; only the first is
 * implemented, and the report's own limitations section already says so — so `coverage: 1`
 * contradicted the same report that contained it.
 *
 * Expressed as a fraction of named dimensions rather than a bare number so that
 * implementing freshness later means moving a dimension, not re-deriving a constant.
 */
const DEPENDENCY_HEALTH_DIMENSIONS = {
  assessed: ['inventory-quality'],
  notImplemented: ['version-freshness', 'deprecation-status'],
} as const;

const DEPENDENCY_HEALTH_COVERAGE =
  DEPENDENCY_HEALTH_DIMENSIONS.assessed.length /
  (DEPENDENCY_HEALTH_DIMENSIONS.assessed.length +
    DEPENDENCY_HEALTH_DIMENSIONS.notImplemented.length);

/** Security configuration. Weighted toward the checks with real security consequences. */
export function scoreSecurityConfiguration(checks: readonly SecurityCheck[]): CategoryResult {
  return scoreChecks(
    'security-configuration',
    checks,
    {
      'security-policy': 20,
      'dependabot-config': 25,
      'codeql-workflow': 15,
      'dependency-review': 10,
      'ci-workflow': 15,
      license: 15,
    },
    (configured, total) => `${configured} of ${total} security practices detected.`,
  );
}

/**
 * Activity and recency.
 *
 * Archived repositories are the clearest signal available — an explicit statement by the
 * owner — and are scored low without being treated as a security finding.
 *
 * Two corrections from the November 2026 audit shape this function:
 *
 * **P1-6.** The old `commitsLast52Weeks === 0` deduction of 15 points has been removed.
 * It could only fire when GitHub had finished computing statistics, so a repository whose
 * statistics were still pending scored 15 points *higher* than one known to have made no
 * commits — missing data outscoring known-bad data, which §7.3 prohibits. The signal was
 * also redundant: `daysSinceLastPush` is always available, never ambiguous, and already
 * carries recency. The commit count is still reported as context, and the limitation is
 * still named in the report; it simply no longer moves a score it could not move
 * consistently.
 *
 * **P1-5.** Coverage now reflects only the signals that can affect the score.
 * `contributorCount` and `daysSinceLastRelease` were previously in the coverage
 * denominator while appearing in no deduction, so they could only ever lower confidence
 * in a number they had no power to change. They remain in the report as context.
 */
export function scoreMaintenance(signals: MaintenanceSignals): CategoryResult {
  const id: CategoryId = 'maintenance';

  if (signals.classification === 'Insufficient data') {
    return insufficient(
      id,
      0,
      'DepGuard could not determine when this repository was last updated.',
    );
  }

  const deductions: Deduction[] = [];

  if (signals.isArchived) {
    deductions.push({
      reason: 'The repository is archived and no longer maintained by its owner',
      points: 70,
    });
  } else {
    const days = signals.daysSinceLastPush;
    if (days !== null) {
      if (days > ACTIVITY_THRESHOLDS.limitedActivityDays) {
        deductions.push({
          reason: `No commits for over ${Math.floor(days / 365)} year${days >= 730 ? 's' : ''}`,
          points: 40,
        });
      } else if (days > ACTIVITY_THRESHOLDS.activeDays) {
        deductions.push({ reason: `No commits in the last ${days} days`, points: 15 });
      }
    }
  }

  // Every signal this category scores — the archived flag and the last push date — comes
  // from repository metadata, which is the one request that must succeed for a scan to
  // happen at all. So coverage is 1 whenever the category is scorable, and 0 when the
  // push date is unusable (handled by the `Insufficient data` branch above). Reporting a
  // fraction derived from unscored signals was the defect, not the fix.
  return scored(id, deductions, 1, summariseActivity(signals));
}

/**
 * States what was measured, and what the score does not cover.
 *
 * Required by P1-4: the score itself is defensible, but presenting "100/100" for a
 * one-day-old repository without saying what was weighed invites the reader to hear a
 * verdict on maintenance quality.
 */
function summariseActivity(signals: MaintenanceSignals): string {
  if (signals.isArchived) {
    return 'This repository is archived, which its owner has stated explicitly.';
  }

  const context: string[] = [];
  if (signals.commitsLast52Weeks !== null) {
    context.push(`${signals.commitsLast52Weeks} commits in the last 52 weeks`);
  }
  if (signals.contributorCount !== null) {
    context.push(
      `${signals.contributorCount} contributor${signals.contributorCount === 1 ? '' : 's'}`,
    );
  }

  const measured =
    `Activity classification: ${signals.classification}. ` +
    'This score reflects how recently the repository was pushed to and whether it is archived. ' +
    'It is not a judgement of maintenance quality: review practice, issue response and release ' +
    'discipline are not observable here.';

  return context.length === 0 ? measured : `${measured} For context: ${context.join(', ')}.`;
}

/** Engineering and project quality signals. */
export function scoreEngineering(checks: readonly SecurityCheck[]): CategoryResult {
  return scoreChecks(
    'engineering',
    checks,
    {
      readme: 30,
      contributing: 15,
      'code-of-conduct': 10,
      tests: 30,
      'project-description': 15,
    },
    (configured, total) => `${configured} of ${total} project quality signals detected.`,
  );
}

/** Exported for the report builder and tests. */
export type { CheckStatus, Severity };
