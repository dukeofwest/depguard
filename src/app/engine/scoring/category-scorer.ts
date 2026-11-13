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
  const deductions = deductionsForFindings(findings);

  const unknownSeverityCount = findings.filter((f) => f.severity === 'Unknown').length;
  const summary = summariseSecurity(findings, coverage, unknownSeverityCount);

  const result = scored(id, deductions, coverage.queryableRatio, summary);

  // A clean result is capped by how much was actually checked. Unchecked packages are
  // unknown, not safe, so a partially checked repository cannot score 100 (§6.5).
  if (result.kind === 'scored' && findings.length === 0 && coverage.queryableRatio < 1) {
    const cap = Math.round(60 + 40 * coverage.queryableRatio);
    if (result.score > cap) {
      return {
        ...result,
        score: cap,
        deductions: [
          ...result.deductions,
          {
            reason: `${coverage.totalPackages - coverage.queryablePackages} of ${coverage.totalPackages} dependencies could not be checked`,
            points: 100 - cap,
          },
        ],
      };
    }
  }

  return result;
}

/** One capped deduction per deduplicated advisory, each traceable to its finding. */
function deductionsForFindings(findings: readonly VulnerabilityFinding[]): readonly Deduction[] {
  const raw: Deduction[] = findings.map((finding) => ({
    reason: `${finding.severity} severity: ${finding.summary ?? finding.key}`,
    points: SEVERITY_DEDUCTIONS[finding.severity],
    relatedFindingKey: finding.key,
  }));

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
): string {
  if (findings.length === 0) {
    return `No known vulnerabilities were found in the ${coverage.queryablePackages} dependencies that could be checked.`;
  }
  const base = `${findings.length} known ${findings.length === 1 ? 'vulnerability' : 'vulnerabilities'} affecting ${coverage.queryablePackages} checked dependencies.`;
  if (unknownSeverityCount > 0) {
    return `${base} ${unknownSeverityCount} ${unknownSeverityCount === 1 ? 'advisory' : 'advisories'} published no severity rating and ${unknownSeverityCount === 1 ? 'was' : 'were'} scored as medium.`;
  }
  return base;
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
    1,
    `${coverage.totalPackages} dependencies identified, ${coverage.queryablePackages} with a resolved version.`,
  );
}

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
 * Maintenance and activity.
 *
 * Archived repositories are the clearest signal available — an explicit statement by the
 * owner — and are scored low without being treated as a security finding.
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

    // Only applied when the data exists; its absence reduces coverage instead.
    if (signals.commitsLast52Weeks !== null && signals.commitsLast52Weeks === 0) {
      deductions.push({ reason: 'No commit activity recorded in the last 52 weeks', points: 15 });
    }
  }

  // Coverage reflects how many of the four activity signals were actually available.
  const available = [
    signals.daysSinceLastPush !== null,
    signals.commitsLast52Weeks !== null,
    signals.contributorCount !== null,
    signals.daysSinceLastRelease !== null,
  ].filter(Boolean).length;

  return scored(
    id,
    deductions,
    available / 4,
    signals.isArchived
      ? 'This repository is archived.'
      : `Activity classification: ${signals.classification}.`,
  );
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
