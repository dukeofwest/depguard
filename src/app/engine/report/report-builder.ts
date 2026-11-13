import type { Severity } from '../../core/models/analysis.model';
import { REPORT_SCHEMA_VERSION } from './schema';
import type {
  DependencyCoverage,
  DependencyRow,
  NormalizedPackage,
} from '../../core/models/dependency.model';
import type {
  AnalysisLimitation,
  CategoryResult,
  DataSourceInfo,
  HealthReport,
} from '../../core/models/health-report.model';
import type { RepositorySnapshot } from '../../core/models/repository.model';
import type { VulnerabilityResult } from '../../core/models/vulnerability.model';
import { VERIFIED_ECOSYSTEMS } from '../dependencies/ecosystems';
import { analyseEngineering } from '../health/engineering-analyzer';
import { analyseMaintenance } from '../health/maintenance-analyzer';
import { buildRecommendations } from '../recommendations/recommendation-engine';
import {
  scoreDependencyHealth,
  scoreDependencySecurity,
  scoreEngineering,
  scoreMaintenance,
  scoreSecurityConfiguration,
} from '../scoring/category-scorer';
import { calculateOverall } from '../scoring/overall-scorer';
import { evaluateSecurityChecks } from '../security/security-checks';

/**
 * Assembles the final report (§7.3).
 *
 * The single entry point to the engine. Pure and deterministic: the same snapshot, the
 * same vulnerability result and the same `now` always produce byte-identical output,
 * which is what makes scores reproducible and explainable (§6.5).
 *
 * The result is also the exported JSON payload. It contains no credentials by
 * construction, because the application never holds any (§9.1).
 */

export interface BuildReportInput {
  readonly snapshot: RepositorySnapshot;
  readonly packages: readonly NormalizedPackage[];
  readonly dependencyCoverage: DependencyCoverage | null;
  readonly vulnerabilities: VulnerabilityResult;
  /** Why the SBOM was unavailable, when it was. */
  readonly sbomUnavailableReason: string | null;
  /** Supplied by the caller so the engine never reads the clock. */
  readonly now: Date;
}

export function buildReport(input: BuildReportInput): HealthReport {
  const { snapshot, packages, dependencyCoverage, vulnerabilities, now } = input;

  const securityChecks = evaluateSecurityChecks(snapshot);
  const maintenance = analyseMaintenance(snapshot, now);
  const engineering = analyseEngineering(snapshot);

  const categories: readonly CategoryResult[] = [
    scoreDependencySecurity(vulnerabilities, dependencyCoverage),
    scoreDependencyHealth(dependencyCoverage),
    scoreSecurityConfiguration(securityChecks),
    scoreMaintenance(maintenance),
    scoreEngineering(engineering.checks),
  ];

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    generatedAt: now.toISOString(),
    repository: snapshot.metadata,
    overall: calculateOverall(categories),
    categories,
    dependencies: buildDependencyRows(packages, vulnerabilities),
    dependencyCoverage,
    vulnerabilities,
    securityChecks,
    maintenance,
    engineering,
    recommendations: buildRecommendations({
      vulnerabilities,
      dependencyCoverage,
      securityChecks,
      engineeringChecks: engineering.checks,
      maintenance,
    }),
    limitations: collectLimitations(input),
    dataSources: describeDataSources(input),
  };
}

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Unknown: 4,
};

/**
 * Joins the inventory to its findings.
 *
 * `wasChecked` is the field that keeps the table honest: a package with zero
 * vulnerabilities and `wasChecked: false` was never looked at, which is a different
 * statement from "checked and clean" and must render differently.
 */
function buildDependencyRows(
  packages: readonly NormalizedPackage[],
  vulnerabilities: VulnerabilityResult,
): readonly DependencyRow[] {
  const findings =
    vulnerabilities.kind === 'completed' || vulnerabilities.kind === 'partial'
      ? vulnerabilities.findings
      : [];

  const byPackage = new Map<string, Severity[]>();
  for (const finding of findings) {
    for (const affected of finding.affected) {
      const key = `${affected.ecosystem}|${affected.name}|${affected.installedVersion}`;
      const existing = byPackage.get(key);
      if (existing === undefined) {
        byPackage.set(key, [finding.severity]);
      } else {
        existing.push(finding.severity);
      }
    }
  }

  return packages.map((pkg) => {
    const severities = byPackage.get(pkg.key) ?? [];
    const highest =
      severities.length === 0
        ? null
        : severities.reduce((worst, current) =>
            SEVERITY_RANK[current] < SEVERITY_RANK[worst] ? current : worst,
          );

    return {
      package: pkg,
      vulnerabilityCount: severities.length,
      highestSeverity: highest,
      wasChecked: pkg.skipReason === null && findings !== null,
    };
  });
}

/**
 * Limitations shown with every report (§5.1, §6.3).
 *
 * Some are unconditional, because they are true of the method itself and a reader who
 * sees a clean report deserves to know what it does and does not cover.
 */
function collectLimitations(input: BuildReportInput): readonly AnalysisLimitation[] {
  const limitations: AnalysisLimitation[] = [
    {
      scope: 'Scope of analysis',
      detail:
        'DepGuard examines observable repository signals. It does not read or execute source code, so it cannot find vulnerabilities in the code itself.',
    },
    {
      scope: 'Vulnerability data',
      detail:
        'Vulnerability data comes from OSV.dev, which aggregates many but not all advisory sources. No detected vulnerabilities does not mean a dependency is safe.',
    },
    {
      scope: 'GitHub feature status',
      detail:
        'DepGuard analyses public repositories without authentication, so it can see configuration files but cannot confirm whether Dependabot alerts, code scanning or CI runs are actually enabled and passing.',
    },
    {
      scope: 'Version freshness',
      detail:
        'Version freshness analysis is not available in this release. DepGuard does not report whether a dependency is outdated, because no reliable registry source is integrated.',
    },
  ];

  if (input.sbomUnavailableReason !== null) {
    limitations.push({
      scope: 'Dependency inventory',
      detail: `${input.sbomUnavailableReason} Dependency and vulnerability analysis could not be performed.`,
    });
  }

  const coverage = input.dependencyCoverage;
  if (coverage !== null && coverage.queryablePackages < coverage.totalPackages) {
    limitations.push({
      scope: 'Dependency coverage',
      detail: `${coverage.totalPackages - coverage.queryablePackages} of ${coverage.totalPackages} dependencies could not be checked for vulnerabilities, because their versions are not recorded as exact versions or their ecosystem is not supported.`,
    });
  }

  // §5.2 forbids claiming ecosystem support that has not been demonstrated. Phase 0
  // verified npm and PyPI against live SBOMs; the other mappings rest on documentation
  // alone, so a repository using one is told so rather than left to assume parity.
  const unverified = [
    ...new Set(
      input.packages
        .map((pkg) => pkg.ecosystem)
        .filter(
          (ecosystem): ecosystem is NonNullable<typeof ecosystem> =>
            ecosystem !== null && !VERIFIED_ECOSYSTEMS.includes(ecosystem),
        ),
    ),
  ].sort();

  if (unverified.length > 0) {
    limitations.push({
      scope: 'Ecosystem coverage',
      detail: `This repository uses ${unverified.join(', ')}. DepGuard's vulnerability matching has been verified against ${VERIFIED_ECOSYSTEMS.join(' and ')} using real repository data; support for these ecosystems follows the documented mapping but has not been confirmed in the same way, so results for them may be incomplete.`,
    });
  }

  if (input.snapshot.tree?.truncated === true) {
    limitations.push({
      scope: 'File inspection',
      detail:
        'This repository is large enough that GitHub returned a truncated file list, so some file-based checks are reported as unknown rather than not detected.',
    });
  }

  if (input.snapshot.weeklyCommits === null) {
    limitations.push({
      scope: 'Commit activity',
      detail:
        'GitHub did not return commit activity statistics for this repository, so recent commit frequency is unknown.',
    });
  }

  if (input.vulnerabilities.kind === 'partial') {
    limitations.push({
      scope: 'Vulnerability query',
      detail: `Some vulnerability queries did not complete: ${input.vulnerabilities.reason}`,
    });
  }

  return limitations;
}

function describeDataSources(input: BuildReportInput): readonly DataSourceInfo[] {
  const retrievedAt = input.snapshot.retrievedAt;

  return [
    {
      name: 'GitHub REST API',
      endpoint: 'https://api.github.com',
      retrievedAt,
      status: 'ok',
    },
    {
      name: 'GitHub Dependency Graph SBOM',
      endpoint: 'https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom',
      retrievedAt,
      status: input.sbomUnavailableReason === null ? 'ok' : 'unavailable',
    },
    {
      name: 'OSV.dev',
      endpoint: 'https://api.osv.dev',
      retrievedAt,
      status:
        input.vulnerabilities.kind === 'completed'
          ? 'ok'
          : input.vulnerabilities.kind === 'partial'
            ? 'partial'
            : 'unavailable',
    },
  ];
}
