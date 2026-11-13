import type { CategoryId, Priority } from '../../core/models/analysis.model';
import type { DependencyCoverage } from '../../core/models/dependency.model';
import type {
  MaintenanceSignals,
  Recommendation,
  SecurityCheck,
} from '../../core/models/health-report.model';
import type {
  VulnerabilityFinding,
  VulnerabilityResult,
} from '../../core/models/vulnerability.model';

/**
 * Evidence-backed recommendations (§7.1, §7.2).
 *
 * Two rules:
 *
 * 1. **No recommendation without evidence.** Every item carries the observation that
 *    produced it, so a reader can check the reasoning rather than trust it.
 * 2. **Priority reflects actual impact.** §7.2 is explicit: a missing README is not
 *    critical, and a missing security policy is not a confirmed vulnerability. Only real
 *    advisories against resolved versions reach Critical or High.
 */

const PRIORITY_ORDER: Readonly<Record<Priority, number>> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Informational: 4,
};

interface Inputs {
  readonly vulnerabilities: VulnerabilityResult;
  readonly dependencyCoverage: DependencyCoverage | null;
  readonly securityChecks: readonly SecurityCheck[];
  readonly engineeringChecks: readonly SecurityCheck[];
  readonly maintenance: MaintenanceSignals;
}

export function buildRecommendations(inputs: Inputs): readonly Recommendation[] {
  const recommendations: Recommendation[] = [
    ...vulnerabilityRecommendations(inputs.vulnerabilities),
    ...coverageRecommendations(inputs.dependencyCoverage, inputs.vulnerabilities),
    ...checkRecommendations(inputs.securityChecks, inputs.engineeringChecks),
    ...maintenanceRecommendations(inputs.maintenance),
  ];

  // Stable ordering: priority first, then id, so identical input yields identical output.
  return recommendations.sort((a, b) => {
    const byPriority = PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority];
    return byPriority !== 0 ? byPriority : a.id.localeCompare(b.id);
  });
}

/**
 * One recommendation per vulnerable package, not per advisory.
 *
 * Grouping by package is what makes the advice actionable: a reader upgrades a package
 * once, even when five advisories affect it.
 */
function vulnerabilityRecommendations(result: VulnerabilityResult): Recommendation[] {
  if (result.kind !== 'completed' && result.kind !== 'partial') {
    return [];
  }

  const byPackage = new Map<
    string,
    { findings: VulnerabilityFinding[]; fixes: Set<string>; version: string }
  >();

  for (const finding of result.findings) {
    for (const affected of finding.affected) {
      const key = `${affected.ecosystem}|${affected.name}`;
      const entry = byPackage.get(key);
      if (entry === undefined) {
        byPackage.set(key, {
          findings: [finding],
          fixes: new Set(affected.fixedVersions),
          version: affected.installedVersion,
        });
      } else {
        entry.findings.push(finding);
        affected.fixedVersions.forEach((fix) => entry.fixes.add(fix));
      }
    }
  }

  const recommendations: Recommendation[] = [];

  for (const [key, entry] of byPackage) {
    const name = key.split('|')[1] ?? key;
    const highest = highestSeverity(entry.findings);
    const fixes = [...entry.fixes].sort();

    recommendations.push({
      id: `upgrade-${key}`,
      priority: priorityForSeverity(highest),
      title:
        fixes.length > 0
          ? `Upgrade ${name} to ${fixes.join(' or ')}`
          : `Review ${name} for a safer version`,
      detail:
        fixes.length > 0
          ? `${name} ${entry.version} is affected by ${entry.findings.length} known ${entry.findings.length === 1 ? 'advisory' : 'advisories'}. A fixed version has been published.`
          : `${name} ${entry.version} is affected by ${entry.findings.length} known ${entry.findings.length === 1 ? 'advisory' : 'advisories'}. No fixed version has been published, so consider whether the package is still appropriate.`,
      category: 'dependency-security',
      evidence: {
        checked: `${name} ${entry.version} against the OSV vulnerability database`,
        found: entry.findings.map((finding) => finding.advisoryIds.join('/')).join(', '),
        source: 'https://osv.dev',
        explanation: `Highest severity reported by the advisory sources: ${highest}.`,
        ...(highest === 'Unknown'
          ? {
              limitation:
                'The advisory source published no severity rating, so the real impact may be higher or lower.',
            }
          : {}),
      },
    });
  }

  return recommendations;
}

function highestSeverity(findings: readonly VulnerabilityFinding[]): string {
  const order = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
  let best = 'Unknown';
  let bestRank = order.length;
  for (const finding of findings) {
    const rank = order.indexOf(finding.severity);
    if (rank >= 0 && rank < bestRank) {
      bestRank = rank;
      best = finding.severity;
    }
  }
  return best;
}

function priorityForSeverity(severity: string): Priority {
  switch (severity) {
    case 'Critical':
      return 'Critical';
    case 'High':
      return 'High';
    case 'Medium':
      return 'Medium';
    case 'Low':
      return 'Low';
    default:
      // An unrated advisory is still a real advisory; Medium avoids both dismissing it
      // and overstating it.
      return 'Medium';
  }
}

/**
 * The lockfile recommendation.
 *
 * DepGuard's most distinctive piece of advice, and it exists because of a limitation
 * rather than in spite of one: when most versions are ranges, almost nothing can be
 * checked, and the fix is within the maintainer's control.
 */
function coverageRecommendations(
  coverage: DependencyCoverage | null,
  result: VulnerabilityResult,
): Recommendation[] {
  if (coverage === null || coverage.totalPackages === 0) {
    return [];
  }

  const unchecked = coverage.totalPackages - coverage.queryablePackages;
  if (unchecked === 0) {
    return [];
  }

  const severelyLimited = coverage.queryableRatio < 0.5;

  const recommendations: Recommendation[] = [];

  if (coverage.rangeVersionsDominant || severelyLimited) {
    recommendations.push({
      id: 'commit-lockfile',
      // High when it blocks security analysis entirely, not merely inconvenient.
      priority: severelyLimited ? 'High' : 'Medium',
      title: 'Commit a lockfile so dependency versions can be verified',
      detail:
        `${unchecked} of ${coverage.totalPackages} dependencies declare a version range rather than a resolved version, ` +
        'so they cannot be matched against vulnerability databases. Committing a lockfile ' +
        '(package-lock.json, yarn.lock, poetry.lock, Cargo.lock or equivalent) records the exact ' +
        'versions actually installed, which lets this and other security tools check them.',
      category: 'dependency-health',
      evidence: {
        checked: 'Declared version strings in the GitHub dependency graph',
        found: `${coverage.skippedByReason['version-not-exact']} version ranges, ${coverage.skippedByReason['no-version']} dependencies with no version`,
        source: 'GitHub dependency graph SBOM',
        explanation:
          'Vulnerability databases match advisories to exact versions. A range such as ^1.2.1 does not identify which version is installed.',
        limitation:
          result.kind === 'not-applicable'
            ? 'Because of this, no vulnerability analysis was possible for this repository. That is not evidence that its dependencies are safe.'
            : 'Dependencies declared as ranges were not checked, so the vulnerability results below are incomplete.',
      },
    });
  }

  const unsupported = coverage.skippedByReason['unsupported-ecosystem'];
  if (unsupported > 0) {
    recommendations.push({
      id: 'unsupported-ecosystems',
      priority: 'Informational',
      title: `${unsupported} ${unsupported === 1 ? 'dependency was' : 'dependencies were'} not checked for vulnerabilities`,
      detail:
        'Some dependencies belong to ecosystems DepGuard does not query, such as GitHub Actions. ' +
        'They are listed in the inventory but were not checked against vulnerability databases.',
      category: 'dependency-health',
      evidence: {
        checked: 'Package URL ecosystem of each dependency',
        found: `${unsupported} dependencies in unsupported ecosystems`,
        source: 'GitHub dependency graph SBOM',
        explanation:
          'These were excluded from vulnerability querying rather than reported as safe.',
      },
    });
  }

  return recommendations;
}

/** Priorities for missing configuration. Nothing here is a confirmed vulnerability. */
const CHECK_PRIORITIES: Readonly<Record<string, Priority>> = {
  'dependabot-config': 'Medium',
  'security-policy': 'Medium',
  'codeql-workflow': 'Low',
  'dependency-review': 'Low',
  'ci-workflow': 'Medium',
  license: 'Medium',
  readme: 'Low',
  tests: 'Medium',
  contributing: 'Informational',
  'code-of-conduct': 'Informational',
  'project-description': 'Informational',
};

const CHECK_CATEGORY: Readonly<Record<string, CategoryId>> = {
  'dependabot-config': 'security-configuration',
  'security-policy': 'security-configuration',
  'codeql-workflow': 'security-configuration',
  'dependency-review': 'security-configuration',
  'ci-workflow': 'security-configuration',
  license: 'security-configuration',
  readme: 'engineering',
  tests: 'engineering',
  contributing: 'engineering',
  'code-of-conduct': 'engineering',
  'project-description': 'engineering',
};

const CHECK_ACTIONS: Readonly<Record<string, string>> = {
  'dependabot-config':
    'Add .github/dependabot.yml to receive automated dependency update pull requests.',
  'security-policy': 'Add SECURITY.md describing how to report a vulnerability privately.',
  'codeql-workflow':
    'Add a CodeQL workflow to scan code for common vulnerability patterns on each change.',
  'dependency-review':
    'Add the dependency review action to catch vulnerable dependencies before merge.',
  'ci-workflow': 'Add a CI workflow so changes are built and tested automatically.',
  license: 'Add a LICENSE file so others know how they may use the project.',
  readme: 'Add a README explaining what the project does and how to use it.',
  tests: 'Add automated tests so changes can be verified.',
  contributing: 'Add CONTRIBUTING.md explaining how to propose changes.',
  'code-of-conduct': 'Add CODE_OF_CONDUCT.md to set expectations for participation.',
  'project-description':
    'Add a repository description and topics so people can find and understand the project.',
};

function checkRecommendations(
  securityChecks: readonly SecurityCheck[],
  engineeringChecks: readonly SecurityCheck[],
): Recommendation[] {
  const recommendations: Recommendation[] = [];

  for (const check of [...securityChecks, ...engineeringChecks]) {
    // Only a definite negative produces advice. An Unknown status means DepGuard could
    // not look, and recommending a fix for something that may already exist would be
    // advice based on an assumption (§7.1).
    if (check.status !== 'Not detected') {
      continue;
    }

    const action = CHECK_ACTIONS[check.id];
    if (action === undefined) {
      continue;
    }

    recommendations.push({
      id: `add-${check.id}`,
      priority: CHECK_PRIORITIES[check.id] ?? 'Low',
      title: check.label === 'Licence' ? 'Add a licence' : `Add ${check.label.toLowerCase()}`,
      detail: action,
      category: CHECK_CATEGORY[check.id] ?? 'engineering',
      evidence: check.evidence,
    });
  }

  return recommendations;
}

function maintenanceRecommendations(signals: MaintenanceSignals): Recommendation[] {
  if (signals.isArchived) {
    return [
      {
        id: 'archived-repository',
        priority: 'High',
        title: 'This repository is archived and will not receive fixes',
        detail:
          'The owner has archived this repository, so it will not receive security fixes or updates. ' +
          'If you depend on it, consider a maintained alternative or plan to vendor and maintain it yourself.',
        category: 'maintenance',
        evidence: {
          checked: 'Repository archived status',
          found: 'The repository is marked as archived.',
          source: 'GitHub repository metadata',
          explanation:
            'Archiving is an explicit statement by the owner that the project is no longer maintained.',
        },
      },
    ];
  }

  if (signals.classification === 'Potentially stale' && signals.daysSinceLastPush !== null) {
    return [
      {
        id: 'stale-activity',
        priority: 'Medium',
        title: 'Check whether this project is still maintained',
        detail:
          `There have been no commits for ${signals.daysSinceLastPush} days. ` +
          'Some mature projects legitimately need few changes, so confirm maintenance status before concluding it is abandoned.',
        category: 'maintenance',
        evidence: {
          checked: 'Date of the most recent push',
          found: `Last push ${signals.daysSinceLastPush} days ago`,
          source: 'GitHub repository metadata',
          explanation:
            'Commit recency is an activity signal, not a measure of quality. A stable project may need no changes.',
        },
      },
    ];
  }

  return [];
}
