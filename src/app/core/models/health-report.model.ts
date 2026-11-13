import type { CategoryId, CheckStatus, Evidence, Priority } from './analysis.model';
import type { DependencyCoverage, DependencyRow } from './dependency.model';
import type { RepositoryMetadata } from './repository.model';
import type { VulnerabilityResult } from './vulnerability.model';

/** A single observable repository check (§5.3). */
export interface SecurityCheck {
  readonly id: string;
  readonly label: string;
  readonly status: CheckStatus;
  readonly evidence: Evidence;
}

/** One traceable score deduction. Every lost point must have one (§6.5). */
export interface Deduction {
  readonly reason: string;
  readonly points: number;
  /** Links the deduction to the finding that caused it. */
  readonly relatedFindingKey?: string;
}

/**
 * A category's outcome.
 *
 * A discriminated union, so an unscorable category is structurally incapable of being
 * read as zero (§6.2). This is the type-level enforcement of the specification's rule
 * that unavailable data must be excluded from the calculation rather than penalised.
 */
export type CategoryResult =
  | {
      readonly kind: 'scored';
      readonly id: CategoryId;
      /** 0–100. */
      readonly score: number;
      /** 0–1: how much of the intended analysis completed. */
      readonly coverage: number;
      readonly deductions: readonly Deduction[];
      readonly summary: string;
    }
  | {
      readonly kind: 'insufficient-data';
      readonly id: CategoryId;
      readonly coverage: number;
      /** User-facing explanation of what was missing and why it matters. */
      readonly reason: string;
    };

/** Score bands (§6.4). Presented as DepGuard's heuristic, not a certification. */
export type ScoreBand = 'Excellent' | 'Good' | 'Fair' | 'Needs attention' | 'Poor';

/**
 * The overall result.
 *
 * `unavailable` exists for the case where too little could be analysed to justify any
 * headline number at all — the report then shows findings without a score.
 */
export type OverallResult =
  | {
      readonly kind: 'scored';
      readonly score: number;
      readonly band: ScoreBand;
      readonly coverage: number;
      /** Categories excluded from the calculation, with their weight redistributed. */
      readonly excludedCategories: readonly CategoryId[];
      readonly explanation: string;
    }
  | { readonly kind: 'unavailable'; readonly reason: string };

/** An evidence-backed, actionable improvement (§7.1). */
export interface Recommendation {
  readonly id: string;
  readonly priority: Priority;
  readonly title: string;
  readonly detail: string;
  readonly category: CategoryId;
  readonly evidence: Evidence;
}

/** Repository activity classification (§5.4). Thresholds live in one place. */
export type ActivityClassification =
  | 'Recently active'
  | 'Active'
  | 'Limited activity'
  | 'Potentially stale'
  | 'Archived'
  | 'Insufficient data';

export interface MaintenanceSignals {
  readonly classification: ActivityClassification;
  readonly daysSinceLastPush: number | null;
  readonly daysSinceLastRelease: number | null;
  readonly commitsLast52Weeks: number | null;
  readonly contributorCount: number | null;
  readonly isArchived: boolean;
}

export interface EngineeringSignals {
  readonly checks: readonly SecurityCheck[];
  readonly hasReadme: boolean;
  readonly hasTests: boolean | null;
  readonly hasCi: boolean;
}

/** Something the analysis could not establish, surfaced to the user (§6.3). */
export interface AnalysisLimitation {
  readonly scope: string;
  readonly detail: string;
}

/** Where the data came from, for the export and the UI (§7.3). */
export interface DataSourceInfo {
  readonly name: string;
  readonly endpoint: string;
  readonly retrievedAt: string;
  readonly status: 'ok' | 'unavailable' | 'partial';
}

/**
 * The complete analysis report.
 *
 * This is also the exported JSON payload (§7.3). It contains no credentials by
 * construction, because the application never holds any (§9.1).
 */
export interface HealthReport {
  readonly schemaVersion: string;
  readonly generatedAt: string;
  readonly repository: RepositoryMetadata;
  readonly overall: OverallResult;
  readonly categories: readonly CategoryResult[];
  readonly dependencies: readonly DependencyRow[];
  readonly dependencyCoverage: DependencyCoverage | null;
  readonly vulnerabilities: VulnerabilityResult;
  readonly securityChecks: readonly SecurityCheck[];
  readonly maintenance: MaintenanceSignals;
  readonly engineering: EngineeringSignals;
  readonly recommendations: readonly Recommendation[];
  readonly limitations: readonly AnalysisLimitation[];
  readonly dataSources: readonly DataSourceInfo[];
}
