/**
 * Vocabulary shared across the whole analysis.
 *
 * These types exist to make the specification's honesty rules structural rather than
 * advisory. Phase 0 measured, repeatedly, that missing data is the common case, not the
 * exception: 2 of 6 repositories had no SBOM at all, PYSEC advisories carry no severity
 * whatsoever, and one repository yielded zero analysable package versions. Types that
 * allow "unknown" to collapse into "zero" or "fine" would make those outcomes
 * misrepresentable, so they do not exist here.
 */

/**
 * Advisory severity (§5.1).
 *
 * `Unknown` is a real, frequently occurring value, not a defensive placeholder: every
 * PYSEC record measured in Phase 0 (22 of 22) carried neither a qualitative severity nor
 * a CVSS vector. It must never be rendered or scored as "safe".
 */
export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown';

export const SEVERITY_ORDER: readonly Severity[] = [
  'Critical',
  'High',
  'Medium',
  'Low',
  'Unknown',
] as const;

/**
 * Status of an observable repository check (§5.3).
 *
 * Deliberately not a boolean. DepGuard can observe that a file exists; it cannot observe
 * whether a GitHub feature is switched on, so `Configured` means "configuration present"
 * and nothing more.
 */
export type CheckStatus = 'Configured' | 'Not detected' | 'Unknown' | 'Not applicable';

/** The five analysis categories (§5). */
export type CategoryId =
  | 'dependency-security'
  | 'dependency-health'
  | 'security-configuration'
  | 'maintenance'
  | 'engineering';

export const CATEGORY_IDS: readonly CategoryId[] = [
  'dependency-security',
  'dependency-health',
  'security-configuration',
  'maintenance',
  'engineering',
] as const;

export const CATEGORY_LABELS: Readonly<Record<CategoryId, string>> = {
  'dependency-security': 'Dependency Security',
  'dependency-health': 'Dependency Health',
  'security-configuration': 'Security Configuration',
  maintenance: 'Maintenance and Activity',
  engineering: 'Engineering and Project Quality',
} as const;

/** Recommendation priority (§7.2). */
export type Priority = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

/**
 * Evidence backing a finding (§5.3).
 *
 * Every check and every recommendation must carry one of these. A finding with no
 * evidence is not a finding, and the type makes that impossible to express.
 */
export interface Evidence {
  /** What was examined, e.g. "Repository file tree". */
  readonly checked: string;
  /** What was actually found, e.g. ".github/dependabot.yml present". */
  readonly found: string;
  /** File path or API endpoint the observation came from. */
  readonly source: string;
  /** Plain-language explanation, including what this does NOT prove. */
  readonly explanation: string;
  /** Known limits on this observation, where any apply. */
  readonly limitation?: string;
}
