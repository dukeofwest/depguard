import type { Severity } from './analysis.model';

/**
 * Ecosystems DepGuard will send to OSV.
 *
 * Phase 0 verified `npm` and `PyPI` against live SBOMs. The remainder are mapped but
 * untested (ADR-0002), and the spec forbids claiming ecosystem support that has not been
 * demonstrated (§5.2), so the UI reports verification status rather than implying parity.
 */
export type OsvEcosystem =
  'npm' | 'PyPI' | 'Maven' | 'Go' | 'crates.io' | 'NuGet' | 'RubyGems' | 'Packagist';

/**
 * Why a package could not be checked for vulnerabilities.
 *
 * This is the most important diagnostic in the product. Phase 0 measured OSV-queryable
 * coverage ranging from 84.9% (`npm/cli`, which commits a lockfile) down to 0.0%
 * (`request/request`, which does not). Users must be told which of their packages went
 * unchecked and why.
 */
export type SkipReason =
  | 'no-purl'
  | 'unsupported-ecosystem'
  | 'no-version'
  /**
   * The version is not a single concrete version: a range (`^1.2.1`), a wildcard
   * (`1.x`), a tag (`latest`), or a format the classifier does not recognise. Named for
   * what was observed rather than assuming a range, since all of these are unusable for
   * the same reason.
   */
  | 'version-not-exact';

/**
 * How usable a declared version string is.
 *
 * Only `exact` versions may be sent to OSV. Phase 0 demonstrated that OSV does not reject
 * a range supplied where a version belongs — querying `lodash@^4.17.15` returned 4
 * advisories while the exact `4.17.15` returned 5, a different and wrong answer. Passing
 * ranges through would produce confident, unfalsifiable, incorrect findings (ADR-0002).
 */
export type VersionKind = 'exact' | 'range' | 'missing';

/** Whether a package is a direct dependency, per SBOM relationship data. */
export type DependencyRelationship = 'direct' | 'transitive' | 'unknown';

/**
 * Where a dependency was discovered.
 *
 * Never inferred, and never merged away: §4.4 requires that a dependency found in a
 * manifest is not represented as though it came from a fully resolved dependency graph.
 * The report shows this so a reader can tell a lockfile-backed inventory from a
 * declaration-only one.
 */
export type DependencySource =
  | 'github-sbom'
  | 'package-lock.json'
  | 'npm-shrinkwrap.json'
  | 'package.json'
  // .NET. Only the first two state installed versions; the rest are declarations.
  | 'packages.lock.json'
  | 'packages.config'
  | 'csproj'
  | 'vbproj'
  | 'fsproj'
  | 'Directory.Packages.props';

/**
 * How much a version string is actually worth.
 *
 * This is the distinction that keeps DepGuard from producing confident, wrong findings,
 * and it is why `queryablePackages` admits only `resolved`.
 *
 * - `resolved` — a lockfile or dependency graph stated the version that is installed.
 * - `declared-minimum` — a manifest stated a lower bound. A NuGet
 *   `<PackageReference Version="13.0.1" />` means `[13.0.1, )`, so the installed version
 *   may be higher. Querying OSV with the lower bound would report advisories fixed in a
 *   version the project actually uses: a false positive that looks entirely plausible.
 * - `declared-range` — a manifest stated a range, e.g. `^4.17.15`. Phase 0 measured that
 *   OSV answers a range query rather than rejecting it, and answers it differently:
 *   `lodash@^4.17.15` returned 4 advisories where the exact `4.17.15` returned 5.
 * - `unresolved` — a version exists but cannot be determined statically, e.g. an MSBuild
 *   `$(Property)`. Recorded as unknown rather than guessed (§13 constraint 12).
 * - `absent` — no version information at all.
 */
export type VersionResolution =
  'resolved' | 'declared-minimum' | 'declared-range' | 'unresolved' | 'absent';

/**
 * Whether a dependency ships to users.
 *
 * `unknown` is a real state: GitHub's SBOM carries no development flag, so claiming
 * production for an SBOM-derived package would be inventing information.
 */
export type DependencyScope = 'production' | 'development' | 'optional' | 'unknown';

/** A dependency normalised from the SBOM, before vulnerability matching. */
export interface NormalizedPackage {
  /** Stable key for deduplication: `ecosystem|name|version`. */
  readonly key: string;
  readonly name: string;
  /** Raw purl type as it appeared in the SBOM, e.g. `npm`, `githubactions`. */
  readonly purlType: string | null;
  /** Null when the purl type has no OSV ecosystem; such packages are never queried. */
  readonly ecosystem: OsvEcosystem | null;
  readonly declaredVersion: string | null;
  readonly versionKind: VersionKind;
  readonly relationship: DependencyRelationship;
  readonly licenseConcluded: string | null;
  /** Absent when the package is queryable; present when it is not. */
  readonly skipReason: SkipReason | null;
  /** Which file or API this dependency came from. */
  readonly source: DependencySource;
  /** The repository path it came from, or null for API-derived inventories. */
  readonly sourcePath: string | null;
  /**
   * What the version means. Only `resolved` may be sent to OSV.
   *
   * Kept separate from `versionKind`, which describes the *shape* of the string. A
   * NuGet declared minimum is shaped like an exact version and is not one, so shape
   * alone cannot decide whether a version is safe to query.
   */
  readonly resolution: VersionResolution;
  readonly scope: DependencyScope;
}

/** A dependency joined with its vulnerability findings, for the inventory table (§5.2). */
export interface DependencyRow {
  readonly package: NormalizedPackage;
  readonly vulnerabilityCount: number;
  readonly highestSeverity: Severity | null;
  /** False when the package was skipped — distinct from "checked and clean". */
  readonly wasChecked: boolean;
}

/**
 * Dependency inventory coverage.
 *
 * `queryableRatio` gates whether Dependency Security may produce a score at all
 * (ADR-0003): below 0.5, the category reports insufficient data instead of a misleading
 * clean result.
 */
export interface DependencyCoverage {
  readonly totalPackages: number;
  readonly queryablePackages: number;
  readonly queryableRatio: number;
  readonly skippedByReason: Readonly<Record<SkipReason, number>>;
  /** True when no lockfile appears to be committed — the dominant cause of low coverage. */
  readonly rangeVersionsDominant: boolean;
  /** Which source produced this inventory, for the report's provenance statement. */
  readonly inventorySource: DependencySource;
  /**
   * How much of the transitive graph this source can express.
   *
   * `none` for a manifest that lists only direct declarations. §5.7 forbids claiming
   * transitive coverage that the parsed files cannot support.
   */
  readonly transitiveCoverage: 'full' | 'partial' | 'none';
  /** Parse limitations, skipped files and unresolved values, for the report. */
  readonly discoveryNotes: readonly string[];
  /**
   * Entries describing a package and version that another entry already described.
   *
   * Measured, not hypothetical: `npm/cli` returns 102 of these in 1,207 entries, because
   * the same package at the same version is reachable through several paths in a real
   * dependency graph. They are therefore **kept** in the inventory - GitHub reported them
   * and the count must match what GitHub reported - but they are collapsed before
   * querying OSV, since they are the same question with the same answer.
   *
   * Reported so that an SBOM consisting of one entry repeated 100,000 times is visible
   * rather than silently expensive.
   */
  readonly duplicateEntries: number;
}
