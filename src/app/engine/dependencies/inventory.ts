import type {
  DependencyCoverage,
  DependencySource,
  NormalizedPackage,
} from '../../core/models/dependency.model';
import { computeCoverage } from '../sbom/spdx-parser';

/**
 * Merges the inventories discovered across several manifests.
 *
 * Pure. Exists because a monorepo has one lockfile per workspace, and the same package at
 * the same version is routinely installed in several of them: `packages/a` and
 * `packages/b` both depending on `lodash@4.17.21` must not make the repository look as
 * though it has two `lodash` dependencies.
 *
 * The rule, which mirrors how the SBOM parser treats GitHub's own duplicates:
 *
 * - **Across files**, a package at the same version is one dependency. Counting it twice
 *   would report an inventory size the repository does not have.
 * - **Within a file**, npm's genuine duplicates are already counted by the lockfile
 *   parser and kept, because the lockfile really does install them separately.
 *
 * Where the same package is reached directly in one workspace and transitively in
 * another, `direct` wins: it is directly declared *somewhere*, and reporting it as
 * transitive would hide that a maintainer chose it.
 */
export function mergeInventories(
  inventories: readonly {
    readonly packages: readonly NormalizedPackage[];
    readonly source: DependencySource;
    readonly transitiveCoverage: DependencyCoverage['transitiveCoverage'];
  }[],
  notes: readonly string[],
): { readonly packages: readonly NormalizedPackage[]; readonly coverage: DependencyCoverage } {
  const byKey = new Map<string, NormalizedPackage>();
  let duplicatesAcrossFiles = 0;

  for (const inventory of inventories) {
    for (const pkg of inventory.packages) {
      const existing = byKey.get(pkg.key);
      if (existing === undefined) {
        byKey.set(pkg.key, pkg);
        continue;
      }

      duplicatesAcrossFiles += 1;
      byKey.set(pkg.key, merge(existing, pkg));
    }
  }

  const packages = [...byKey.values()];

  // `transitiveCoverage` is `full` only when every source could express the graph, and
  // `none` only when none of them could. Anything else is `partial`.
  //
  // Both ends matter. A repository with one `packages.lock.json` and 80 `.csproj` files
  // must not be described as having full transitive coverage (§5.7) — but it must not be
  // described as having none either, because the lockfile really did supply the graph for
  // its own project. "Partial" is the only statement the evidence supports.
  const levels = inventories.map((inventory) => inventory.transitiveCoverage);
  const transitiveCoverage = levels.every((level) => level === 'full')
    ? 'full'
    : levels.every((level) => level === 'none')
      ? 'none'
      : 'partial';

  // The source reported is the most authoritative one that contributed, since that is
  // what a reader needs in order to judge the inventory. Resolved sources rank above
  // declaration-only ones.
  const ranked: readonly DependencySource[] = [
    'github-sbom',
    'package-lock.json',
    'npm-shrinkwrap.json',
    'packages.lock.json',
    'packages.config',
    'csproj',
    'vbproj',
    'fsproj',
    'package.json',
    'Directory.Packages.props',
  ];
  const sources = inventories.map((inventory) => inventory.source);
  const inventorySource =
    ranked.find((candidate) => sources.includes(candidate)) ?? sources[0] ?? 'package-lock.json';

  return {
    packages,
    coverage: computeCoverage(packages, duplicatesAcrossFiles, {
      inventorySource,
      transitiveCoverage,
      discoveryNotes: notes,
    }),
  };
}

/**
 * Combines two entries for the same package at the same version.
 *
 * Prefers the more consequential classification in each dimension rather than the first
 * seen, so a merge cannot quietly downgrade what is known: `direct` beats `transitive`,
 * and a production install beats a development one — because a package that ships to
 * users in any workspace does ship to users.
 */
function merge(first: NormalizedPackage, second: NormalizedPackage): NormalizedPackage {
  const relationship =
    first.relationship === 'direct' || second.relationship === 'direct'
      ? 'direct'
      : first.relationship === 'transitive' || second.relationship === 'transitive'
        ? 'transitive'
        : 'unknown';

  const scope =
    first.scope === 'production' || second.scope === 'production'
      ? 'production'
      : first.scope === 'optional' || second.scope === 'optional'
        ? 'optional'
        : first.scope === 'development' || second.scope === 'development'
          ? 'development'
          : 'unknown';

  return {
    ...first,
    relationship,
    scope,
    // Both paths are real, so the first is kept and the inventory notes record that
    // several lockfiles contributed. Inventing a joined path would make the provenance
    // field unusable as a path.
    sourcePath: first.sourcePath,
  };
}
