import type {
  DependencyCoverage,
  DependencyScope,
  DependencySource,
  NormalizedPackage,
  SkipReason,
} from '../../core/models/dependency.model';
import { classifyVersion } from './purl';
import { boundedString } from '../validation/external-input';
import { computeCoverage } from '../sbom/spdx-parser';

/**
 * npm lockfile parsing.
 *
 * Pure, total and deterministic: every malformed input yields a result describing what
 * could be read, never an exception. The document is untrusted repository content (§9.2).
 *
 * This exists because GitHub's dependency graph is not available for every repository —
 * measured: `dukeofwest/depguard` returns 404 from the SBOM endpoint even with an
 * authenticated token, while committing a `package-lock.json` with 587 packages, all 587
 * carrying exact resolved versions. Reporting "no dependency inventory" for that
 * repository was correct about GitHub and wrong about the repository.
 *
 * A lockfile is the *better* source where both exist, because it states what is actually
 * installed. GitHub's graph remains preferred only because it is already normalised,
 * covers ecosystems this file does not, and costs a request DepGuard has already spent.
 */

/** Maximum entries read from one lockfile, mirroring the SBOM package cap. */
const MAX_ENTRIES = 20000;

/** Maximum nesting followed in a v1 `dependencies` tree. */
const MAX_TREE_DEPTH = 64;

export type NpmLockfileResult =
  | {
      readonly kind: 'parsed';
      readonly packages: readonly NormalizedPackage[];
      readonly coverage: DependencyCoverage;
      readonly lockfileVersion: number;
      /** Limitations encountered while parsing, for the report. */
      readonly notes: readonly string[];
    }
  | { readonly kind: 'invalid'; readonly reason: string }
  | { readonly kind: 'unsupported'; readonly reason: string };

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function str(value: unknown): string | null {
  return boundedString(value);
}

/**
 * Reads an own, non-inherited property.
 *
 * Lockfile keys are attacker-controlled package paths, so `obj[key]` would otherwise
 * resolve `__proto__`, `constructor` and `toString` to inherited values and admit
 * prototype-pollution-shaped confusion. Everything that walks a lockfile object goes
 * through here or through `ownEntries`.
 */
function own(record: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined;
}

/** Own enumerable entries only, with inherited and `__proto__` keys excluded. */
function ownEntries(record: Record<string, unknown>): readonly [string, unknown][] {
  return Object.entries(record).filter(
    ([key]) => key !== '__proto__' && Object.prototype.hasOwnProperty.call(record, key),
  );
}

/**
 * Parses a `package-lock.json` or `npm-shrinkwrap.json` body.
 *
 * Accepts the parsed JSON rather than text: the caller has already applied the shared
 * size, depth, node-count and string-length bounds in `response-guard.ts`, so this
 * function never sees an unbounded object graph.
 */
export function parseNpmLockfile(
  body: unknown,
  source: DependencySource,
  path: string,
): NpmLockfileResult {
  if (!isObject(body)) {
    return { kind: 'invalid', reason: `${path} is not a JSON object.` };
  }

  const rawVersion = own(body, 'lockfileVersion');
  const lockfileVersion = typeof rawVersion === 'number' ? rawVersion : null;

  if (lockfileVersion === null) {
    return {
      kind: 'invalid',
      reason: `${path} declares no lockfileVersion, so its format cannot be determined.`,
    };
  }

  // v2 and v3 both carry the flat `packages` map; v2 additionally carries the legacy
  // `dependencies` tree for older npm clients. The flat map is preferred wherever it
  // exists because it states each entry's resolved version and dev flag directly.
  const packagesMap = own(body, 'packages');
  const dependenciesTree = own(body, 'dependencies');

  if (isObject(packagesMap)) {
    return fromFlatPackages(packagesMap, lockfileVersion, source, path);
  }

  if (lockfileVersion === 1 && isObject(dependenciesTree)) {
    return fromDependencyTree(dependenciesTree, lockfileVersion, source, path);
  }

  // A version we do not recognise, reported by number rather than guessed at. §13
  // constraint 18 forbids claiming support that has not been implemented, and guessing a
  // future format's shape is how a parser silently produces a wrong inventory.
  if (lockfileVersion > 3) {
    return {
      kind: 'unsupported',
      reason: `${path} uses lockfileVersion ${lockfileVersion}, which this release does not support. Supported versions are 1, 2 and 3.`,
    };
  }

  return {
    kind: 'invalid',
    reason: `${path} declares lockfileVersion ${lockfileVersion} but contains no readable package list.`,
  };
}

/**
 * Reads the flat `packages` map used by lockfile v2 and v3.
 *
 * Keys are paths relative to the project root: `""` is the root project itself,
 * `node_modules/x` is a hoisted install, and `packages/app/node_modules/x` is a workspace
 * one. Nested paths such as `node_modules/a/node_modules/b` express a version conflict
 * that npm resolved by duplicating the tree.
 */
function fromFlatPackages(
  packagesMap: Record<string, unknown>,
  lockfileVersion: number,
  source: DependencySource,
  path: string,
): NpmLockfileResult {
  const notes: string[] = [];
  const packages: NormalizedPackage[] = [];

  // Direct dependencies are those named in the root project's own manifest sections,
  // which the lockfile mirrors at the `""` key.
  const root = own(packagesMap, '');
  const directNames = isObject(root) ? directDependencyNames(root) : null;

  let truncated = false;
  let skippedLinks = 0;
  let skippedWithoutVersion = 0;

  for (const [key, entry] of ownEntries(packagesMap)) {
    if (key === '') {
      continue;
    }
    if (packages.length >= MAX_ENTRIES) {
      truncated = true;
      break;
    }
    if (!isObject(entry)) {
      continue;
    }

    // `link: true` entries point at a workspace directory rather than a registry
    // package. They have no registry identity and no version to check, so they are
    // counted rather than invented.
    if (own(entry, 'link') === true) {
      skippedLinks += 1;
      continue;
    }

    const name = packageNameFromPath(key) ?? str(own(entry, 'name'));
    if (name === null) {
      continue;
    }

    const version = str(own(entry, 'version'));
    if (version === null) {
      // An entry with no version: npm writes these for some `file:` and workspace
      // dependencies. Recorded as absent rather than skipped silently.
      skippedWithoutVersion += 1;
    }

    packages.push(
      normalize({
        name,
        version,
        source,
        path,
        scope: scopeOf(entry),
        relationship:
          directNames === null ? 'unknown' : directNames.has(name) ? 'direct' : 'transitive',
      }),
    );
  }

  if (truncated) {
    notes.push(
      `${path} contains more than ${MAX_ENTRIES} entries; the inventory was truncated, so it is incomplete.`,
    );
  }
  if (skippedLinks > 0) {
    notes.push(
      `${skippedLinks} workspace link ${skippedLinks === 1 ? 'entry was' : 'entries were'} not included: they reference directories in this repository rather than published packages.`,
    );
  }
  if (skippedWithoutVersion > 0) {
    notes.push(
      `${skippedWithoutVersion} ${skippedWithoutVersion === 1 ? 'entry has' : 'entries have'} no resolved version recorded in the lockfile.`,
    );
  }
  if (directNames === null) {
    notes.push(
      `${path} records no root dependency list, so direct and transitive dependencies could not be distinguished.`,
    );
  }

  return {
    kind: 'parsed',
    packages,
    coverage: computeCoverage(packages, countDuplicates(packages), {
      inventorySource: source,
      // The flat map is npm's own resolved install tree: every installed package appears,
      // not only the declared ones.
      transitiveCoverage: truncated ? 'partial' : 'full',
      discoveryNotes: notes,
    }),
    lockfileVersion,
    notes,
  };
}

/**
 * Reads the nested `dependencies` tree used by lockfile v1.
 *
 * Traversal is **iterative**. A recursive walker would overflow the stack on exactly the
 * input it exists to reject — a lockfile nested tens of thousands of levels deep — which
 * is the same reasoning as `checkJsonShape` in `engine/validation/external-input.ts`.
 */
function fromDependencyTree(
  tree: Record<string, unknown>,
  lockfileVersion: number,
  source: DependencySource,
  path: string,
): NpmLockfileResult {
  const notes: string[] = [];
  const packages: NormalizedPackage[] = [];

  interface Frame {
    readonly record: Record<string, unknown>;
    readonly depth: number;
    /** Depth 1 is the root manifest's own dependency list. */
    readonly isTopLevel: boolean;
  }

  const stack: Frame[] = [{ record: tree, depth: 1, isTopLevel: true }];
  let truncated = false;
  let depthExceeded = false;

  while (stack.length > 0) {
    const frame = stack.pop();
    if (frame === undefined) {
      break;
    }

    if (frame.depth > MAX_TREE_DEPTH) {
      depthExceeded = true;
      continue;
    }

    for (const [name, entry] of ownEntries(frame.record)) {
      if (packages.length >= MAX_ENTRIES) {
        truncated = true;
        break;
      }
      if (!isObject(entry)) {
        continue;
      }

      packages.push(
        normalize({
          name,
          version: str(own(entry, 'version')),
          source,
          path,
          scope: scopeOf(entry),
          // v1 expresses the install tree by nesting, so top-level entries are the
          // direct dependencies and everything nested below them is transitive.
          relationship: frame.isTopLevel ? 'direct' : 'transitive',
        }),
      );

      const nested = own(entry, 'dependencies');
      if (isObject(nested)) {
        stack.push({ record: nested, depth: frame.depth + 1, isTopLevel: false });
      }
    }

    if (truncated) {
      break;
    }
  }

  if (truncated) {
    notes.push(
      `${path} contains more than ${MAX_ENTRIES} entries; the inventory was truncated, so it is incomplete.`,
    );
  }
  if (depthExceeded) {
    notes.push(
      `${path} nests dependencies more than ${MAX_TREE_DEPTH} levels deep; the deepest entries were not read.`,
    );
  }

  return {
    kind: 'parsed',
    packages,
    coverage: computeCoverage(packages, countDuplicates(packages), {
      inventorySource: source,
      transitiveCoverage: truncated || depthExceeded ? 'partial' : 'full',
      discoveryNotes: notes,
    }),
    lockfileVersion,
    notes,
  };
}

/**
 * The names the root project declares directly.
 *
 * Peer and optional dependencies are included: they are declared by this project, so
 * they are direct, whatever their install semantics.
 */
function directDependencyNames(root: Record<string, unknown>): ReadonlySet<string> | null {
  const names = new Set<string>();
  let found = false;

  for (const section of [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies',
  ]) {
    const value = own(root, section);
    if (isObject(value)) {
      found = true;
      for (const [name] of ownEntries(value)) {
        names.add(name);
      }
    }
  }

  return found ? names : null;
}

/**
 * The package name from a lockfile path key.
 *
 * `node_modules/lodash` → `lodash`; `node_modules/@babel/core` → `@babel/core`;
 * `packages/app/node_modules/x` → `x`. The segment after the **last** `node_modules` is
 * the installed package, and a leading `@` means the following segment belongs to it.
 */
export function packageNameFromPath(key: string): string | null {
  const marker = 'node_modules/';
  const index = key.lastIndexOf(marker);
  if (index < 0) {
    return null;
  }

  const remainder = key.slice(index + marker.length);
  if (remainder.length === 0) {
    return null;
  }

  const segments = remainder.split('/');
  const first = segments[0];
  if (first === undefined || first.length === 0) {
    return null;
  }

  if (first.startsWith('@')) {
    const second = segments[1];
    return second === undefined || second.length === 0 ? null : `${first}/${second}`;
  }

  return first;
}

/** npm's own flags. `dev` covers `devDependencies` and anything reachable only through it. */
function scopeOf(entry: Record<string, unknown>): DependencyScope {
  if (own(entry, 'dev') === true || own(entry, 'devOptional') === true) {
    return 'development';
  }
  if (own(entry, 'optional') === true) {
    return 'optional';
  }
  return 'production';
}

/**
 * Builds a `NormalizedPackage` for an npm lockfile entry.
 *
 * A lockfile records what npm installed, so an exact version here is genuinely
 * `resolved`. Anything else is reported for what it is and never queried: an alias
 * specifier such as `npm:left-pad@1.3.0`, a `file:` or `git:` reference, or a missing
 * version are all unusable for vulnerability matching, and saying so costs coverage
 * rather than correctness.
 */
function normalize(input: {
  readonly name: string;
  readonly version: string | null;
  readonly source: DependencySource;
  readonly path: string;
  readonly scope: DependencyScope;
  readonly relationship: NormalizedPackage['relationship'];
}): NormalizedPackage {
  const versionKind = classifyVersion(input.version);
  const resolved = versionKind === 'exact';

  const skipReason: SkipReason | null = resolved
    ? null
    : versionKind === 'missing'
      ? 'no-version'
      : 'version-not-exact';

  return {
    key: `npm|${input.name}|${input.version ?? ''}`,
    name: input.name,
    purlType: 'npm',
    ecosystem: 'npm',
    declaredVersion: input.version,
    versionKind,
    relationship: input.relationship,
    licenseConcluded: null,
    skipReason,
    source: input.source,
    sourcePath: input.path,
    resolution: resolved ? 'resolved' : versionKind === 'missing' ? 'absent' : 'declared-range',
    scope: input.scope,
  };
}

/**
 * Counts entries describing a package and version already seen.
 *
 * Kept in the inventory for the same reason the SBOM parser keeps them: npm genuinely
 * installs one package at one version in several places, and a dependency count that
 * disagrees with the lockfile is worse than one that includes real repetition. They are
 * collapsed before querying by `queryablePackages`.
 */
function countDuplicates(packages: readonly NormalizedPackage[]): number {
  const seen = new Set<string>();
  let duplicates = 0;
  for (const pkg of packages) {
    if (seen.has(pkg.key)) {
      duplicates += 1;
    } else {
      seen.add(pkg.key);
    }
  }
  return duplicates;
}
