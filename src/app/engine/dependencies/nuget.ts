import type {
  DependencyCoverage,
  DependencyRelationship,
  DependencyScope,
  DependencySource,
  NormalizedPackage,
  SkipReason,
  VersionResolution,
} from '../../core/models/dependency.model';
import { classifyVersion } from './purl';
import { boundedString } from '../validation/external-input';
import { computeCoverage } from '../sbom/spdx-parser';
import { attribute, childElement, findElements, parseXml, type XmlElement } from './xml';

/**
 * NuGet / .NET dependency discovery.
 *
 * ## The rule this file exists to enforce
 *
 * In NuGet, `<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />` does **not**
 * say that 13.0.1 is installed. A bare version is shorthand for the range `[13.0.1, )` — a
 * *minimum*. NuGet resolves it to the lowest available version satisfying it, which is
 * usually 13.0.1 but is not guaranteed to be, and transitive resolution can lift it higher.
 *
 * A parser that treats that string as a resolved version produces **false positives**: if
 * 13.0.1 carries an advisory fixed in 13.0.2 and the project actually restored 13.0.3,
 * DepGuard reports a vulnerability on a project that does not have one. That is the mirror
 * image of the `lodash@^4.17.15` problem ADR-0002 was written about, and worse, because it
 * is confident in the other direction.
 *
 * So: only `packages.lock.json`, `packages.config` and NuGet's bracketed exact syntax
 * `[13.0.1]` yield `resolved`. Everything from a project file is `declared-minimum`,
 * `declared-range` or `unresolved`, and `queryablePackages` never sends those to OSV.
 *
 * ## What is deliberately not done
 *
 * MSBuild is never executed (§13 constraint 7). Imports are not followed. A
 * `$(Property)` reference is resolved only when its value is a literal in a file already
 * parsed for another reason; otherwise the version is `unresolved` and said to be. This is
 * static analysis, not an MSBuild implementation (§7.4 stage 4).
 */

/** Entries read from one file. Mirrors the npm and SBOM caps. */
const MAX_PACKAGES_PER_FILE = 20000;

export type NuGetParseResult =
  | {
      readonly kind: 'parsed';
      readonly packages: readonly NormalizedPackage[];
      readonly notes: readonly string[];
    }
  | { readonly kind: 'rejected'; readonly reason: string };

/** A central version definition from `Directory.Packages.props`. */
export interface CentralVersions {
  /** Package id, lowercased, to the version string declared for it. */
  readonly versions: Readonly<Record<string, string>>;
  /** MSBuild properties whose values are literals, for `$(Prop)` substitution. */
  readonly properties: Readonly<Record<string, string>>;
  readonly path: string;
}

/**
 * NuGet package ids are case-insensitive.
 *
 * Measured against OSV on 14 November 2026: `Newtonsoft.Json`, `newtonsoft.json` and
 * `NEWTONSOFT.JSON` at 9.0.1 all returned the same advisory, and OSV also normalised
 * two- and four-part version strings. So **no normalisation is required for matching** —
 * the canonical casing is preserved for display, and lowercase is used only as a lookup
 * key for central version resolution.
 */
function idKey(id: string): string {
  return id.toLowerCase();
}

function str(value: unknown): string | null {
  return boundedString(value);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function own(record: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined;
}

function ownEntries(record: Record<string, unknown>): readonly [string, unknown][] {
  return Object.entries(record).filter(
    ([key]) => key !== '__proto__' && Object.prototype.hasOwnProperty.call(record, key),
  );
}

// ---------------------------------------------------------------------------
// packages.lock.json — the only project-file source of resolved versions
// ---------------------------------------------------------------------------

/**
 * Parses `packages.lock.json`.
 *
 * The one .NET file that states what was actually restored. Shape:
 *
 * ```json
 * { "version": 1,
 *   "dependencies": {
 *     ".NETCoreApp,Version=v8.0": {
 *       "Newtonsoft.Json": { "type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1" }
 *     } } }
 * ```
 *
 * `requested` and `resolved` are **not** interchangeable: `requested` is the constraint
 * the project asked for and `resolved` is what NuGet picked. Only `resolved` is queried.
 */
export function parseNuGetLockfile(body: unknown, path: string): NuGetParseResult {
  if (!isObject(body)) {
    return { kind: 'rejected', reason: `${path} is not a JSON object.` };
  }

  const dependencies = own(body, 'dependencies');
  if (!isObject(dependencies)) {
    return {
      kind: 'rejected',
      reason: `${path} contains no dependency list, so no resolved versions could be read.`,
    };
  }

  const packages: NormalizedPackage[] = [];
  const notes: string[] = [];
  const frameworks: string[] = [];
  let withoutResolved = 0;
  let truncated = false;

  for (const [framework, entries] of ownEntries(dependencies)) {
    if (!isObject(entries)) {
      continue;
    }
    frameworks.push(framework);

    for (const [id, entry] of ownEntries(entries)) {
      if (packages.length >= MAX_PACKAGES_PER_FILE) {
        truncated = true;
        break;
      }
      if (!isObject(entry)) {
        continue;
      }

      const resolved = str(own(entry, 'resolved'));
      const requested = str(own(entry, 'requested'));
      const type = str(own(entry, 'type'));

      if (resolved === null) {
        // A `Project` entry (a project reference) has no resolved version, and neither
        // does a malformed one. Counted, never filled in from `requested`.
        withoutResolved += 1;
      }

      packages.push(
        build({
          id,
          version: resolved ?? requested,
          // `resolved` is genuinely installed. Falling back to `requested` keeps the
          // dependency visible in the inventory while marking it unqueryable.
          resolution: resolved === null ? 'declared-range' : exactness(resolved),
          source: 'packages.lock.json',
          path,
          relationship: relationshipFromLockType(type),
          scope: 'unknown',
          framework,
        }),
      );
    }

    if (truncated) {
      break;
    }
  }

  if (truncated) {
    notes.push(
      `${path} lists more than ${MAX_PACKAGES_PER_FILE} packages; the inventory was truncated.`,
    );
  }
  if (withoutResolved > 0) {
    notes.push(
      `${withoutResolved} ${withoutResolved === 1 ? 'entry in' : 'entries in'} ${path} ${withoutResolved === 1 ? 'has' : 'have'} no resolved version, so ${withoutResolved === 1 ? 'it was' : 'they were'} not checked for vulnerabilities.`,
    );
  }
  if (frameworks.length > 1) {
    notes.push(
      `${path} resolves packages for ${frameworks.length} target frameworks (${frameworks.join(', ')}). Packages resolved to different versions per framework appear once for each.`,
    );
  }

  return { kind: 'parsed', packages, notes };
}

/** NuGet's own classification. `Project` is a project reference, not a package. */
function relationshipFromLockType(type: string | null): DependencyRelationship {
  switch (type?.toLowerCase()) {
    case 'direct':
      return 'direct';
    case 'transitive':
      return 'transitive';
    default:
      return 'unknown';
  }
}

// ---------------------------------------------------------------------------
// packages.config — legacy, and genuinely resolved
// ---------------------------------------------------------------------------

/**
 * Parses a legacy `packages.config`.
 *
 * ```xml
 * <packages><package id="Newtonsoft.Json" version="13.0.1" targetFramework="net48" /></packages>
 * ```
 *
 * Unlike a `PackageReference`, this `version` is the version actually installed into
 * `packages/` — the old NuGet model wrote the resolved result here. So it is `resolved`,
 * and it is the only XML .NET source for which that is true.
 *
 * It expresses no transitive information: the file is flat and every entry looks the same
 * whether a human asked for it or NuGet pulled it in.
 */
export function parsePackagesConfig(text: string, path: string): NuGetParseResult {
  const parsedXml = parseXml(text);
  if (parsedXml.kind === 'rejected') {
    return { kind: 'rejected', reason: `${path}: ${parsedXml.reason}` };
  }

  const packages: NormalizedPackage[] = [];
  const notes: string[] = [];
  let withoutVersion = 0;

  for (const element of findElements(parsedXml.root, 'package')) {
    if (packages.length >= MAX_PACKAGES_PER_FILE) {
      notes.push(`${path} lists more than ${MAX_PACKAGES_PER_FILE} packages; it was truncated.`);
      break;
    }

    const id = attribute(element, 'id');
    if (id === null) {
      continue;
    }

    const version = attribute(element, 'version');
    if (version === null) {
      withoutVersion += 1;
    }

    packages.push(
      build({
        id,
        version,
        resolution: version === null ? 'absent' : exactness(version),
        source: 'packages.config',
        path,
        // Flat file: nothing in it distinguishes a direct dependency from one NuGet
        // installed on a dependency's behalf.
        relationship: 'unknown',
        scope: attribute(element, 'developmentdependency') === 'true' ? 'development' : 'unknown',
        framework: attribute(element, 'targetframework'),
      }),
    );
  }

  if (withoutVersion > 0) {
    notes.push(
      `${withoutVersion} ${withoutVersion === 1 ? 'entry' : 'entries'} in ${path} ${withoutVersion === 1 ? 'declares' : 'declare'} no version.`,
    );
  }

  return { kind: 'parsed', packages, notes };
}

// ---------------------------------------------------------------------------
// Directory.Packages.props / Directory.Build.props — central versions
// ---------------------------------------------------------------------------

/**
 * Reads central package versions and literal MSBuild properties.
 *
 * `Directory.Packages.props` supplies versions to `PackageReference` elements that omit
 * one (Central Package Management). `Directory.Build.props` is read only for its
 * `PropertyGroup` literals, which is what allows a `Version="$(SerilogVersion)"` to be
 * resolved when the property is defined as a literal — and nothing more. Imports are not
 * followed, and conditions are not evaluated.
 */
export function parseCentralVersions(text: string, path: string): CentralVersions | null {
  const parsedXml = parseXml(text);
  if (parsedXml.kind === 'rejected') {
    return null;
  }

  const versions: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const element of findElements(parsedXml.root, 'PackageVersion')) {
    const id = attribute(element, 'include');
    const version = attribute(element, 'version') ?? childElement(element, 'version')?.text ?? null;
    if (id !== null && version !== null && version.length > 0) {
      versions[idKey(id)] = version;
    }
  }

  // Literal properties only. A property whose value references another property is left
  // out rather than resolved transitively, which would mean implementing MSBuild.
  const properties: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const group of findElements(parsedXml.root, 'PropertyGroup')) {
    for (const property of group.children) {
      const value = property.text;
      if (value.length > 0 && !value.includes('$(')) {
        properties[property.name.toLowerCase()] = value;
      }
    }
  }

  return { versions, properties, path };
}

// ---------------------------------------------------------------------------
// .csproj / .vbproj / .fsproj
// ---------------------------------------------------------------------------

/**
 * Parses `PackageReference` declarations from a project file.
 *
 * Every version here is a **declaration**, never a resolution. The `resolution` assigned
 * depends on the form NuGet gave it:
 *
 * | Declared                | Means                  | `resolution`       | Queried |
 * |-------------------------|------------------------|--------------------|---------|
 * | `Version="13.0.1"`      | `[13.0.1, )`, minimum  | `declared-minimum` | no      |
 * | `Version="[13.0.1]"`    | exactly 13.0.1         | `resolved`         | **yes** |
 * | `Version="[1.0,2.0)"`   | a range                | `declared-range`   | no      |
 * | `Version="13.0.*"`      | a floating version     | `declared-range`   | no      |
 * | `Version="$(Prop)"`     | unknown statically     | `unresolved`       | no      |
 * | no version, no CPM      | unknown                | `absent`           | no      |
 */
export function parseProjectFile(
  text: string,
  path: string,
  source: DependencySource,
  central: CentralVersions | null,
): NuGetParseResult {
  const parsedXml = parseXml(text);
  if (parsedXml.kind === 'rejected') {
    return { kind: 'rejected', reason: `${path}: ${parsedXml.reason}` };
  }

  // Properties declared in this project file itself take precedence over central ones,
  // which matches MSBuild's ordering for the simple, literal cases handled here.
  const localProperties: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const group of findElements(parsedXml.root, 'PropertyGroup')) {
    for (const property of group.children) {
      const value = property.text;
      if (value.length > 0 && !value.includes('$(')) {
        localProperties[property.name.toLowerCase()] = value;
      }
    }
  }

  const frameworks = targetFrameworks(parsedXml.root);
  const packages: NormalizedPackage[] = [];
  const notes: string[] = [];

  let unresolvedProperties = 0;
  let inheritedFromCentral = 0;
  let conditional = 0;
  let withoutVersion = 0;

  for (const element of findElements(parsedXml.root, 'PackageReference')) {
    if (packages.length >= MAX_PACKAGES_PER_FILE) {
      notes.push(`${path} declares more than ${MAX_PACKAGES_PER_FILE} packages; it was truncated.`);
      break;
    }

    // `Update` declares metadata for a reference inherited from elsewhere; `Include`
    // declares the reference itself. Both name a package.
    const id = attribute(element, 'include') ?? attribute(element, 'update');
    if (id === null) {
      continue;
    }

    // A condition means this reference may or may not apply. DepGuard cannot evaluate
    // MSBuild conditions, so the package is kept — it is declared — and the uncertainty
    // is recorded rather than resolved by picking a branch (§7.4 stage 4).
    const hasCondition =
      attribute(element, 'condition') !== null ||
      findElements(parsedXml.root, 'ItemGroup').some(
        (group) => attribute(group, 'condition') !== null && group.children.includes(element),
      );
    if (hasCondition) {
      conditional += 1;
    }

    // Version as an attribute, then as a child element, then centrally.
    let declared = attribute(element, 'version') ?? childElement(element, 'version')?.text ?? null;
    let fromCentral = false;

    // A project-level VersionOverride beats the central value, which is exactly what the
    // feature is for.
    const override = attribute(element, 'versionoverride');
    if (override !== null) {
      declared = override;
    } else if (declared === null || declared.length === 0) {
      const centralVersion = central === null ? undefined : central.versions[idKey(id)];
      if (centralVersion !== undefined) {
        declared = centralVersion;
        fromCentral = true;
        inheritedFromCentral += 1;
      }
    }

    let resolution: VersionResolution;
    if (declared === null || declared.length === 0) {
      resolution = 'absent';
      withoutVersion += 1;
    } else if (declared.includes('$(')) {
      // Try the literal properties available; otherwise record it as unresolved rather
      // than guessing (§13 constraint 12).
      const substituted = substituteProperties(declared, localProperties, central?.properties);
      if (substituted === null) {
        resolution = 'unresolved';
        unresolvedProperties += 1;
      } else {
        declared = substituted;
        resolution = declaredResolution(substituted);
      }
    } else {
      resolution = declaredResolution(declared);
    }

    packages.push(
      build({
        id,
        version: declared,
        resolution,
        source,
        path,
        // A PackageReference is by definition something this project asked for.
        relationship: 'direct',
        scope: isDevelopmentOnly(element) ? 'development' : 'unknown',
        framework: frameworks.length === 1 ? (frameworks[0] ?? null) : null,
        versionFromCentral: fromCentral ? central?.path : undefined,
      }),
    );
  }

  // The honest headline for a project file: these are declarations.
  if (packages.length > 0) {
    notes.push(
      `${path} declares ${packages.length} package ${packages.length === 1 ? 'reference' : 'references'}. A NuGet version declared in a project file is a minimum, not the version restored, so these were not checked against vulnerability databases. Commit a packages.lock.json to record resolved versions.`,
    );
  }
  if (inheritedFromCentral > 0 && central !== null) {
    notes.push(
      `${inheritedFromCentral} ${inheritedFromCentral === 1 ? 'version was' : 'versions were'} inherited from ${central.path} through Central Package Management.`,
    );
  }
  if (unresolvedProperties > 0) {
    notes.push(
      `${unresolvedProperties} ${unresolvedProperties === 1 ? 'version in' : 'versions in'} ${path} ${unresolvedProperties === 1 ? 'is' : 'are'} an MSBuild property DepGuard could not resolve without building the project.`,
    );
  }
  if (conditional > 0) {
    notes.push(
      `${conditional} package ${conditional === 1 ? 'reference is' : 'references are'} conditional in ${path}. DepGuard does not evaluate MSBuild conditions, so ${conditional === 1 ? 'it is' : 'they are'} listed without determining whether ${conditional === 1 ? 'it applies' : 'they apply'}.`,
    );
  }
  if (frameworks.length > 1) {
    notes.push(
      `${path} targets ${frameworks.length} frameworks (${frameworks.join(', ')}). Package versions can differ per framework; DepGuard does not distinguish them.`,
    );
  }
  if (withoutVersion > 0) {
    notes.push(
      `${withoutVersion} package ${withoutVersion === 1 ? 'reference declares' : 'references declare'} no version in ${path} and no central version was found.`,
    );
  }

  return { kind: 'parsed', packages, notes };
}

/**
 * Classifies a declared NuGet version string.
 *
 * The distinction the whole file turns on. `[1.0.0]` is NuGet's syntax for "exactly this
 * version" and is the only single-value form that may be queried.
 */
export function declaredResolution(declared: string): VersionResolution {
  const trimmed = declared.trim();

  // Exact-version syntax: a bracketed single value with no comma.
  const exactMatch = /^\[([^,[\]]+)\]$/.exec(trimmed);
  if (exactMatch !== null) {
    const inner = exactMatch[1]?.trim() ?? '';
    return classifyVersion(inner) === 'exact' ? 'resolved' : 'declared-range';
  }

  // Interval notation, a floating version, or anything with range punctuation.
  if (/[,[\]()*]/.test(trimmed) || trimmed.length === 0) {
    return 'declared-range';
  }

  // A bare version. This is the trap: it looks exact and means "at least this".
  return classifyVersion(trimmed) === 'exact' ? 'declared-minimum' : 'declared-range';
}

/** For sources whose version really is the installed one. */
function exactness(version: string): VersionResolution {
  return classifyVersion(version) === 'exact' ? 'resolved' : 'declared-range';
}

/**
 * Substitutes `$(Property)` references from literal properties only.
 *
 * Returns null unless **every** reference in the string could be substituted — a
 * partially substituted version string is not a version, and shipping one would be worse
 * than admitting the value is unknown.
 */
function substituteProperties(
  value: string,
  local: Readonly<Record<string, string>>,
  central: Readonly<Record<string, string>> | undefined,
): string | null {
  let unresolved = false;

  const substituted = value.replace(/\$\(([A-Za-z0-9_.-]+)\)/g, (_match, name: string) => {
    const key = name.toLowerCase();
    const replacement =
      (Object.prototype.hasOwnProperty.call(local, key) ? local[key] : undefined) ??
      (central !== undefined && Object.prototype.hasOwnProperty.call(central, key)
        ? central[key]
        : undefined);
    if (replacement === undefined) {
      unresolved = true;
      return '';
    }
    return replacement;
  });

  return unresolved || substituted.includes('$(') ? null : substituted;
}

/** `PrivateAssets=all` is the standard way to say a package does not flow to consumers. */
function isDevelopmentOnly(element: XmlElement): boolean {
  const privateAssets =
    attribute(element, 'privateassets') ?? childElement(element, 'privateassets')?.text ?? null;
  return privateAssets !== null && privateAssets.toLowerCase().includes('all');
}

/** `TargetFramework` or the semicolon-separated `TargetFrameworks`. */
function targetFrameworks(root: XmlElement): readonly string[] {
  const single = findElements(root, 'TargetFramework')
    .map((element) => element.text)
    .filter((value) => value.length > 0);
  const multiple = findElements(root, 'TargetFrameworks')
    .flatMap((element) => element.text.split(';'))
    .map((value) => value.trim())
    .filter((value) => value.length > 0);

  return [...new Set([...single, ...multiple])];
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/**
 * Builds a `NormalizedPackage` for a NuGet dependency.
 *
 * `skipReason` is derived from `resolution`, not from the version string's shape, so a
 * declared minimum is reported as an unusable version even though it looks exact. The
 * report then tells the user *why* their .NET project was not fully checked, which is the
 * actionable part: commit a lockfile.
 */
function build(input: {
  readonly id: string;
  readonly version: string | null;
  readonly resolution: VersionResolution;
  readonly source: DependencySource;
  readonly path: string;
  readonly relationship: DependencyRelationship;
  readonly scope: DependencyScope;
  readonly framework: string | null;
  readonly versionFromCentral?: string | undefined;
}): NormalizedPackage {
  const skipReason: SkipReason | null =
    input.resolution === 'resolved'
      ? null
      : input.resolution === 'absent' || input.resolution === 'unresolved'
        ? 'no-version'
        : 'version-not-exact';

  return {
    key: `NuGet|${idKey(input.id)}|${input.version ?? ''}`,
    // Canonical casing preserved for display; matching is case-insensitive at OSV, which
    // was measured rather than assumed.
    name: input.id,
    purlType: 'nuget',
    ecosystem: 'NuGet',
    declaredVersion: input.version,
    versionKind: classifyVersion(input.version),
    relationship: input.relationship,
    licenseConcluded: null,
    skipReason,
    source: input.source,
    sourcePath: input.versionFromCentral ?? input.path,
    resolution: input.resolution,
    scope: input.scope,
  };
}

/**
 * Builds the coverage summary for a .NET inventory.
 *
 * `transitiveCoverage` is the honest part: `full` only when every contributing file was a
 * lockfile, and `none` when the inventory is declarations alone. §5.7 forbids claiming
 * transitive coverage that the parsed files cannot support, and a `.csproj` cannot.
 */
export function nugetCoverage(
  packages: readonly NormalizedPackage[],
  sources: readonly DependencySource[],
  notes: readonly string[],
): DependencyCoverage {
  const resolvedSources: readonly DependencySource[] = ['packages.lock.json', 'packages.config'];
  const hasLockfile = sources.includes('packages.lock.json');
  const onlyResolvedSources = sources.every((source) => resolvedSources.includes(source));

  const seen = new Set<string>();
  let duplicates = 0;
  for (const pkg of packages) {
    if (seen.has(pkg.key)) {
      duplicates += 1;
    } else {
      seen.add(pkg.key);
    }
  }

  return computeCoverage(packages, duplicates, {
    inventorySource: sources[0] ?? 'csproj',
    transitiveCoverage: hasLockfile ? (onlyResolvedSources ? 'full' : 'partial') : 'none',
    discoveryNotes: notes,
  });
}
