import type {
  DependencyCoverage,
  NormalizedPackage,
  SkipReason,
} from '../../core/models/dependency.model';
import { classifyVersion, parsePurl, toOsvEcosystem } from '../dependencies/purl';

/**
 * Parses GitHub's Dependency Graph SBOM (SPDX 2.3 JSON) into normalised packages.
 *
 * Pure and total: every malformed input yields a result describing what could be read,
 * never an exception. The document is untrusted (§9.2) and real ones are routinely
 * incomplete — Phase 0 found 12 of 30 packages in `psf/requests` carrying no version at
 * all.
 */

export type SbomParseResult =
  | {
      readonly kind: 'parsed';
      readonly packages: readonly NormalizedPackage[];
      readonly coverage: DependencyCoverage;
      readonly documentName: string | null;
      readonly spdxVersion: string | null;
    }
  | { readonly kind: 'unavailable'; readonly reason: string }
  | { readonly kind: 'invalid'; readonly reason: string };

interface SpdxPackage {
  readonly spdxId: string;
  readonly name: string;
  readonly versionInfo: string | null;
  readonly purlLocator: string | null;
  readonly licenseConcluded: string | null;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function str(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * Parses an SBOM response body.
 *
 * `null` means the SBOM endpoint returned 404, which is a normal outcome for many
 * repositories and is reported as unavailable rather than as a failure.
 */
export function parseSbom(body: unknown, maxPackages: number): SbomParseResult {
  if (body === null || body === undefined) {
    return {
      kind: 'unavailable',
      reason: 'GitHub has no dependency graph for this repository.',
    };
  }

  if (!isObject(body)) {
    return { kind: 'invalid', reason: 'The dependency graph response was not an object.' };
  }

  // GitHub wraps the document: `{ sbom: { ... } }`.
  const document = isObject(body['sbom']) ? body['sbom'] : body;

  const rawPackages = document['packages'];
  if (!Array.isArray(rawPackages)) {
    return {
      kind: 'invalid',
      reason: 'The dependency graph response contained no package list.',
    };
  }

  const spdxPackages = readPackages(rawPackages, maxPackages);
  const directIds = readDirectDependencyIds(document['relationships']);

  const packages = spdxPackages.map((spdxPackage) => normalizePackage(spdxPackage, directIds));

  // The root `DESCRIBES` element is the repository itself, not a dependency.
  const dependencies = packages.filter((pkg) => pkg.purlType !== 'github');

  return {
    kind: 'parsed',
    packages: dependencies,
    coverage: computeCoverage(dependencies),
    documentName: str(document['name']),
    spdxVersion: str(document['spdxVersion']),
  };
}

function readPackages(raw: readonly unknown[], maxPackages: number): SpdxPackage[] {
  const packages: SpdxPackage[] = [];

  for (const item of raw) {
    if (packages.length >= maxPackages) {
      break;
    }
    if (!isObject(item)) {
      continue;
    }

    const name = str(item['name']);
    if (name === null) {
      continue;
    }

    packages.push({
      spdxId: str(item['SPDXID']) ?? '',
      name,
      versionInfo: str(item['versionInfo']),
      purlLocator: readPurlLocator(item['externalRefs']),
      licenseConcluded: readLicense(item['licenseConcluded']),
    });
  }

  return packages;
}

function readPurlLocator(externalRefs: unknown): string | null {
  if (!Array.isArray(externalRefs)) {
    return null;
  }
  for (const ref of externalRefs) {
    if (isObject(ref) && ref['referenceType'] === 'purl') {
      const locator = str(ref['referenceLocator']);
      if (locator !== null) {
        return locator;
      }
    }
  }
  return null;
}

/** SPDX uses these sentinels for "no assertion"; they are absence, not a licence name. */
function readLicense(value: unknown): string | null {
  const license = str(value);
  if (license === null || license === 'NOASSERTION' || license === 'NONE') {
    return null;
  }
  return license;
}

/**
 * Collects the SPDX ids that the root element depends on directly.
 *
 * Only meaningful when the SBOM has real depth. Phase 0 measured `expressjs/express`
 * returning all 53 `DEPENDS_ON` edges from the single root element — a flat list, where
 * "direct" would be true of everything and therefore means nothing. `npm/cli`, which
 * commits a lockfile, returned 2,277 relationships across 1,208 packages.
 *
 * Returns null when the graph is flat, so classification degrades to `unknown` rather
 * than claiming every transitive dependency is direct.
 */
function readDirectDependencyIds(relationships: unknown): ReadonlySet<string> | null {
  if (!Array.isArray(relationships)) {
    return null;
  }

  const describedBy = new Set<string>();
  const dependsOn = new Map<string, Set<string>>();

  for (const item of relationships) {
    if (!isObject(item)) {
      continue;
    }
    const from = str(item['spdxElementId']);
    const to = str(item['relatedSpdxElement']);
    const type = str(item['relationshipType']);
    if (from === null || to === null || type === null) {
      continue;
    }

    if (type === 'DESCRIBES') {
      describedBy.add(to);
    } else if (type === 'DEPENDS_ON') {
      const existing = dependsOn.get(from);
      if (existing === undefined) {
        dependsOn.set(from, new Set([to]));
      } else {
        existing.add(to);
      }
    }
  }

  if (dependsOn.size === 0) {
    return null;
  }

  // A flat graph has exactly one node with outgoing edges: the root.
  if (dependsOn.size === 1) {
    return null;
  }

  const direct = new Set<string>();
  for (const rootId of describedBy) {
    for (const dependency of dependsOn.get(rootId) ?? []) {
      direct.add(dependency);
    }
  }

  return direct.size > 0 ? direct : null;
}

function normalizePackage(
  spdxPackage: SpdxPackage,
  directIds: ReadonlySet<string> | null,
): NormalizedPackage {
  const purl = spdxPackage.purlLocator === null ? null : parsePurl(spdxPackage.purlLocator);
  const ecosystem = purl === null ? null : toOsvEcosystem(purl.type);

  // Prefer the SBOM's own versionInfo; fall back to the purl's version.
  const declaredVersion = spdxPackage.versionInfo ?? purl?.version ?? null;
  const versionKind = classifyVersion(declaredVersion);

  const skipReason = determineSkipReason(purl !== null, ecosystem, versionKind);

  const name = purl?.name ?? spdxPackage.name;
  const relationship =
    directIds === null ? 'unknown' : directIds.has(spdxPackage.spdxId) ? 'direct' : 'transitive';

  return {
    key: `${ecosystem ?? purl?.type ?? 'unknown'}|${name}|${declaredVersion ?? ''}`,
    name,
    purlType: purl?.type ?? null,
    ecosystem,
    declaredVersion,
    versionKind,
    relationship,
    licenseConcluded: spdxPackage.licenseConcluded,
    skipReason,
  };
}

function determineSkipReason(
  hasPurl: boolean,
  ecosystem: string | null,
  versionKind: string,
): SkipReason | null {
  if (!hasPurl) {
    return 'no-purl';
  }
  if (ecosystem === null) {
    return 'unsupported-ecosystem';
  }
  if (versionKind === 'missing') {
    return 'no-version';
  }
  if (versionKind !== 'exact') {
    return 'version-not-exact';
  }
  return null;
}

function computeCoverage(packages: readonly NormalizedPackage[]): DependencyCoverage {
  const skippedByReason: Record<SkipReason, number> = {
    'no-purl': 0,
    'unsupported-ecosystem': 0,
    'no-version': 0,
    'version-not-exact': 0,
  };

  let queryable = 0;
  for (const pkg of packages) {
    if (pkg.skipReason === null) {
      queryable++;
    } else {
      skippedByReason[pkg.skipReason]++;
    }
  }

  const total = packages.length;

  return {
    totalPackages: total,
    queryablePackages: queryable,
    queryableRatio: total === 0 ? 0 : queryable / total,
    skippedByReason,
    // The signature of a repository with no committed lockfile, and the thing that most
    // often explains low coverage. Surfaced so the report can say so plainly.
    rangeVersionsDominant: total > 0 && skippedByReason['version-not-exact'] > total / 2,
  };
}

/** The packages that may be sent to OSV. Nothing else ever is (ADR-0002). */
export function queryablePackages(
  packages: readonly NormalizedPackage[],
): readonly NormalizedPackage[] {
  return packages.filter((pkg) => pkg.skipReason === null && pkg.ecosystem !== null);
}
