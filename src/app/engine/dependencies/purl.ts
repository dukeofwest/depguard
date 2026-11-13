import type { OsvEcosystem, VersionKind } from '../../core/models/dependency.model';
import { PURL_TYPE_TO_ECOSYSTEM } from './ecosystems';

/**
 * Package URL parsing and version classification.
 *
 * Pure, deterministic, no I/O. The version classifier here is the single most
 * consequential function in DepGuard: it decides which packages may be sent to OSV, and
 * ADR-0002 exists because getting it wrong produces confident, wrong vulnerability
 * findings rather than visible failures.
 */

export interface ParsedPurl {
  /** purl type as written, lowercased, e.g. `npm`, `githubactions`. */
  readonly type: string;
  /** Decoded package name, including any namespace, e.g. `@npmcli/git`. */
  readonly name: string;
  /** Decoded version, or null when the purl carries none. */
  readonly version: string | null;
}

/**
 * Parses a Package URL.
 *
 * GitHub percent-encodes these: `pkg:npm/%40npmcli/git@%5E8.0.0` is `@npmcli/git` at
 * `^8.0.0`. Decoding is therefore mandatory, not cosmetic — without it every scoped npm
 * package would be queried under the wrong name and silently return no vulnerabilities.
 */
export function parsePurl(locator: string): ParsedPurl | null {
  if (typeof locator !== 'string' || !locator.startsWith('pkg:')) {
    return null;
  }

  // Qualifiers (`?arch=x`) and subpaths (`#sub`) carry no information DepGuard uses.
  const withoutQualifiers = locator.split('?')[0]?.split('#')[0] ?? '';
  const body = withoutQualifiers.slice('pkg:'.length);
  if (body.length === 0) {
    return null;
  }

  // The version follows the LAST `@`, because scoped npm names begin with one.
  const versionSeparator = body.lastIndexOf('@');
  const hasVersion = versionSeparator > 0;
  const namePart = hasVersion ? body.slice(0, versionSeparator) : body;
  const versionPart = hasVersion ? body.slice(versionSeparator + 1) : null;

  const typeSeparator = namePart.indexOf('/');
  if (typeSeparator <= 0) {
    return null;
  }

  const type = namePart.slice(0, typeSeparator).toLowerCase();
  const rawName = namePart.slice(typeSeparator + 1);
  if (rawName.length === 0) {
    return null;
  }

  const name = safeDecodePath(rawName);
  const version = versionPart === null ? null : safeDecode(versionPart);

  return { type, name, version: version !== null && version.length > 0 ? version : null };
}

/** Decodes a path, segment by segment, preserving the `/` between namespace and name. */
function safeDecodePath(value: string): string {
  return value
    .split('/')
    .map((segment) => safeDecode(segment) ?? segment)
    .join('/');
}

/** Percent-decodes, returning the original on malformed input rather than throwing. */
function safeDecode(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Maps a purl type to an OSV ecosystem, or null when it has no OSV equivalent. */
export function toOsvEcosystem(purlType: string): OsvEcosystem | null {
  return PURL_TYPE_TO_ECOSYSTEM[purlType.toLowerCase()] ?? null;
}

/**
 * Characters that mean "this is a constraint, not a version".
 *
 * Covers npm/cargo (`^`, `~`, `*`, `||`, `>=`), Python (`>=`, `!=`, `,`), Maven and NuGet
 * interval notation (`[1.0,2.0)`), and whitespace-separated compound ranges.
 */
const RANGE_CHARACTERS = /[\^~<>=*|,[\]()\s!]/;

/**
 * A single, concrete version.
 *
 * Permits an optional leading `v` (Go uses `v1.2.3`), dotted numeric components, and a
 * semver prerelease or build suffix. Everything else is rejected.
 */
const EXACT_VERSION = /^[vV]?\d+(\.\d+)*([-+][0-9A-Za-z.-]+)?$/;

/**
 * Classifies a declared version string.
 *
 * Deliberately conservative: anything not provably a single concrete version is treated
 * as unusable. Phase 0 demonstrated why — OSV does not reject a range supplied where a
 * version belongs. Querying `lodash@^4.17.15` returned 4 advisories where the exact
 * `4.17.15` returned 5: a different, wrong, and entirely plausible-looking answer.
 *
 * A false `range` costs coverage, which is measured and shown to the user. A false
 * `exact` costs correctness, silently. The asymmetry decides the default.
 */
export function classifyVersion(version: string | null | undefined): VersionKind {
  if (typeof version !== 'string') {
    return 'missing';
  }
  const trimmed = version.trim();
  if (trimmed.length === 0) {
    return 'missing';
  }
  if (RANGE_CHARACTERS.test(trimmed)) {
    return 'range';
  }
  return EXACT_VERSION.test(trimmed) ? 'exact' : 'range';
}

/**
 * Normalises an exact version for querying.
 *
 * Only the Go ecosystem's `v` prefix is handled, because OSV expects Go versions with it
 * and other ecosystems never use it. No other rewriting happens: altering a version
 * before matching would risk matching the wrong one.
 */
export function normalizeVersionForQuery(ecosystem: OsvEcosystem, version: string): string {
  const trimmed = version.trim();
  if (ecosystem === 'Go') {
    return trimmed.startsWith('v') ? trimmed : `v${trimmed}`;
  }
  return trimmed.replace(/^[vV](?=\d)/, '');
}
