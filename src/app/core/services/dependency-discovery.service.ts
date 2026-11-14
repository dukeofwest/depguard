import { Injectable, inject } from '@angular/core';
import { EMPTY, Observable, concatMap, defer, from, map, of, reduce } from 'rxjs';

import { GithubApiService } from '../api/github-api.service';
import {
  DISCOVERY_LIMITS,
  RESPONSE_LIMITS,
  isDiscoverableManifest,
  isProjectFile,
} from '../config/api.config';
import { DEFAULT_JSON_BOUNDS, parseBoundedJson } from '../api/response-guard';
import type {
  DependencyCoverage,
  DependencySource,
  NormalizedPackage,
} from '../models/dependency.model';
import type { RepositoryRef, RepositorySnapshot } from '../models/repository.model';
import { parseNpmLockfile } from '../../engine/dependencies/npm-lockfile';
import {
  parseCentralVersions,
  parseNuGetLockfile,
  parsePackagesConfig,
  parseProjectFile,
  type CentralVersions,
} from '../../engine/dependencies/nuget';
import { mergeInventories } from '../../engine/dependencies/inventory';

/**
 * Dependency discovery from repository manifests.
 *
 * The fallback for when GitHub has no dependency graph. It spends **no GitHub API quota**:
 * candidate paths come from the recursive tree already fetched for the security and
 * engineering checks, and file contents come from `raw.githubusercontent.com`, which is
 * CORS-open and outside the quota (measured in Phase 0 and re-confirmed in the November
 * 2026 audit).
 *
 * All I/O lives here. The parsing and merging it calls are pure engine functions, so the
 * engine stays free of HTTP and the clock (§4.4).
 */

/**
 * The outcome of a discovery attempt.
 *
 * Deliberately not reducible to "some packages or none": §4.5 requires that a parse
 * failure, an unsupported format, a truncated tree and a genuine absence of manifests are
 * all distinguishable, because they call for different things from the reader.
 */
export type DiscoveryResult =
  | {
      readonly kind: 'discovered';
      readonly packages: readonly NormalizedPackage[];
      readonly coverage: DependencyCoverage;
      /** Repository paths that produced this inventory. */
      readonly sources: readonly string[];
      /** True when a limit was reached or some file failed, so more may exist. */
      readonly partial: boolean;
      readonly notes: readonly string[];
    }
  | {
      /** Manifests were found but none could be parsed. */
      readonly kind: 'parse-failed';
      readonly reason: string;
      readonly notes: readonly string[];
    }
  | {
      /** Manifests were found in a format this release does not support. */
      readonly kind: 'unsupported';
      readonly reason: string;
      readonly notes: readonly string[];
    }
  | {
      /** No supported manifest exists in the tree, and the tree can be trusted. */
      readonly kind: 'no-manifest';
      readonly reason: string;
    }
  | {
      /** The tree was unreadable or truncated, so absence proves nothing. */
      readonly kind: 'cannot-determine';
      readonly reason: string;
    };

@Injectable({ providedIn: 'root' })
export class DependencyDiscoveryService {
  private readonly github = inject(GithubApiService);

  /**
   * Discovers dependencies from the repository's own manifests.
   *
   * Cancellable by unsubscribing, like every other request path: the fetches run
   * sequentially through `concatMap`, so abandoning the scan abandons the queue rather
   * than leaving requests in flight.
   */
  discover(ref: RepositoryRef, snapshot: RepositorySnapshot): Observable<DiscoveryResult> {
    const tree = snapshot.tree;

    if (tree === null) {
      return of({
        kind: 'cannot-determine',
        reason:
          'The repository file list could not be read, so DepGuard could not look for a lockfile.',
      });
    }

    const candidates = tree.entries
      .filter((entry) => entry.type === 'blob' && isDiscoverableManifest(entry.path))
      // Shallowest first: a root lockfile is the most representative single file in a
      // monorepo, so if the file limit truncates the set it keeps the useful ones.
      .sort((a, b) => depthOf(a.path) - depthOf(b.path) || a.path.localeCompare(b.path));

    if (candidates.length === 0) {
      // A truncated tree cannot support a claim of absence: `torvalds/linux` returns
      // 71,474 entries with `truncated: true`, and a lockfile could be among the ones
      // GitHub did not list.
      if (tree.truncated) {
        return of({
          kind: 'cannot-determine',
          reason:
            'GitHub returned a truncated file list for this repository, so DepGuard cannot tell whether a lockfile is present.',
        });
      }
      return of({
        kind: 'no-manifest',
        reason:
          'No supported dependency lockfile was found in this repository. DepGuard reads package-lock.json and npm-shrinkwrap.json.',
      });
    }

    // Project files are capped separately and read last, because Central Package
    // Management means a `.csproj` cannot be interpreted until
    // `Directory.Packages.props` has been read. Ordering the fetches this way avoids a
    // second pass.
    const projectFiles = candidates.filter((entry) => isProjectFile(entry.path));
    const others = candidates.filter((entry) => !isProjectFile(entry.path));

    const selectedOthers = others.slice(0, DISCOVERY_LIMITS.maxManifestFiles);
    const selectedProjects = projectFiles.slice(0, DISCOVERY_LIMITS.maxProjectFiles);
    const omitted =
      others.length - selectedOthers.length + (projectFiles.length - selectedProjects.length);

    const ordered = [...selectedOthers, ...selectedProjects];

    // `defer`, because the byte budget below is mutable state that belongs to one
    // subscription. Built eagerly it would be shared between subscriptions, and a second
    // scan of the same repository would start with the first one's budget already spent.
    return defer(() => {
      const budget: DiscoveryBudget = {
        consumed: 0,
        skipped: [],
        stoppedByBudget: false,
      };

      return from(ordered).pipe(
        // Sequential, so the props files are parsed before the project files that inherit
        // from them, so cancellation abandons a queue rather than many open requests, and
        // so each fetch sees what the ones before it have already spent.
        concatMap((entry) =>
          this.fetchText(ref, snapshot.metadata.defaultBranch, entry.path, budget),
        ),
        reduce((accumulated: FileOutcome[], outcome: FileOutcome) => {
          accumulated.push(outcome);
          return accumulated;
        }, []),
        map((outcomes) => this.combine(outcomes, omitted, tree.truncated, budget)),
      );
    });
  }

  /**
   * Fetches one manifest's text.
   *
   * Parsing happens later, in one pure pass over every file, because Central Package
   * Management means a `.csproj` cannot be interpreted until `Directory.Packages.props`
   * has been read. Keeping the fetch and the parse apart also keeps all the parsing in
   * the engine, where it is pure and testable without HTTP.
   */
  private fetchText(
    ref: RepositoryRef,
    branch: string,
    path: string,
    budget: DiscoveryBudget,
  ): Observable<FileOutcome> {
    const remaining = DISCOVERY_LIMITS.maxManifestBytes - budget.consumed;

    if (remaining <= 0) {
      // No allowance left, so no request is issued at all. Recorded rather than
      // discarded: the inventory that results is incomplete and has to say so.
      budget.skipped.push(path);
      budget.stoppedByBudget = true;
      return EMPTY;
    }

    // Two limits, and the smaller governs: the standing per-file cap, and whatever is
    // left of the aggregate. Passing the smaller one down is what makes the aggregate a
    // real bound on bytes received rather than a total checked afterwards.
    const limit = Math.min(remaining, RESPONSE_LIMITS.maxFileContentBytes);
    const budgetBound = limit < RESPONSE_LIMITS.maxFileContentBytes;

    return new Observable<FileOutcome>((subscriber) => {
      const subscription = this.github.getBoundedRawFile(ref, branch, path, limit).subscribe({
        next: (outcome) => {
          // Charged first, and for every outcome: a response whose body turns out to be
          // malformed, unsupported or over-limit still cost the bytes it cost, and must
          // not vanish from the accounting just because it produced no packages.
          budget.consumed += outcome.consumed;

          if (outcome.kind === 'missing') {
            // Listed in the tree but not served: a branch race, or a path the raw host
            // declines. Reported, not treated as an empty manifest.
            subscriber.next({
              kind: 'failed',
              path,
              reason: `${path} is listed in the repository but its contents could not be retrieved.`,
            });
          } else if (outcome.kind === 'over-limit') {
            if (budgetBound) {
              // The aggregate ran out part-way through this file, not the per-file cap.
              // Saying which bound stopped it is the difference between "this repository
              // has an enormous lockfile" and "this scan ran out of budget".
              budget.stoppedByBudget = true;
              subscriber.next({
                kind: 'failed',
                path,
                reason: `${path} was not read: the ${Math.round(DISCOVERY_LIMITS.maxManifestBytes / 1024 / 1024)} MB a single scan will download for dependency files was already spent.`,
              });
            } else {
              subscriber.next({
                kind: 'failed',
                path,
                reason: `${path} is larger than the ${Math.round(RESPONSE_LIMITS.maxFileContentBytes / 1024)} KB DepGuard will read, so it was not parsed.`,
              });
            }
          } else {
            subscriber.next({ kind: 'fetched', path, text: outcome.text });
          }
          subscriber.complete();
        },
        error: () => {
          subscriber.next({
            kind: 'failed',
            path,
            reason: `${path} could not be retrieved from GitHub.`,
          });
          subscriber.complete();
        },
      });

      return () => subscription.unsubscribe();
    });
  }

  /**
   * Parses every fetched file, in the order that lets later ones use earlier ones.
   *
   * Pure dispatch: JSON files go through the shared bounded parser first, XML files
   * through the engine's bounded reader. Central package versions are accumulated as the
   * props files are encountered, which is why they are fetched before the project files.
   */
  private parseAll(outcomes: readonly FileOutcome[]): readonly ParseOutcome[] {
    const results: ParseOutcome[] = [];

    // Accumulated as the props files are encountered, and handed to every project file
    // parsed afterwards. Plain records rather than a nullable object, because "no props
    // file seen yet" and "a props file with nothing in it" behave identically here.
    const centralVersions: Record<string, string> = {};
    const centralProperties: Record<string, string> = {};
    let centralPath: string | null = null;

    for (const outcome of outcomes) {
      if (outcome.kind !== 'fetched') {
        results.push(outcome);
        continue;
      }

      const { path, text } = outcome;
      const basename = (path.split('/').pop() ?? '').toLowerCase();

      // ---- Central Package Management and shared properties ----
      if (basename === 'directory.packages.props' || basename === 'directory.build.props') {
        const parsed = parseCentralVersions(text, path);
        if (parsed === null) {
          results.push({
            kind: 'failed',
            path,
            reason: `${path} could not be read as XML, so central package versions were not applied.`,
          });
          continue;
        }
        // Merged rather than replaced: a repository can have both files, and
        // Directory.Build.props contributes properties while Directory.Packages.props
        // contributes versions.
        Object.assign(centralVersions, parsed.versions);
        Object.assign(centralProperties, parsed.properties);
        // Directory.Packages.props is the file that owns central versions, so it names
        // the source in the report even when Directory.Build.props also contributed.
        if (basename === 'directory.packages.props' || centralPath === null) {
          centralPath = path;
        }
        // Props files declare versions, not dependencies. A PackageVersion entry with no
        // corresponding PackageReference is not a dependency of anything.
        results.push({ kind: 'contextual', path, bytes: text.length });
        continue;
      }

      // ---- npm lockfiles ----
      if (basename === 'package-lock.json' || basename === 'npm-shrinkwrap.json') {
        const json = this.readJson(text, path);
        if (json.kind === 'failed') {
          results.push(json);
          continue;
        }
        const result = parseNpmLockfile(
          json.value,
          basename === 'npm-shrinkwrap.json' ? 'npm-shrinkwrap.json' : 'package-lock.json',
          path,
        );
        results.push(
          result.kind === 'parsed'
            ? {
                kind: 'parsed',
                path,
                bytes: text.length,
                packages: result.packages,
                notes: result.notes,
                source:
                  basename === 'npm-shrinkwrap.json' ? 'npm-shrinkwrap.json' : 'package-lock.json',
                transitive: result.coverage.transitiveCoverage,
              }
            : {
                kind: result.kind === 'unsupported' ? 'unsupported' : 'failed',
                path,
                reason: result.reason,
              },
        );
        continue;
      }

      // ---- NuGet lockfile ----
      if (basename === 'packages.lock.json') {
        const json = this.readJson(text, path);
        if (json.kind === 'failed') {
          results.push(json);
          continue;
        }
        const result = parseNuGetLockfile(json.value, path);
        results.push(
          result.kind === 'parsed'
            ? {
                kind: 'parsed',
                path,
                bytes: text.length,
                packages: result.packages,
                notes: result.notes,
                source: 'packages.lock.json',
                transitive: 'full',
              }
            : { kind: 'failed', path, reason: result.reason },
        );
        continue;
      }

      // ---- Legacy NuGet ----
      if (basename === 'packages.config') {
        const result = parsePackagesConfig(text, path);
        results.push(
          result.kind === 'parsed'
            ? {
                kind: 'parsed',
                path,
                bytes: text.length,
                packages: result.packages,
                notes: result.notes,
                source: 'packages.config',
                // Flat file: it records installed versions but expresses no graph.
                transitive: 'partial',
              }
            : { kind: 'failed', path, reason: result.reason },
        );
        continue;
      }

      // ---- .NET project files ----
      const source = projectSourceFor(basename);
      if (source !== null) {
        const central: CentralVersions | null =
          centralPath === null
            ? null
            : { versions: centralVersions, properties: centralProperties, path: centralPath };
        const result = parseProjectFile(text, path, source, central);
        results.push(
          result.kind === 'parsed'
            ? {
                kind: 'parsed',
                path,
                bytes: text.length,
                packages: result.packages,
                notes: result.notes,
                source,
                // Declarations only. §5.7 forbids claiming transitive coverage a project
                // file cannot support.
                transitive: 'none',
              }
            : { kind: 'failed', path, reason: result.reason },
        );
        continue;
      }

      results.push({
        kind: 'unsupported',
        path,
        reason: `${path} is not a format DepGuard reads.`,
      });
    }

    return results;
  }

  /** Applies the shared JSON bounds before any parser sees the value. */
  private readJson(
    text: string,
    path: string,
  ): { kind: 'ok'; value: unknown } | { kind: 'failed'; path: string; reason: string } {
    const parsed = parseBoundedJson(text, DEFAULT_JSON_BOUNDS);
    if (parsed.ok) {
      return { kind: 'ok', value: parsed.value };
    }
    return {
      kind: 'failed',
      path,
      reason:
        parsed.kind === 'malformed'
          ? `${path} is not valid JSON, so it could not be read.`
          : `${path} was rejected before parsing: ${parsed.reason}`,
    };
  }

  /** Combines per-file outcomes into one inventory, or into an accurate failure. */
  private combine(
    fetched: readonly FileOutcome[],
    omittedFiles: number,
    treeTruncated: boolean,
    budget: DiscoveryBudget,
  ): DiscoveryResult {
    const outcomes = this.parseAll(fetched);
    const notes: string[] = [];
    const parsed = outcomes.filter((o): o is ParsedOutcome => o.kind === 'parsed');

    if (budget.stoppedByBudget) {
      const unread = budget.skipped.length;
      notes.push(
        `Dependency discovery stopped after downloading ${Math.round(budget.consumed / 1024)} KB, the ${Math.round(DISCOVERY_LIMITS.maxManifestBytes / 1024 / 1024)} MB a single scan will spend on dependency files.` +
          (unread === 0
            ? ' The inventory is therefore incomplete.'
            : ` ${unread} further file${unread === 1 ? '' : 's'} ${unread === 1 ? 'was' : 'were'} not requested, so the inventory is incomplete.`),
      );
    }

    for (const outcome of outcomes) {
      if (outcome.kind === 'failed' || outcome.kind === 'unsupported') {
        notes.push(outcome.reason);
      }
    }

    if (omittedFiles > 0) {
      notes.push(
        `${omittedFiles} further lockfile${omittedFiles === 1 ? '' : 's'} ${omittedFiles === 1 ? 'was' : 'were'} found but not read, to bound the work one scan performs. The inventory is therefore incomplete.`,
      );
    }
    if (treeTruncated) {
      notes.push(
        'GitHub returned a truncated file list, so there may be lockfiles DepGuard never saw.',
      );
    }

    if (parsed.length === 0) {
      const unsupported = outcomes.filter((o) => o.kind === 'unsupported');
      const failed = outcomes.filter((o) => o.kind === 'failed');

      // Nothing was parsed and the budget is why. This must not fall through to any of
      // the branches below: "no manifest exists" and "DepGuard stopped looking" are
      // different claims, and only one of them is true here.
      if (budget.stoppedByBudget) {
        return {
          kind: 'cannot-determine',
          reason: `Dependency discovery reached the ${Math.round(DISCOVERY_LIMITS.maxManifestBytes / 1024 / 1024)} MB a single scan will download for dependency files before any inventory could be read, so DepGuard cannot say what this repository depends on.`,
        };
      }

      // A props file alone is not an inventory: it declares versions for references that
      // are themselves declared elsewhere. Saying so beats reporting a parse failure for
      // a file that parsed perfectly well.
      if (failed.length === 0 && unsupported.length === 0) {
        return {
          kind: 'no-manifest',
          reason:
            'The only dependency files found declare versions for packages referenced elsewhere, and no project or lockfile referencing them could be read.',
        };
      }

      if (unsupported.length > 0 && failed.length === 0) {
        return {
          kind: 'unsupported',
          reason: unsupported.map((o) => o.reason).join(' '),
          notes,
        };
      }

      const only = failed[0];
      return {
        kind: 'parse-failed',
        reason:
          failed.length === 1 && only !== undefined
            ? only.reason
            : `None of the ${failed.length} dependency files found could be read.`,
        notes,
      };
    }

    for (const outcome of parsed) {
      notes.push(...outcome.notes);
    }

    const merged = mergeInventories(
      parsed.map((outcome) => ({
        packages: outcome.packages,
        source: outcome.source,
        transitiveCoverage: outcome.transitive,
      })),
      notes,
    );

    const partial =
      omittedFiles > 0 ||
      treeTruncated ||
      outcomes.some((outcome) => outcome.kind === 'failed' || outcome.kind === 'unsupported') ||
      budget.stoppedByBudget;

    return {
      kind: 'discovered',
      packages: merged.packages,
      coverage: merged.coverage,
      sources: parsed.map((outcome) => outcome.path),
      partial,
      notes,
    };
  }
}

/** The `DependencySource` for a .NET project file extension, or null. */
function projectSourceFor(basename: string): DependencySource | null {
  if (basename.endsWith('.csproj')) return 'csproj';
  if (basename.endsWith('.vbproj')) return 'vbproj';
  if (basename.endsWith('.fsproj')) return 'fsproj';
  return null;
}

/** How deep a repository path is, for ordering candidates root-first. */
function depthOf(path: string): number {
  return path.split('/').length;
}

/**
 * One subscription's share of the aggregate download allowance.
 *
 * Mutable, and deliberately so: the fetches run sequentially, so each one needs to see
 * what the ones before it actually spent. It lives inside a `defer`, so it is per
 * subscription rather than per service.
 *
 * `consumed` counts **bytes received**, including those spent on responses that turned
 * out to be malformed, unsupported, oversized or empty. Counting only what parsed
 * successfully is what made the previous limit ineffective: a repository could spend the
 * whole allowance on files that contributed nothing and never be charged for any of it.
 */
interface DiscoveryBudget {
  consumed: number;
  /** Paths that were never requested, because the allowance was already gone. */
  readonly skipped: string[];
  /** True once the allowance has refused a request or cut one short. */
  stoppedByBudget: boolean;
}

/** A file whose text was retrieved, or the reason it was not. */
type FileOutcome =
  | { readonly kind: 'fetched'; readonly path: string; readonly text: string }
  | { readonly kind: 'failed'; readonly path: string; readonly reason: string };

interface ParsedOutcome {
  readonly kind: 'parsed';
  readonly path: string;
  readonly bytes: number;
  readonly packages: readonly NormalizedPackage[];
  readonly notes: readonly string[];
  readonly source: DependencySource;
  readonly transitive: DependencyCoverage['transitiveCoverage'];
}

/** The result of parsing one fetched file. */
type ParseOutcome =
  | ParsedOutcome
  /** Parsed successfully but contributes context rather than dependencies. */
  | { readonly kind: 'contextual'; readonly path: string; readonly bytes: number }
  | { readonly kind: 'failed'; readonly path: string; readonly reason: string }
  | { readonly kind: 'unsupported'; readonly path: string; readonly reason: string };
