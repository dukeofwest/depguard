import { Injectable, inject } from '@angular/core';
import { Observable, catchError, forkJoin, map, of, switchMap } from 'rxjs';

import { GithubApiService } from '../api/github-api.service';
import {
  INSPECTED_FILE_PATHS,
  INSPECTED_WORKFLOW_LIMIT,
  isWorkflowFile,
} from '../config/api.config';
import { isAppError, type AppErrorKind } from '../models/api-error.model';
import type {
  RepositoryRef,
  RepositorySnapshot,
  RepositoryTree,
  SourceId,
  SourceState,
  SourceUnavailableReason,
} from '../models/repository.model';

/**
 * Assembles a complete repository snapshot.
 *
 * Budget-aware by construction. Phase 0 established that anonymous GitHub access allows
 * 60 requests per hour per IP, so this service spends a fixed, known number of them:
 *
 *   1 metadata (sequential — everything else needs the default branch)
 * + 1 tree + 1 workflows + 1 release + 1 contributors + 1 languages + 1 commit activity
 * + 1 SBOM
 *   = 8 quota-consuming requests, plus file contents from raw.githubusercontent.com,
 *     which cost nothing.
 *
 * Only repository metadata is required. Every other source degrades to `null`, because a
 * partial analysis that says so is far more useful than a failed one (§6.3). The engine
 * then reports reduced coverage rather than inventing values.
 */
@Injectable({ providedIn: 'root' })
export class RepositoryDataService {
  private readonly github = inject(GithubApiService);

  /**
   * Fetches everything needed to analyse a repository.
   *
   * Cancellable: unsubscribing aborts every in-flight request, which is what makes
   * starting a new scan safe (§10.4).
   */
  loadSnapshot(ref: RepositoryRef): Observable<RepositorySnapshot> {
    // Metadata first and alone: it supplies the default branch that the tree and raw file
    // requests depend on, and it is the one request whose failure must fail the scan.
    return this.github.getRepository(ref).pipe(
      switchMap((metadata) => {
        const branch = metadata.defaultBranch;

        // The tree is fetched before the rest, not alongside it, because the workflow
        // files whose contents the CodeQL check needs are discovered *from* the tree
        // (P1-10). This costs no extra request — the tree was always fetched — only an
        // extra round trip.
        return this.traced(this.github.getTree(ref, branch))
          .pipe(
            switchMap((tree) =>
              forkJoin({
                tree: of(tree),
                workflows: this.traced(this.github.getWorkflows(ref)),
                latestRelease: this.traced(this.github.getLatestRelease(ref)),
                contributorCount: this.traced(this.github.getContributorCount(ref)),
                languages: this.traced(this.github.getLanguages(ref)),
                weeklyCommits: this.traced(this.github.getWeeklyCommits(ref)),
                fileContents: this.loadInspectedFiles(ref, branch, tree.value),
              }),
            ),
          )
          .pipe(
            map((parts): RepositorySnapshot => {
              const commits = parts.weeklyCommits.value;

              const sourceStates: Partial<Record<SourceId, SourceState>> = {};
              const record = (id: SourceId, outcome: Traced<unknown>): void => {
                if (outcome.state !== null) {
                  sourceStates[id] = outcome.state;
                }
              };

              record('tree', parts.tree);
              record('workflows', parts.workflows);
              record('latest-release', parts.latestRelease);
              record('contributors', parts.contributorCount);
              record('languages', parts.languages);

              // Commit activity carries its own three-way state, so its absence is
              // described as pending or unavailable rather than inferred from an error.
              if (parts.weeklyCommits.state !== null) {
                sourceStates['commit-activity'] = parts.weeklyCommits.state;
              } else if (commits !== null && commits.kind !== 'available') {
                sourceStates['commit-activity'] =
                  commits.kind === 'pending'
                    ? {
                        kind: 'unavailable',
                        reason: 'pending',
                        detail:
                          'GitHub is still computing commit statistics for this repository, which it does the first time they are requested.',
                      }
                    : {
                        kind: 'unavailable',
                        reason: 'error',
                        detail: 'GitHub did not return usable commit statistics.',
                      };
              }

              return {
                metadata,
                tree: parts.tree.value,
                workflows: parts.workflows.value,
                latestRelease: parts.latestRelease.value,
                contributorCount: parts.contributorCount.value,
                languages: parts.languages.value,
                weeklyCommits:
                  commits !== null && commits.kind === 'available' ? commits.weeks : null,
                fileContents: parts.fileContents,
                sourceStates,
                // Captured once, here, so the engine never reads the clock and stays
                // deterministic (§6.5).
                retrievedAt: new Date().toISOString(),
              };
            }),
          );
      }),
    );
  }

  /**
   * The SBOM, separately: it is large and its absence is normal (2 of 6 repos in testing).
   *
   * Returns the reason alongside the value. The previous version flattened every
   * transport failure to `null`, which the SBOM parser then rendered as "GitHub has no
   * dependency graph for this repository" — asserting a fact about GitHub's state from a
   * rate limit, a 403 or a dropped connection (P1-2).
   */
  loadSbom(ref: RepositoryRef): Observable<SbomRetrieval> {
    return this.traced(this.github.getSbom(ref)).pipe(
      map((outcome) => ({
        body: outcome.value,
        // `getSbom` maps 404 to null without erroring, because a repository with no
        // dependency graph is a normal outcome rather than a failure.
        state:
          outcome.state ??
          (outcome.value === null
            ? ({
                kind: 'unavailable',
                reason: 'not-found',
                detail: 'GitHub has no dependency graph for this repository.',
              } as const)
            : ({ kind: 'available' } as const)),
      })),
    );
  }

  /**
   * Fetches the allowlisted files whose contents are needed for validation.
   *
   * These come from raw.githubusercontent.com and cost no API quota, which is what makes
   * it affordable to check that a Dependabot config really contains an update
   * configuration rather than merely existing (§5.3).
   */
  private loadInspectedFiles(
    ref: RepositoryRef,
    branch: string,
    tree: RepositoryTree | null,
  ): Observable<Readonly<Record<string, string>>> {
    // Workflow files, discovered from the tree rather than guessed. Needed because a
    // workflow's *name* proves nothing about what it runs: `codeql.yml` could contain
    // anything, and the CodeQL check previously claimed to verify content it never read
    // (P1-10).
    //
    // Same boundary as dependency discovery: the path comes from the tree, the basename
    // must match a compiled pattern, and the count is bounded.
    const workflowPaths = (tree?.entries ?? [])
      .filter((entry) => entry.type === 'blob' && isWorkflowFile(entry.path))
      .map((entry) => entry.path)
      .sort()
      .slice(0, INSPECTED_WORKFLOW_LIMIT);

    const requests = [...INSPECTED_FILE_PATHS, ...workflowPaths].map((path) =>
      this.optional(this.github.getRawFile(ref, branch, path)).pipe(
        map((content) => ({ path, content })),
      ),
    );

    if (requests.length === 0) {
      return of({});
    }

    return forkJoin(requests).pipe(
      map((results) => {
        const contents: Record<string, string> = {};
        for (const { path, content } of results) {
          if (content !== null) {
            contents[path] = content;
          }
        }
        return contents;
      }),
    );
  }

  /**
   * Degrades a failed optional source to `null`.
   *
   * Deliberately swallows the error: these sources are supplementary, and one flaky
   * endpoint must not discard an otherwise complete analysis. The resulting `null` is
   * what later drives the `Unknown` status and reduced coverage, so the loss is reported
   * to the user rather than hidden.
   */
  private optional<T>(source: Observable<T>): Observable<T | null> {
    return source.pipe(catchError(() => of(null)));
  }

  /**
   * Like `optional`, but keeps **why** the source failed.
   *
   * The previous behaviour discarded the error entirely, which is how a rate limit came
   * to be reported as "GitHub has no dependency graph for this repository" — a positive
   * claim about GitHub's state inferred from a swallowed exception (P1-2).
   */
  private traced<T>(source: Observable<T>): Observable<Traced<T>> {
    return source.pipe(
      map((value): Traced<T> => ({ value, state: null })),
      catchError((error: unknown) => of({ value: null, state: describeFailure(error) })),
    );
  }
}

/** The dependency graph retrieval: the document, and why it is absent when it is. */
export interface SbomRetrieval {
  readonly body: unknown;
  readonly state: SourceState;
}

/** An optional source's value, plus the reason it is absent when it is. */
interface Traced<T> {
  readonly value: T | null;
  /** Null when the request succeeded — including when it legitimately returned null. */
  readonly state: SourceState | null;
}

/** Maps a typed `AppError` onto the reason vocabulary the report uses. */
function describeFailure(error: unknown): SourceState {
  const reason = reasonFor(isAppError(error) ? error.kind : null);
  return {
    kind: 'unavailable',
    reason,
    detail: isAppError(error) ? error.message : 'This information could not be retrieved.',
  };
}

function reasonFor(kind: AppErrorKind | null): SourceUnavailableReason {
  switch (kind) {
    case 'repository-not-found':
      return 'not-found';
    case 'repository-inaccessible':
      return 'access-denied';
    case 'rate-limited':
      return 'rate-limited';
    case 'network':
      return 'network';
    case 'cancelled':
      return 'cancelled';
    case 'response-too-large':
      return 'limit-exceeded';
    case 'sbom-invalid':
      return 'invalid';
    default:
      return 'error';
  }
}
