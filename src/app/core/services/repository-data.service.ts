import { Injectable, inject } from '@angular/core';
import { Observable, catchError, forkJoin, map, of, switchMap } from 'rxjs';

import { GithubApiService } from '../api/github-api.service';
import { INSPECTED_FILE_PATHS } from '../config/api.config';
import type { RepositoryRef, RepositorySnapshot } from '../models/repository.model';

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

        return forkJoin({
          tree: this.optional(this.github.getTree(ref, branch)),
          workflows: this.optional(this.github.getWorkflows(ref)),
          latestRelease: this.optional(this.github.getLatestRelease(ref)),
          contributorCount: this.optional(this.github.getContributorCount(ref)),
          languages: this.optional(this.github.getLanguages(ref)),
          weeklyCommits: this.optional(this.github.getWeeklyCommits(ref)),
          fileContents: this.loadInspectedFiles(ref, branch),
        }).pipe(
          map((parts): RepositorySnapshot => ({
            metadata,
            tree: parts.tree,
            workflows: parts.workflows,
            latestRelease: parts.latestRelease,
            contributorCount: parts.contributorCount,
            languages: parts.languages,
            weeklyCommits: parts.weeklyCommits,
            fileContents: parts.fileContents,
            // Captured once, here, so the engine never reads the clock and stays
            // deterministic (§6.5).
            retrievedAt: new Date().toISOString(),
          })),
        );
      }),
    );
  }

  /** The SBOM, separately: it is large and its absence is normal (2 of 6 repos in testing). */
  loadSbom(ref: RepositoryRef): Observable<unknown | null> {
    return this.optional(this.github.getSbom(ref));
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
  ): Observable<Readonly<Record<string, string>>> {
    const requests = INSPECTED_FILE_PATHS.map((path) =>
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
}
