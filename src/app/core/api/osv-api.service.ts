import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, catchError, concatMap, from, map, mergeMap, of, reduce, timeout } from 'rxjs';

import { OSV_API_ORIGIN, OSV_LIMITS, RESPONSE_LIMITS } from '../config/api.config';
import type { NormalizedPackage } from '../models/dependency.model';
import { normalizeVersionForQuery } from '../../engine/dependencies/purl';

/**
 * OSV.dev vulnerability client.
 *
 * Two-pass by necessity, not by choice: `querybatch` returns advisory *identifiers only*
 * — no severity, no summary, no fixed version — so a second pass fetches details for each
 * unique id. Phase 0 measured this as decisively cheaper than the alternative: for
 * `npm/cli`, 1,026 packages produced just 54 unique advisories, so batch-then-detail costs
 * 3 + 54 requests where `POST /v1/query` per package would cost 1,026.
 */

/** Which advisory ids came back for which package. */
export interface AdvisoryMatch {
  readonly advisoryId: string;
  readonly package: NormalizedPackage;
}

export interface OsvQueryResult {
  /** Full advisory records, for the engine to normalise. */
  readonly records: readonly unknown[];
  readonly matches: readonly AdvisoryMatch[];
  readonly packagesChecked: number;
  /** Packages whose batch failed. Non-zero means the result is partial, not clean. */
  readonly packagesFailed: number;
  /** Advisories found but not fetched in detail, because the cap was reached. */
  readonly advisoriesOmitted: number;
  readonly failureReason: string | null;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

@Injectable({ providedIn: 'root' })
export class OsvApiService {
  private readonly http = inject(HttpClient);

  /**
   * Queries OSV for the supplied packages.
   *
   * Callers must pass only packages with exact versions; `queryablePackages()` in the
   * engine enforces that. This is the hard rule from ADR-0002 — OSV does not reject a
   * range supplied where a version belongs, it silently returns a different and wrong
   * answer — so the guard below rejects anything else rather than trusting the caller.
   *
   * Cancellable by unsubscribing. A failed chunk degrades to a partial result rather than
   * discarding everything, because partial vulnerability data that says so is more useful
   * than none (§6.3).
   */
  queryPackages(packages: readonly NormalizedPackage[]): Observable<OsvQueryResult> {
    const queryable = packages.filter(
      (pkg) =>
        pkg.ecosystem !== null && pkg.versionKind === 'exact' && pkg.declaredVersion !== null,
    );

    if (queryable.length === 0) {
      return of({
        records: [],
        matches: [],
        packagesChecked: 0,
        packagesFailed: 0,
        advisoriesOmitted: 0,
        failureReason: null,
      });
    }

    const chunks = chunk(queryable, OSV_LIMITS.chunkSize);

    return from(chunks).pipe(
      // Sequential: OSV publishes no rate limit, but a burst of large POSTs from every
      // visitor is not a reasonable thing to do to a free public service. Phase 0
      // measured 1,026 packages in 3 sequential chunks at ~2s total.
      concatMap((batch) => this.queryBatch(batch)),
      reduce(
        (accumulated: BatchOutcome, outcome: BatchOutcome) => ({
          matches: [...accumulated.matches, ...outcome.matches],
          checked: accumulated.checked + outcome.checked,
          failed: accumulated.failed + outcome.failed,
          failureReason: accumulated.failureReason ?? outcome.failureReason,
        }),
        { matches: [], checked: 0, failed: 0, failureReason: null },
      ),
      concatMap((batched) => this.fetchDetails(batched)),
    );
  }

  /** One `POST /v1/querybatch`. A failure degrades the chunk rather than the whole scan. */
  private queryBatch(packages: readonly NormalizedPackage[]): Observable<BatchOutcome> {
    const queries = packages.map((pkg) => ({
      package: { name: pkg.name, ecosystem: pkg.ecosystem },
      // Normalised per ecosystem: OSV expects Go versions with a leading `v`, and
      // rejects it elsewhere. No other rewriting happens — altering a version before
      // matching would risk matching the wrong one.
      version:
        pkg.ecosystem === null || pkg.declaredVersion === null
          ? pkg.declaredVersion
          : normalizeVersionForQuery(pkg.ecosystem, pkg.declaredVersion),
    }));

    return this.http
      .post<unknown>(`${OSV_API_ORIGIN}/v1/querybatch`, { queries }, { observe: 'body' })
      .pipe(
        timeout(RESPONSE_LIMITS.requestTimeoutMs),
        map((body) => ({
          matches: readBatchMatches(body, packages),
          checked: packages.length,
          failed: 0,
          failureReason: null as string | null,
        })),
        catchError((error: unknown) =>
          of({
            matches: [],
            checked: 0,
            failed: packages.length,
            failureReason: describeOsvFailure(error),
          }),
        ),
      );
  }

  /**
   * Fetches full advisory records for each unique id.
   *
   * Bounded concurrency and a hard cap on total requests. The cap matters: a repository
   * with many vulnerable dependencies could otherwise produce hundreds of requests from a
   * single page load.
   */
  private fetchDetails(batched: BatchOutcome): Observable<OsvQueryResult> {
    const uniqueIds = [...new Set(batched.matches.map((match) => match.advisoryId))].sort();
    const idsToFetch = uniqueIds.slice(0, OSV_LIMITS.maxDetailRequests);
    const advisoriesOmitted = uniqueIds.length - idsToFetch.length;

    if (idsToFetch.length === 0) {
      return of({
        records: [],
        matches: batched.matches,
        packagesChecked: batched.checked,
        packagesFailed: batched.failed,
        advisoriesOmitted: 0,
        failureReason: batched.failureReason,
      });
    }

    return from(idsToFetch).pipe(
      mergeMap((id) => this.fetchDetail(id), OSV_LIMITS.detailConcurrency),
      reduce((records: unknown[], record: unknown | null) => {
        if (record !== null) {
          records.push(record);
        }
        return records;
      }, []),
      map((records) => ({
        records,
        matches: batched.matches,
        packagesChecked: batched.checked,
        packagesFailed: batched.failed,
        advisoriesOmitted,
        failureReason:
          batched.failureReason ??
          (advisoriesOmitted > 0
            ? `${advisoriesOmitted} further advisories were found but not retrieved, to bound the number of requests.`
            : null),
      })),
    );
  }

  /** A single advisory. Failure yields null: one lost record must not fail the scan. */
  private fetchDetail(id: string): Observable<unknown | null> {
    const url = `${OSV_API_ORIGIN}/v1/vulns/${encodeURIComponent(id)}`;
    return this.http.get<unknown>(url).pipe(
      timeout(RESPONSE_LIMITS.requestTimeoutMs),
      catchError(() => of(null)),
    );
  }
}

interface BatchOutcome {
  readonly matches: readonly AdvisoryMatch[];
  readonly checked: number;
  readonly failed: number;
  readonly failureReason: string | null;
}

/**
 * Reads `querybatch` results.
 *
 * Results are positional: `results[i]` corresponds to `queries[i]`. The response is
 * untrusted (§9.2), so a mismatched length is treated as unusable rather than guessed at
 * — misaligning results would attribute advisories to the wrong packages, which is worse
 * than reporting none.
 */
function readBatchMatches(
  body: unknown,
  packages: readonly NormalizedPackage[],
): readonly AdvisoryMatch[] {
  if (!isObject(body) || !Array.isArray(body['results'])) {
    return [];
  }

  const results = body['results'];
  if (results.length !== packages.length) {
    return [];
  }

  const matches: AdvisoryMatch[] = [];
  for (let index = 0; index < results.length; index++) {
    const result = results[index];
    const pkg = packages[index];
    if (!isObject(result) || pkg === undefined || !Array.isArray(result['vulns'])) {
      continue;
    }
    for (const vuln of result['vulns']) {
      if (!isObject(vuln)) {
        continue;
      }
      const id = vuln['id'];
      if (typeof id === 'string' && id.length > 0) {
        matches.push({ advisoryId: id, package: pkg });
      }
    }
  }

  return matches;
}

function describeOsvFailure(error: unknown): string {
  if (error instanceof HttpErrorResponse) {
    if (error.status === 0) {
      return 'The vulnerability database could not be reached.';
    }
    if (error.status === 400) {
      return 'The vulnerability database rejected a query.';
    }
    if (error.status >= 500) {
      return 'The vulnerability database is temporarily unavailable.';
    }
    return `The vulnerability database returned an unexpected response (HTTP ${error.status}).`;
  }
  if (error instanceof Error && error.name === 'TimeoutError') {
    return 'The vulnerability database did not respond in time.';
  }
  return 'The vulnerability database could not be queried.';
}

/** Splits into chunks, bounded by OSV's measured limit of 1,000 queries per request. */
function chunk<T>(items: readonly T[], size: number): readonly (readonly T[])[] {
  const bounded = Math.min(size, OSV_LIMITS.maxQueriesPerBatch);
  const chunks: T[][] = [];
  for (let index = 0; index < items.length; index += bounded) {
    chunks.push(items.slice(index, index + bounded));
  }
  return chunks;
}
