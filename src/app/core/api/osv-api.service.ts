import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, catchError, concatMap, from, map, mergeMap, of, reduce, timeout } from 'rxjs';

import { OSV_API_ORIGIN, OSV_LIMITS, RESPONSE_LIMITS } from '../config/api.config';
import type { NormalizedPackage } from '../models/dependency.model';
import { normalizeVersionForQuery } from '../../engine/dependencies/purl';
import { DEFAULT_JSON_BOUNDS, parseBoundedJson } from './response-guard';

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
  /**
   * Advisory ids OSV confirmed in `querybatch` whose detail request then failed.
   *
   * Load-bearing. `querybatch` establishes that a package *is* affected; the detail
   * request only supplies severity and prose. Dropping a failed detail silently would
   * erase a confirmed vulnerability, and because findings are built from records rather
   * than from matches the result would read as "no known vulnerabilities were found" —
   * the single most damaging thing DepGuard could say (§6, ADR-0002).
   *
   * Retained as ids rather than as a count so the report can name what it lost. The
   * ids are not turned into findings: inventing advisory details from an id alone would
   * be the opposite error.
   */
  readonly advisoriesUnretrieved: readonly string[];
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
        advisoriesUnretrieved: [],
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
      .post(
        `${OSV_API_ORIGIN}/v1/querybatch`,
        { queries },
        {
          observe: 'body',
          // Text, then parsed under explicit bounds - see `requestJson` in
          // github-api.service.ts for why HttpClient's JSON mode is not used.
          responseType: 'text',
        },
      )
      .pipe(
        timeout(RESPONSE_LIMITS.requestTimeoutMs),
        map((text) => ({
          matches: readBatchMatches(readBounded(text), packages),
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

    // Advisories beyond the cap were confirmed but deliberately not requested. They are
    // a disclosed omission, not a transport failure, so they are counted separately from
    // `advisoriesUnretrieved`.
    const omittedIds = uniqueIds.slice(idsToFetch.length);

    if (idsToFetch.length === 0) {
      return of({
        records: [],
        matches: batched.matches,
        packagesChecked: batched.checked,
        packagesFailed: batched.failed,
        advisoriesOmitted: 0,
        advisoriesUnretrieved: [],
        failureReason: batched.failureReason,
      });
    }

    return from(idsToFetch).pipe(
      mergeMap((id) => this.fetchDetail(id), OSV_LIMITS.detailConcurrency),
      reduce(
        (accumulated: DetailOutcome, outcome: AdvisoryDetail) => {
          if (outcome.record === null) {
            // Confirmed by querybatch, but its details never arrived. Recorded so the
            // scan cannot be reported as complete.
            accumulated.unretrieved.push(outcome.id);
          } else {
            accumulated.records.push(outcome.record);
          }
          return accumulated;
        },
        { records: [], unretrieved: [] },
      ),
      map(({ records, unretrieved }) => ({
        records,
        matches: batched.matches,
        packagesChecked: batched.checked,
        packagesFailed: batched.failed,
        advisoriesOmitted,
        advisoriesUnretrieved: [...unretrieved].sort(),
        failureReason:
          batched.failureReason ??
          describeIncompleteDetails([...unretrieved].sort(), omittedIds.length),
      })),
    );
  }

  /**
   * A single advisory.
   *
   * A failure yields a null record **paired with its id** rather than a bare null: one
   * lost record must not fail the scan, but it must not vanish either. An unparseable or
   * oversized body is treated the same way as a transport failure — in both cases the
   * advisory is confirmed and its details are unavailable.
   */
  private fetchDetail(id: string): Observable<AdvisoryDetail> {
    const url = `${OSV_API_ORIGIN}/v1/vulns/${encodeURIComponent(id)}`;
    return this.http.get(url, { responseType: 'text' }).pipe(
      timeout(RESPONSE_LIMITS.requestTimeoutMs),
      map((text) => ({ id, record: readBounded(text) })),
      catchError(() => of({ id, record: null })),
    );
  }
}

/** One advisory detail attempt: the id, and its record or null if it could not be read. */
interface AdvisoryDetail {
  readonly id: string;
  readonly record: unknown | null;
}

interface DetailOutcome {
  readonly records: unknown[];
  readonly unretrieved: string[];
}

/**
 * Describes incomplete advisory retrieval, or null when nothing was lost.
 *
 * Returning null for the complete case matters: a non-null reason forces the result to
 * `partial`, and a scan that retrieved everything it asked for must not be marked
 * incomplete merely because there was nothing to retrieve (§4.3 Scenario D).
 */
function describeIncompleteDetails(unretrieved: readonly string[], omitted: number): string | null {
  const parts: string[] = [];

  if (unretrieved.length > 0) {
    parts.push(
      `${unretrieved.length} confirmed ${unretrieved.length === 1 ? 'advisory' : 'advisories'} ` +
        `could not be retrieved in full (${unretrieved.join(', ')}), so ${unretrieved.length === 1 ? 'it is' : 'they are'} ` +
        'not listed below. This is not evidence that the affected dependencies are safe.',
    );
  }

  if (omitted > 0) {
    parts.push(
      `${omitted} further advisories were found but not retrieved, to bound the number of requests.`,
    );
  }

  return parts.length === 0 ? null : parts.join(' ');
}

/**
 * Parses an OSV body under the shared response bounds.
 *
 * Returns null on anything oversized, malformed or pathologically nested. A lost
 * advisory record degrades the result - which the report then declares as partial - and
 * that is the right trade: the alternative is letting a hostile response from a public
 * API decide how much memory this page allocates.
 */
function readBounded(text: string): unknown {
  const parsed = parseBoundedJson(text, DEFAULT_JSON_BOUNDS);
  return parsed.ok ? parsed.value : null;
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
