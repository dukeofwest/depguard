import { Injectable, inject } from '@angular/core';
import {
  HttpClient,
  HttpErrorResponse,
  HttpEventType,
  HttpHeaders,
  type HttpEvent,
  type HttpResponse,
} from '@angular/common/http';
import { Observable, catchError, map, of, retry, throwError, timeout, timer } from 'rxjs';

import {
  GITHUB_ACCEPT_HEADER,
  GITHUB_API_ORIGIN,
  GITHUB_API_VERSION_HEADER,
  GITHUB_RAW_ORIGIN,
  RESPONSE_LIMITS,
  isAllowedUrl,
} from '../config/api.config';
import { createAppError, type AppError } from '../models/api-error.model';
import type {
  ReleaseInfo,
  RepositoryMetadata,
  RepositoryRef,
  RepositoryTree,
  WeeklyCommits,
  WorkflowSummary,
} from '../models/repository.model';
import { encodeRef } from '../utils/github-url';
import {
  DEFAULT_JSON_BOUNDS,
  SBOM_BOUNDS,
  parseBoundedJson,
  type JsonBounds,
} from './response-guard';
import { CacheService } from '../services/cache.service';
import { RateLimitService } from '../services/rate-limit.service';
import {
  contributorCountFromLink,
  toLanguages,
  toReleaseInfo,
  toRepositoryMetadata,
  toRepositoryTree,
  toWeeklyCommits,
  toWorkflowSummaries,
} from './github-response';

/**
 * The result of a byte-bounded raw-content fetch.
 *
 * `consumed` is present on every variant and is what a caller charges to an aggregate
 * budget: bytes actually received before the transfer ended, whether it ended by
 * completing, by being refused, or by being aborted mid-body.
 */
export type RawFileOutcome =
  | {
      /** No such file on this branch, or an empty body. */
      readonly kind: 'missing';
      readonly consumed: number;
    }
  | {
      readonly kind: 'text';
      readonly text: string;
      readonly consumed: number;
    }
  | {
      /**
       * The allowance was exceeded, so the transfer was abandoned and no body is
       * returned. `announced` is the server's `Content-Length` when that is what refused
       * the file before its body was read, and null when the bytes received did.
       */
      readonly kind: 'over-limit';
      readonly limit: number;
      readonly consumed: number;
      readonly announced: number | null;
    };

/**
 * GitHub REST client.
 *
 * Uses only the endpoints verified anonymously in Phase 0 (see
 * docs/phase-0/FEASIBILITY-REPORT.md §2). Every method is cancellable by unsubscribing,
 * every response is validated before use, and every error becomes a typed `AppError` so
 * raw API output never reaches the UI (§10.5).
 *
 * There is no SBOM polling. Phase 0 established that
 * `GET /repos/{owner}/{repo}/dependency-graph/sbom` responds synchronously with the SPDX
 * document; the asynchronous workflow the specification anticipated does not exist.
 */
@Injectable({ providedIn: 'root' })
export class GithubApiService {
  private readonly http = inject(HttpClient);
  private readonly cache = inject(CacheService);
  private readonly rateLimit = inject(RateLimitService);

  // ---- Public API ------------------------------------------------------

  /**
   * Primes the rate-limit display without spending any quota.
   *
   * Phase 0 confirmed `GET /rate_limit` reports the budget and does **not** decrement it.
   * Calling it on load means the remaining-requests indicator is populated before the
   * user's first scan rather than appearing only after it — which matters most for a
   * visitor arriving on a shared IP whose budget is already spent (ADR-0004).
   *
   * Failure is deliberately silent: this is a display nicety, not a prerequisite.
   */
  primeRateLimit(): Observable<void> {
    return this.http
      .get(`${GITHUB_API_ORIGIN}/rate_limit`, {
        headers: new HttpHeaders({ Accept: GITHUB_ACCEPT_HEADER }),
        observe: 'response',
        // Only the headers are read, so the body is never parsed.
        responseType: 'text',
      })
      .pipe(
        timeout(RESPONSE_LIMITS.requestTimeoutMs),
        map((response) => {
          this.rateLimit.updateFromHeaders(response.headers);
        }),
        catchError(() => of(undefined)),
      );
  }

  /** `GET /repos/{owner}/{repo}` — the only strictly required request. */
  getRepository(ref: RepositoryRef): Observable<RepositoryMetadata> {
    const { owner, repo } = encodeRef(ref);
    return this.getJson(`${GITHUB_API_ORIGIN}/repos/${owner}/${repo}`).pipe(
      map((response) => {
        const metadata = toRepositoryMetadata(response.body, ref);
        if (metadata === null) {
          throw createAppError(
            'github-unavailable',
            'GitHub returned an unexpected response for this repository.',
            { remedy: 'Try again in a moment.' },
          );
        }
        return metadata;
      }),
    );
  }

  /**
   * The repository SBOM, as SPDX JSON.
   *
   * Returns `null` on 404, which is a normal outcome rather than an error: Phase 0 found
   * 2 of 6 tested repositories had no dependency graph available.
   */
  getSbom(ref: RepositoryRef): Observable<unknown | null> {
    const { owner, repo } = encodeRef(ref);
    return this.getJson(
      `${GITHUB_API_ORIGIN}/repos/${owner}/${repo}/dependency-graph/sbom`,
      SBOM_BOUNDS,
    ).pipe(
      this.nullOn404(),
      map((response) => response?.body ?? null),
    );
  }

  /**
   * The full file tree for a ref.
   *
   * One recursive request replaces a per-file existence check for every documentation,
   * security and CI signal — Phase 0 measured 133 signal-bearing paths returned in a
   * single call for `expressjs/express`, against a budget of 60 requests per hour.
   */
  getTree(ref: RepositoryRef, branch: string): Observable<RepositoryTree | null> {
    const { owner, repo } = encodeRef(ref);
    const encodedBranch = encodeURIComponent(branch);
    return this.getJson(
      `${GITHUB_API_ORIGIN}/repos/${owner}/${repo}/git/trees/${encodedBranch}?recursive=1`,
    ).pipe(
      this.nullOn404(),
      map((response) =>
        response === null ? null : toRepositoryTree(response.body, RESPONSE_LIMITS.maxPackages),
      ),
    );
  }

  /** `GET /repos/{owner}/{repo}/actions/workflows`. */
  getWorkflows(ref: RepositoryRef): Observable<readonly WorkflowSummary[] | null> {
    const { owner, repo } = encodeRef(ref);
    return this.getJson(`${GITHUB_API_ORIGIN}/repos/${owner}/${repo}/actions/workflows`).pipe(
      this.nullOn404(),
      map((response) => (response === null ? null : toWorkflowSummaries(response.body))),
    );
  }

  /** Latest release. 404 means the repository has none — not a failure. */
  getLatestRelease(ref: RepositoryRef): Observable<ReleaseInfo | null> {
    const { owner, repo } = encodeRef(ref);
    return this.getJson(`${GITHUB_API_ORIGIN}/repos/${owner}/${repo}/releases/latest`).pipe(
      this.nullOn404(),
      map((response) => (response === null ? null : toReleaseInfo(response.body))),
    );
  }

  /** Contributor count, derived from the `Link` header rather than by paging. */
  getContributorCount(ref: RepositoryRef): Observable<number | null> {
    const { owner, repo } = encodeRef(ref);
    return this.getJson(
      `${GITHUB_API_ORIGIN}/repos/${owner}/${repo}/contributors?per_page=1&anon=true`,
    ).pipe(
      this.nullOn404(),
      map((response) => {
        if (response === null) {
          return null;
        }
        const fromLink = contributorCountFromLink(response.headers.get('link'));
        if (fromLink !== null) {
          return fromLink;
        }
        // No `Link` header means a single page; count what came back.
        return Array.isArray(response.body) ? response.body.length : null;
      }),
    );
  }

  /** `GET /repos/{owner}/{repo}/languages`. */
  getLanguages(ref: RepositoryRef): Observable<Readonly<Record<string, number>> | null> {
    const { owner, repo } = encodeRef(ref);
    return this.getJson(`${GITHUB_API_ORIGIN}/repos/${owner}/${repo}/languages`).pipe(
      this.nullOn404(),
      map((response) => (response === null ? null : toLanguages(response.body))),
    );
  }

  /**
   * 52 weeks of commit totals.
   *
   * GitHub returns `202 Accepted` with an empty body while it computes statistics for a
   * repository it has not cached. That yields `null`, reported as `Unknown` activity —
   * never as zero commits. It is deliberately not polled: the result is a secondary
   * signal and polling would spend scarce quota.
   */
  getWeeklyCommits(ref: RepositoryRef): Observable<WeeklyCommits> {
    const { owner, repo } = encodeRef(ref);
    return this.getJson(`${GITHUB_API_ORIGIN}/repos/${owner}/${repo}/stats/commit_activity`).pipe(
      this.nullOn404(),
      map((response): WeeklyCommits => {
        if (response === null) {
          return { kind: 'unavailable' };
        }
        // 202 means "accepted, still computing" — reported as pending so a young
        // repository's unbuilt statistics are never read as zero activity (P1-6).
        if (response.status === 202) {
          return { kind: 'pending' };
        }
        const weeks = toWeeklyCommits(response.body);
        return weeks === null ? { kind: 'unavailable' } : { kind: 'available', weeks };
      }),
    );
  }

  /**
   * Fetches one allowlisted file's contents from raw.githubusercontent.com.
   *
   * Phase 0 confirmed this origin is CORS-open and **does not consume the API quota**,
   * which is what makes content-level validation affordable: checking that a workflow
   * actually invokes CodeQL, rather than inferring it from a filename.
   *
   * `path` must come from the fixed allowlist in api.config.ts. A path discovered inside
   * repository content is never fetched (§9.2).
   */
  getRawFile(ref: RepositoryRef, branch: string, path: string): Observable<string | null> {
    const url = this.rawFileUrl(ref, branch, path);

    if (url === null) {
      return throwError(() =>
        createAppError('internal', 'DepGuard tried to contact an unexpected address.'),
      );
    }

    return this.cache.getOrCreate(`raw:${url}`, () =>
      this.http.get(url, { observe: 'response', responseType: 'text' }).pipe(
        timeout(RESPONSE_LIMITS.requestTimeoutMs),
        map((response: HttpResponse<string>) => {
          const body = response.body;
          if (body === null) {
            return null;
          }
          // Bound memory: a hostile or pathological file is truncated, not loaded whole.
          return body.length > RESPONSE_LIMITS.maxFileContentBytes
            ? body.slice(0, RESPONSE_LIMITS.maxFileContentBytes)
            : body;
        }),
        // A missing file is the expected case for most of the allowlist, so 404 is data,
        // not an error. raw.githubusercontent.com costs no API quota, so no retry budget
        // concern applies here.
        catchError((error: unknown) =>
          error instanceof HttpErrorResponse && error.status === 404
            ? of(null)
            : throwError(() => this.toAppError(error)),
        ),
      ),
    );
  }

  /**
   * Fetches one allowlisted file under an explicit byte allowance, aborting the transfer
   * if the allowance is exceeded.
   *
   * ## Why this exists alongside `getRawFile`
   *
   * `getRawFile` reads the body and *then* truncates it. That bounds how much DepGuard
   * keeps, not how much it downloads, which is adequate for the four fixed paths and the
   * workflow files but not for dependency discovery: there the per-file cap has to
   * compose with an aggregate budget across up to 32 files, and a cap applied after the
   * fact cannot bound an aggregate at all.
   *
   * So this one enforces its allowance **while consuming the response**:
   *
   * 1. `Content-Length`, when present, is compared against the allowance before the body
   *    is read, so an oversized file costs one set of headers and nothing more.
   * 2. Download-progress events are watched as chunks arrive, and the transfer is
   *    abandoned the moment the bytes received exceed the allowance. Completing the
   *    subscriber tears down the inner subscription, which aborts the `fetch` — so the
   *    bound is "the allowance plus at most one chunk", not the file's full size.
   * 3. The assembled body is re-checked, as a backstop for a backend that reports no
   *    progress at all.
   *
   * `consumed` on every outcome is what the caller must charge to its budget: bytes
   * actually received, taken from the progress events' `loaded` counter rather than from
   * the decoded string's length, so the accounting is in wire bytes.
   */
  getBoundedRawFile(
    ref: RepositoryRef,
    branch: string,
    path: string,
    limitBytes: number,
  ): Observable<RawFileOutcome> {
    const url = this.rawFileUrl(ref, branch, path);

    if (url === null) {
      return throwError(() =>
        createAppError('internal', 'DepGuard tried to contact an unexpected address.'),
      );
    }

    // Never above the standing per-file cap, whatever the caller asks for, and never
    // negative — a caller with no allowance left should not be issuing a request at all,
    // but a zero allowance must not become an unbounded one.
    const limit = Math.max(
      0,
      Math.min(Math.floor(limitBytes), RESPONSE_LIMITS.maxFileContentBytes),
    );

    // The allowance is part of the cache key: the same file read under a smaller
    // allowance is a different, possibly refused, result, and must not be served from a
    // request made under a larger one.
    return this.cache.getOrCreate(`raw:${limit}:${url}`, () => this.streamBounded(url, limit));
  }

  // ---- Internals -------------------------------------------------------

  /**
   * The validated raw-content URL for a repository path, or null if it would leave the
   * allowlisted origin.
   *
   * The path is still filtered segment by segment and percent-encoded, so a traversal
   * segment cannot survive even if the caller's own allowlist were bypassed.
   */
  private rawFileUrl(ref: RepositoryRef, branch: string, path: string): string | null {
    const { owner, repo } = encodeRef(ref);
    const safePath = path
      .split('/')
      .filter((segment) => segment.length > 0 && segment !== '.' && segment !== '..')
      .map(encodeURIComponent)
      .join('/');
    const url = `${GITHUB_RAW_ORIGIN}/${owner}/${repo}/${encodeURIComponent(branch)}/${safePath}`;

    return isAllowedUrl(url) ? url : null;
  }

  /** The bounded transfer itself. Never throws for a 404; see `getBoundedRawFile`. */
  private streamBounded(url: string, limit: number): Observable<RawFileOutcome> {
    return new Observable<RawFileOutcome>((subscriber) => {
      let received = 0;
      let partial = '';
      let settled = false;

      /**
       * Emits once and completes. Completing runs this Observable's teardown, which
       * unsubscribes the inner request — and that is what aborts an over-limit transfer
       * rather than merely ignoring its result.
       */
      const settle = (outcome: RawFileOutcome): void => {
        if (settled) {
          return;
        }
        settled = true;
        subscriber.next(outcome);
        subscriber.complete();
      };

      const subscription = this.http
        .get(url, { observe: 'events', reportProgress: true, responseType: 'text' })
        .pipe(timeout(RESPONSE_LIMITS.requestTimeoutMs))
        .subscribe({
          next: (event: HttpEvent<string>) => {
            if (event.type === HttpEventType.ResponseHeader) {
              const header = event.headers.get('Content-Length');
              const announced = header === null ? Number.NaN : Number(header);
              if (Number.isFinite(announced) && announced > limit) {
                // The server's own claim about its size. Believing it here only ever
                // refuses early; a server that understates it is still caught below.
                settle({ kind: 'over-limit', limit, consumed: 0, announced });
              }
              return;
            }

            if (event.type === HttpEventType.DownloadProgress) {
              received = Math.max(received, event.loaded);
              partial = event.partialText ?? partial;
              if (received > limit || partial.length > limit) {
                settle({ kind: 'over-limit', limit, consumed: received, announced: null });
              }
              return;
            }

            if (event.type === HttpEventType.Response) {
              const body = event.body;
              if (body === null) {
                settle({ kind: 'missing', consumed: received });
                return;
              }
              // Backstop for a backend that emitted no progress events. Measured as
              // **encoded UTF-8 bytes**, not as the string's length: `String.length`
              // counts UTF-16 code units, which undercounts every character outside the
              // BMP by half and would let a file of astral characters consume up to
              // twice its allowance whenever progress reporting was unavailable. The
              // bound must not depend on the backend being chatty.
              received = Math.max(received, utf8ByteLength(body));
              if (received > limit) {
                settle({ kind: 'over-limit', limit, consumed: received, announced: null });
                return;
              }
              settle({ kind: 'text', text: body, consumed: received });
            }
          },
          error: (error: unknown) => {
            // A missing file is the expected case for most of the allowlist, so 404 is
            // data rather than an error.
            if (error instanceof HttpErrorResponse && error.status === 404) {
              settle({ kind: 'missing', consumed: received });
              return;
            }
            if (!settled) {
              settled = true;
              subscriber.error(this.toAppError(error));
            }
          },
          complete: () => {
            // A response that produced no event this method recognises. Treated as
            // absent rather than as empty content, so nothing downstream reads a
            // zero-length manifest as a real one.
            settle({ kind: 'missing', consumed: received });
          },
        });

      return () => subscription.unsubscribe();
    });
  }

  /**
   * Performs a cached, validated, rate-limit-aware GET.
   *
   * Responses are cached by URL so a repeated analysis in the same session spends no
   * quota, and concurrent identical requests are deduplicated by CacheService.
   */
  private getJson(
    url: string,
    bounds: JsonBounds = DEFAULT_JSON_BOUNDS,
  ): Observable<HttpResponse<unknown>> {
    return this.cache.getOrCreate(`gh:${url}`, () => this.requestJson(url, bounds));
  }

  /**
   * Requests a body as **text** and parses it under explicit bounds.
   *
   * Deliberately not `HttpClient`'s JSON mode. That parses before any size or shape
   * check can run, so a hostile or pathological body is already an object graph in
   * memory by the time it could be rejected - and `Content-Length`, the only thing a
   * pre-parse check could consult, is absent on a chunked response. Taking the text and
   * parsing it here makes the limits in `response-guard.ts` apply to every response
   * rather than only to the ones that announce their size.
   */
  private requestJson(url: string, bounds: JsonBounds): Observable<HttpResponse<unknown>> {
    if (!isAllowedUrl(url)) {
      // Should be unreachable: every URL is built from validated refs. Kept as a hard
      // stop so a future bug cannot turn into a request to an arbitrary host (§14).
      return throwError(() =>
        createAppError('internal', 'DepGuard tried to contact an unexpected address.'),
      );
    }

    const headers = new HttpHeaders({
      Accept: GITHUB_ACCEPT_HEADER,
      'X-GitHub-Api-Version': GITHUB_API_VERSION_HEADER,
    });

    return this.http.get(url, { headers, observe: 'response', responseType: 'text' }).pipe(
      timeout(RESPONSE_LIMITS.requestTimeoutMs),
      retry({
        count: 2,
        delay: (error: unknown, retryCount) => {
          // Retry only what a retry can fix. A 4xx — including a rate limit — will not
          // succeed on repetition and must not burn more of the budget (§8.4).
          if (!this.isRetryable(error)) {
            return throwError(() => error);
          }
          return timer(300 * Math.pow(2, retryCount - 1));
        },
      }),
      map((response) => {
        this.rateLimit.updateFromHeaders(response.headers);
        this.enforceSizeLimit(response, bounds.maxLength);
        return this.parseBody(response, bounds);
      }),
      catchError((error: unknown) => throwError(() => this.toAppError(error))),
    );
  }

  /** Lets 404 pass through as `null`; everything else stays an error. */
  private nullOn404<T>() {
    return (source: Observable<T>): Observable<T | null> =>
      source.pipe(
        catchError((error: unknown) => {
          if (this.isAppErrorOfKind(error, 'repository-not-found')) {
            return of(null);
          }
          return throwError(() => error);
        }),
      );
  }

  private isAppErrorOfKind(error: unknown, kind: string): boolean {
    return (
      typeof error === 'object' && error !== null && (error as { kind?: unknown }).kind === kind
    );
  }

  private isRetryable(error: unknown): boolean {
    if (error instanceof HttpErrorResponse) {
      // 0 covers network failures and CORS rejections; 5xx is a server-side blip.
      return error.status === 0 || error.status >= 500;
    }
    // A timeout from the `timeout` operator.
    return error instanceof Error && error.name === 'TimeoutError';
  }

  /**
   * Rejects an oversized body before it is read, when the server declares its size.
   *
   * A cheap early exit only: `Content-Length` is absent on chunked responses and is in
   * any case the server's own claim, so `parseBody` re-checks the text it actually
   * received.
   */
  private enforceSizeLimit(response: HttpResponse<unknown>, maxBytes: number): void {
    const declared = response.headers.get('content-length');
    if (declared === null) {
      return;
    }
    const size = Number.parseInt(declared, 10);
    if (Number.isFinite(size) && size > maxBytes) {
      throw createAppError(
        'response-too-large',
        'This repository returned more data than DepGuard will process.',
        { remedy: 'Very large dependency graphs are not supported in this release.' },
      );
    }
  }

  /**
   * Turns response text into a validated object graph.
   *
   * An empty body is `null` rather than a parse failure: GitHub returns `202 Accepted`
   * with no body while it computes commit statistics, and `204` elsewhere. Those are
   * legitimate "no data yet" answers, which callers already map to `Unknown`.
   */
  private parseBody(response: HttpResponse<string>, bounds: JsonBounds): HttpResponse<unknown> {
    const text = response.body;
    if (text === null || text.trim().length === 0) {
      return response.clone<unknown>({ body: null });
    }

    const parsed = parseBoundedJson(text, bounds);
    if (parsed.ok) {
      return response.clone<unknown>({ body: parsed.value });
    }

    if (parsed.kind === 'malformed') {
      throw createAppError(
        'github-unavailable',
        'GitHub returned a response DepGuard could not read.',
        {
          remedy: 'Try again in a moment.',
        },
      );
    }

    throw createAppError('response-too-large', parsed.reason, {
      remedy: 'Very large or deeply nested dependency graphs are not supported in this release.',
    });
  }

  /** Maps any failure to a typed, user-safe error. Stack traces never escape (§10.5). */
  private toAppError(error: unknown): AppError {
    if (typeof error === 'object' && error !== null && 'kind' in error && 'message' in error) {
      return error as AppError;
    }

    if (error instanceof Error && error.name === 'TimeoutError') {
      return createAppError('network', 'GitHub did not respond in time.', {
        remedy: 'Check your connection and try again.',
      });
    }

    if (!(error instanceof HttpErrorResponse)) {
      return createAppError('internal', 'Something went wrong while contacting GitHub.');
    }

    this.rateLimit.updateFromHeaders(error.headers);

    switch (error.status) {
      case 0:
        return createAppError('network', 'Could not reach GitHub.', {
          remedy: 'Check your internet connection and try again.',
        });

      // GitHub returns 404 rather than 403 for repositories an anonymous caller cannot
      // see, so "not found" and "private" are genuinely indistinguishable here. The
      // message says so instead of guessing.
      case 401:
      case 404:
        return createAppError('repository-not-found', 'That repository could not be found.', {
          remedy: 'Check the spelling, and note that private repositories are not supported.',
        });

      case 403:
      case 429: {
        const remaining = error.headers.get('x-ratelimit-remaining');
        if (remaining === '0' || error.status === 429) {
          const reset = Number.parseInt(error.headers.get('x-ratelimit-reset') ?? '', 10);
          const resetAt = Number.isFinite(reset) ? reset : null;
          this.rateLimit.markExhausted(resetAt);
          return createAppError(
            'rate-limited',
            'GitHub’s hourly limit for anonymous requests has been reached.',
            {
              remedy:
                'DepGuard analyses public repositories without an account, which GitHub limits to 60 requests per hour per IP address.',
              ...(resetAt === null ? {} : { retryAt: new Date(resetAt * 1000).toISOString() }),
            },
          );
        }
        return createAppError(
          'repository-inaccessible',
          'GitHub refused access to that repository.',
          {
            remedy: 'It may be private, disabled, or blocked.',
          },
        );
      }

      case 451:
        return createAppError(
          'repository-inaccessible',
          'That repository is unavailable for legal reasons.',
        );

      default:
        if (error.status >= 500) {
          return createAppError('github-unavailable', 'GitHub is having trouble right now.', {
            remedy: 'Try again in a few minutes.',
          });
        }
        return createAppError('github-unavailable', 'GitHub returned an unexpected response.', {
          context: `HTTP ${error.status}`,
        });
    }
  }
}

/**
 * Shared encoder. Allocating one per response would be wasteful and `TextEncoder` holds
 * no per-call state.
 */
const UTF8 = new TextEncoder();

/**
 * The size of a string in encoded UTF-8 bytes.
 *
 * Used wherever a byte allowance has to be checked against text that has already been
 * decoded, so the check is in the same unit as the allowance. `String.prototype.length`
 * is not that unit: it counts UTF-16 code units, so `'𝄞'.length` is 2 where the character
 * occupies 4 bytes on the wire.
 *
 * `TextEncoder.encode` allocates, which is why this is reached only for a body already
 * held in memory and already bounded by the per-file cap — never for a stream being
 * consumed, where the progress counter reports true wire bytes directly.
 *
 * Note that UTF-8 length is always greater than or equal to the UTF-16 code-unit count,
 * so the cheaper code-unit comparison used while streaming can only ever refuse a
 * transfer earlier than this would. It is conservative, not permissive.
 */
function utf8ByteLength(text: string): number {
  return UTF8.encode(text).length;
}
