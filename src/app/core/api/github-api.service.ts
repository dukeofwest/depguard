import { Injectable, inject } from '@angular/core';
import {
  HttpClient,
  HttpErrorResponse,
  HttpHeaders,
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
  getWeeklyCommits(ref: RepositoryRef): Observable<readonly number[] | null> {
    const { owner, repo } = encodeRef(ref);
    return this.getJson(`${GITHUB_API_ORIGIN}/repos/${owner}/${repo}/stats/commit_activity`).pipe(
      this.nullOn404(),
      map((response) =>
        response === null || response.status === 202 ? null : toWeeklyCommits(response.body),
      ),
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
    const { owner, repo } = encodeRef(ref);
    const safePath = path
      .split('/')
      .filter((segment) => segment.length > 0 && segment !== '.' && segment !== '..')
      .map(encodeURIComponent)
      .join('/');
    const url = `${GITHUB_RAW_ORIGIN}/${owner}/${repo}/${encodeURIComponent(branch)}/${safePath}`;

    if (!isAllowedUrl(url)) {
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

  // ---- Internals -------------------------------------------------------

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
