import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
  type TestRequest,
} from '@angular/common/http/testing';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';

import { GithubApiService } from './github-api.service';
import { CacheService } from '../services/cache.service';
import { RateLimitService } from '../services/rate-limit.service';
import type { AppError } from '../models/api-error.model';
import type { RepositoryRef } from '../models/repository.model';

const REF: RepositoryRef = { owner: 'expressjs', repo: 'express' };
const REPO_URL = 'https://api.github.com/repos/expressjs/express';

/** Headers matching what GitHub actually returns, as captured in Phase 0. */
function rateLimitHeaders(remaining = '59'): Record<string, string> {
  return {
    'x-ratelimit-limit': '60',
    'x-ratelimit-remaining': remaining,
    'x-ratelimit-reset': '1794559580',
  };
}

describe('GithubApiService', () => {
  let service: GithubApiService;
  let httpMock: HttpTestingController;
  let rateLimit: RateLimitService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        GithubApiService,
        CacheService,
        RateLimitService,
      ],
    });
    service = TestBed.inject(GithubApiService);
    httpMock = TestBed.inject(HttpTestingController);
    rateLimit = TestBed.inject(RateLimitService);
    // Each test gets a clean cache, otherwise results leak between tests.
    TestBed.inject(CacheService).clear();
  });

  afterEach(() => {
    httpMock.verify();
  });

  describe('getRepository', () => {
    it('normalises a real-shaped response', () => {
      const received: unknown[] = [];
      service.getRepository(REF).subscribe((value) => received.push(value));

      httpMock.expectOne(REPO_URL).flush(
        {
          full_name: 'expressjs/express',
          description: 'Fast, unopinionated, minimalist web framework for node.',
          html_url: 'https://github.com/expressjs/express',
          default_branch: 'master',
          archived: false,
          disabled: false,
          fork: false,
          visibility: 'public',
          stargazers_count: 69675,
          forks_count: 25439,
          open_issues_count: 262,
          size: 10074,
          language: 'JavaScript',
          license: { spdx_id: 'MIT', name: 'MIT License' },
          topics: ['express', 'nodejs'],
          created_at: '2009-06-26T18:56:01Z',
          updated_at: '2026-11-13T03:15:13Z',
          pushed_at: '2026-11-02T20:15:26Z',
        },
        { headers: rateLimitHeaders() },
      );

      expect(received).toHaveLength(1);
      expect(received[0]).toMatchObject({
        fullName: 'expressjs/express',
        defaultBranch: 'master',
        stars: 69675,
        licenseSpdxId: 'MIT',
        isArchived: false,
        pushedAt: '2026-11-02T20:15:26Z',
      });
    });

    it('survives missing and wrongly typed fields without inventing values', () => {
      // API responses are untrusted input (§9.2). Nothing here should throw.
      let result: { description: string | null; stars: number; topics: readonly string[] } | null =
        null;
      service.getRepository(REF).subscribe((value) => {
        result = value;
      });

      httpMock.expectOne(REPO_URL).flush({
        default_branch: 'main',
        html_url: 'https://github.com/expressjs/express',
        description: null,
        stargazers_count: 'not a number',
        topics: ['ok', 42, null],
        pushed_at: 'definitely-not-a-date',
        license: 'not an object',
      });

      expect(result).not.toBeNull();
      const value = result as unknown as {
        description: string | null;
        stars: number;
        topics: readonly string[];
        pushedAt: string | null;
        licenseSpdxId: string | null;
      };
      expect(value.description).toBeNull();
      expect(value.stars).toBe(0);
      expect(value.topics).toEqual(['ok']);
      // An unparseable date must become null, never "now".
      expect(value.pushedAt).toBeNull();
      expect(value.licenseSpdxId).toBeNull();
    });

    it('rejects a hostile html_url instead of rendering it as a link', () => {
      let result: { htmlUrl: string } | null = null;
      service.getRepository(REF).subscribe((value) => {
        result = value as unknown as { htmlUrl: string };
      });

      httpMock.expectOne(REPO_URL).flush({
        default_branch: 'main',
        html_url: 'javascript:alert(1)',
      });

      expect((result as unknown as { htmlUrl: string }).htmlUrl).toBe(
        'https://github.com/expressjs/express',
      );
    });
  });

  describe('error mapping (§10.5)', () => {
    it('maps 404 to repository-not-found without leaking the body', () => {
      let error: AppError | null = null;
      service.getRepository(REF).subscribe({ error: (e: AppError) => (error = e) });

      httpMock.expectOne(REPO_URL).flush(
        { message: 'Not Found', documentation_url: 'https://docs.github.com/rest' },
        {
          status: 404,
          statusText: 'Not Found',
        },
      );

      const mapped = error as unknown as AppError;
      expect(mapped.kind).toBe('repository-not-found');
      expect(mapped.message).not.toContain('documentation_url');
    });

    it('maps an exhausted budget to rate-limited with a reset time', () => {
      let error: AppError | null = null;
      service.getRepository(REF).subscribe({ error: (e: AppError) => (error = e) });

      httpMock.expectOne(REPO_URL).flush(
        { message: 'API rate limit exceeded' },
        {
          status: 403,
          statusText: 'Forbidden',
          headers: { ...rateLimitHeaders('0') },
        },
      );

      const mapped = error as unknown as AppError;
      expect(mapped.kind).toBe('rate-limited');
      expect(mapped.retryAt).toBeDefined();
      // The service must record exhaustion so the UI can stop further scans.
      expect(rateLimit.remaining()).toBe(0);
      expect(rateLimit.canStartScan()).toBe(false);
    });

    it('distinguishes a 403 that is not a rate limit', () => {
      let error: AppError | null = null;
      service.getRepository(REF).subscribe({ error: (e: AppError) => (error = e) });

      httpMock.expectOne(REPO_URL).flush(
        { message: 'Repository access blocked' },
        {
          status: 403,
          statusText: 'Forbidden',
          headers: rateLimitHeaders('42'),
        },
      );

      expect((error as unknown as AppError).kind).toBe('repository-inaccessible');
    });

    it('does not retry a 404 — a repeat cannot succeed and would waste quota', () => {
      service.getRepository(REF).subscribe({ error: () => undefined });
      httpMock.expectOne(REPO_URL).flush({}, { status: 404, statusText: 'Not Found' });
      // verify() in afterEach fails if a retry was issued.
      httpMock.verify();
    });

    it('retries a 500 with backoff', async () => {
      vi.useFakeTimers();
      try {
        const results: unknown[] = [];
        service.getRepository(REF).subscribe({ next: (v) => results.push(v) });

        httpMock.expectOne(REPO_URL).flush({}, { status: 500, statusText: 'Server Error' });
        await vi.advanceTimersByTimeAsync(1000);

        const retried = httpMock.expectOne(REPO_URL);
        retried.flush(
          { default_branch: 'main', html_url: 'https://github.com/expressjs/express' },
          { headers: rateLimitHeaders() },
        );

        expect(results).toHaveLength(1);
      } finally {
        vi.useRealTimers();
      }
    });
  });

  describe('SBOM', () => {
    const SBOM_URL = `${REPO_URL}/dependency-graph/sbom`;

    it('returns the document from a single synchronous request', () => {
      // Phase 0 disproved the asynchronous generate/poll/redirect workflow: this endpoint
      // answers with the SPDX document directly. One request, no polling.
      let body: unknown = undefined;
      service.getSbom(REF).subscribe((value) => (body = value));

      const request = httpMock.expectOne(SBOM_URL);
      expect(request.request.method).toBe('GET');
      request.flush(
        { sbom: { spdxVersion: 'SPDX-2.3', packages: [] } },
        {
          headers: rateLimitHeaders(),
        },
      );

      expect(body).toMatchObject({ sbom: { spdxVersion: 'SPDX-2.3' } });
      httpMock.verify();
    });

    it('treats 404 as "no SBOM available", not an error', () => {
      let body: unknown = 'untouched';
      let errored = false;
      service.getSbom(REF).subscribe({
        next: (value) => (body = value),
        error: () => (errored = true),
      });

      httpMock.expectOne(SBOM_URL).flush(
        { message: 'Not Found' },
        {
          status: 404,
          statusText: 'Not Found',
        },
      );

      expect(errored).toBe(false);
      expect(body).toBeNull();
    });

    it('refuses a response larger than the configured cap', () => {
      let error: AppError | null = null;
      service.getSbom(REF).subscribe({ error: (e: AppError) => (error = e) });

      httpMock
        .expectOne(SBOM_URL)
        .flush(
          { sbom: { packages: [] } },
          { headers: { 'content-length': String(64 * 1024 * 1024) } },
        );

      expect((error as unknown as AppError).kind).toBe('response-too-large');
    });
  });

  describe('tree', () => {
    it('carries truncation through so absence is not mistaken for proof', () => {
      let tree: { truncated: boolean; entries: readonly unknown[] } | null = null;
      service.getTree(REF, 'master').subscribe((value) => {
        tree = value as unknown as { truncated: boolean; entries: readonly unknown[] };
      });

      httpMock.expectOne(`${REPO_URL}/git/trees/master?recursive=1`).flush(
        {
          tree: [
            { path: 'LICENSE', type: 'blob', size: 1249 },
            { path: '.github/workflows/codeql.yml', type: 'blob', size: 2654 },
            { path: 'bogus', type: 'not-a-type' },
          ],
          truncated: true,
        },
        { headers: rateLimitHeaders() },
      );

      const value = tree as unknown as { truncated: boolean; entries: readonly unknown[] };
      expect(value.truncated).toBe(true);
      // The entry with an unrecognised type is dropped rather than guessed at.
      expect(value.entries).toHaveLength(2);
    });

    it('flags GitHub-injected workflows as not repository-defined', () => {
      // Regression guard for a finding from live testing: GitHub's workflow listing
      // includes workflows the repository never committed, under paths such as
      // `dynamic/...`. Treating those as configured CI would be a false claim (§5.3).
      let workflows: readonly { path: string; isRepositoryDefined: boolean }[] | null = null;
      service.getWorkflows(REF).subscribe((value) => {
        workflows = value as unknown as readonly {
          path: string;
          isRepositoryDefined: boolean;
        }[];
      });

      httpMock.expectOne(`${REPO_URL}/actions/workflows`).flush({
        workflows: [
          { name: 'CI', path: '.github/workflows/ci.yml', state: 'active' },
          {
            name: 'Copilot review',
            path: 'dynamic/copilot-pull-request-reviewer',
            state: 'active',
          },
        ],
      });

      const value = workflows as unknown as readonly {
        path: string;
        isRepositoryDefined: boolean;
      }[];
      expect(value).toHaveLength(2);
      expect(value[0]?.isRepositoryDefined).toBe(true);
      expect(value[1]?.isRepositoryDefined).toBe(false);
    });

    it('encodes the branch name', () => {
      service.getTree(REF, 'feature/a b').subscribe();
      const request = httpMock.expectOne((r) => r.url.includes('/git/trees/'));
      expect(request.request.url).toContain('feature%2Fa%20b');
      request.flush({ tree: [], truncated: false });
    });
  });

  describe('releases and stats', () => {
    it('reports no releases for a 404 rather than failing', () => {
      let release: unknown = 'untouched';
      service.getLatestRelease(REF).subscribe((value) => (release = value));
      httpMock
        .expectOne(`${REPO_URL}/releases/latest`)
        .flush({}, { status: 404, statusText: 'Not Found' });
      expect(release).toBeNull();
    });

    it('treats a 202 from commit stats as unknown, never as zero commits', () => {
      let commits: unknown = 'untouched';
      service.getWeeklyCommits(REF).subscribe((value) => (commits = value));
      httpMock
        .expectOne(`${REPO_URL}/stats/commit_activity`)
        .flush(null, { status: 202, statusText: 'Accepted' });
      expect(commits).toBeNull();
    });

    it('derives the contributor count from the Link header', () => {
      let count: number | null = null;
      service.getContributorCount(REF).subscribe((value) => (count = value));

      httpMock.expectOne(`${REPO_URL}/contributors?per_page=1&anon=true`).flush([{ login: 'a' }], {
        headers: {
          link: '<https://api.github.com/repositories/237159/contributors?per_page=1&page=372>; rel="last"',
        },
      });

      expect(count).toBe(372);
    });
  });

  describe('rate limit tracking', () => {
    it('records the budget from response headers', () => {
      service.getRepository(REF).subscribe({ error: () => undefined });
      httpMock
        .expectOne(REPO_URL)
        .flush(
          { default_branch: 'main', html_url: 'https://github.com/expressjs/express' },
          { headers: rateLimitHeaders('47') },
        );

      expect(rateLimit.remaining()).toBe(47);
      expect(rateLimit.limit()).toBe(60);
      // 47 remaining at ~9 per scan.
      expect(rateLimit.scansRemaining()).toBe(5);
    });

    it('leaves the budget untouched when headers are absent', () => {
      service.getRepository(REF).subscribe({ error: () => undefined });
      httpMock
        .expectOne(REPO_URL)
        .flush({ default_branch: 'main', html_url: 'https://github.com/expressjs/express' });

      // A missing header is not a budget of zero.
      expect(rateLimit.remaining()).toBeNull();
      expect(rateLimit.canStartScan()).toBe(true);
    });
  });

  describe('caching and deduplication (§8.4)', () => {
    it('serves a repeated request from cache without spending quota', () => {
      service.getRepository(REF).subscribe();
      httpMock
        .expectOne(REPO_URL)
        .flush(
          { default_branch: 'main', html_url: 'https://github.com/expressjs/express' },
          { headers: rateLimitHeaders() },
        );

      let second: unknown = null;
      service.getRepository(REF).subscribe((value) => (second = value));

      // No second HTTP request: verify() in afterEach would fail if one were issued.
      expect(second).not.toBeNull();
    });

    it('shares one in-flight request between concurrent callers', () => {
      const results: unknown[] = [];
      service.getRepository(REF).subscribe((v) => results.push(v));
      service.getRepository(REF).subscribe((v) => results.push(v));

      const requests: TestRequest[] = httpMock.match(REPO_URL);
      expect(requests).toHaveLength(1);

      requests[0]?.flush(
        { default_branch: 'main', html_url: 'https://github.com/expressjs/express' },
        { headers: rateLimitHeaders() },
      );

      expect(results).toHaveLength(2);
    });
  });

  describe('cancellation (§10.4)', () => {
    it('aborts the request when the subscriber unsubscribes', () => {
      const subscription = service.getRepository(REF).subscribe();
      const request = httpMock.expectOne(REPO_URL);
      expect(request.cancelled).toBe(false);

      subscription.unsubscribe();
      expect(request.cancelled).toBe(true);
    });
  });

  describe('raw file contents', () => {
    it('fetches from raw.githubusercontent.com, which costs no API quota', () => {
      let content: string | null = null;
      service.getRawFile(REF, 'master', '.github/dependabot.yml').subscribe((value) => {
        content = value;
      });

      const request = httpMock.expectOne(
        'https://raw.githubusercontent.com/expressjs/express/master/.github/dependabot.yml',
      );
      request.flush('version: 2\nupdates:\n  - package-ecosystem: npm\n');

      expect(content).toContain('updates:');
      // Rate limit state must be untouched by a raw request.
      expect(rateLimit.remaining()).toBeNull();
    });

    it('returns null for a missing file', () => {
      let content: string | null = 'untouched';
      service.getRawFile(REF, 'master', 'SECURITY.md').subscribe((value) => (content = value));

      httpMock
        .expectOne((r) => r.url.includes('SECURITY.md'))
        .flush('Not Found', { status: 404, statusText: 'Not Found' });

      expect(content).toBeNull();
    });

    it('strips traversal segments from the path', () => {
      service.getRawFile(REF, 'master', '../../../etc/passwd').subscribe();
      const request = httpMock.expectOne((r) =>
        r.url.startsWith('https://raw.githubusercontent.com/'),
      );
      expect(request.request.url).not.toContain('..');
      request.flush('', { status: 404, statusText: 'Not Found' });
    });

    it('truncates an oversized file rather than holding it all', () => {
      let content: string | null = null;
      service.getRawFile(REF, 'master', 'SECURITY.md').subscribe((value) => (content = value));

      httpMock.expectOne((r) => r.url.includes('SECURITY.md')).flush('x'.repeat(2_000_000));

      expect((content as unknown as string).length).toBe(512 * 1024);
    });
  });
});
