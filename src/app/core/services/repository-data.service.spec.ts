import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { RepositoryDataService } from './repository-data.service';
import { CacheService } from './cache.service';
import type { AppError } from '../models/api-error.model';
import type { RepositoryRef, RepositorySnapshot } from '../models/repository.model';

const REF: RepositoryRef = { owner: 'expressjs', repo: 'express' };
const BASE = 'https://api.github.com/repos/expressjs/express';

const METADATA = {
  full_name: 'expressjs/express',
  html_url: 'https://github.com/expressjs/express',
  default_branch: 'master',
  pushed_at: '2026-11-02T20:15:26Z',
  stargazers_count: 100,
};

describe('RepositoryDataService', () => {
  let service: RepositoryDataService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), RepositoryDataService],
    });
    service = TestBed.inject(RepositoryDataService);
    httpMock = TestBed.inject(HttpTestingController);
    TestBed.inject(CacheService).clear();
  });

  afterEach(() => {
    try {
      httpMock.verify();
    } finally {
      // Always reset, even when verify() throws, so one failing test cannot cascade into
      // "test module has already been instantiated" errors in every test after it.
      TestBed.resetTestingModule();
    }
  });

  /** Answers every secondary request, optionally forcing some to fail. */
  function flushSecondary(options: { fail?: readonly string[] } = {}): void {
    const fail = options.fail ?? [];
    const respond = (url: string, body: object): void => {
      const request = httpMock.expectOne(url);
      if (fail.includes(url)) {
        // 403 (not a rate limit) rather than 500: a 5xx is retried with backoff, which
        // would leave forkJoin pending until the timers run. This exercises the
        // degradation path directly.
        request.flush(
          { message: 'Blocked' },
          {
            status: 403,
            statusText: 'Forbidden',
            headers: { 'x-ratelimit-remaining': '42' },
          },
        );
      } else {
        request.flush(body);
      }
    };

    respond(`${BASE}/git/trees/master?recursive=1`, {
      tree: [{ path: 'LICENSE', type: 'blob', size: 10 }],
      truncated: false,
    });
    respond(`${BASE}/actions/workflows`, { workflows: [{ path: '.github/workflows/ci.yml' }] });
    respond(`${BASE}/releases/latest`, {
      tag_name: 'v5.3.0',
      published_at: '2026-10-09T12:50:31Z',
    });
    respond(`${BASE}/contributors?per_page=1&anon=true`, [{ login: 'a' }]);
    respond(`${BASE}/languages`, { JavaScript: 1000 });
    respond(`${BASE}/stats/commit_activity`, [{ total: 3 }, { total: 5 }]);

    // Raw file contents — no API quota, so these are separate from the budget.
    for (const request of httpMock.match((r) =>
      r.url.startsWith('https://raw.githubusercontent.com/'),
    )) {
      request.flush('', { status: 404, statusText: 'Not Found' });
    }
  }

  it('assembles a complete snapshot', () => {
    let snapshot: RepositorySnapshot | null = null;
    service.loadSnapshot(REF).subscribe((value) => (snapshot = value));

    httpMock.expectOne(BASE).flush(METADATA);
    flushSecondary();

    const value = snapshot as unknown as RepositorySnapshot;
    expect(value).not.toBeNull();
    expect(value.metadata.defaultBranch).toBe('master');
    expect(value.tree?.entries).toHaveLength(1);
    expect(value.workflows).toHaveLength(1);
    expect(value.latestRelease?.tagName).toBe('v5.3.0');
    expect(value.weeklyCommits).toEqual([3, 5]);
    expect(value.retrievedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('stays within the documented request budget', () => {
    service.loadSnapshot(REF).subscribe();
    httpMock.expectOne(BASE).flush(METADATA);

    // `match` consumes the requests, so they are flushed here rather than via
    // flushSecondary().
    const quotaRequests = httpMock.match((r) => r.url.startsWith('https://api.github.com/'));

    // 6 secondary + 1 metadata = 7 quota-consuming requests for a snapshot, plus the
    // SBOM fetched separately = 8 per scan. ADR-0004 budgeted 9 because it included
    // `/community/profile`; the recursive tree plus free raw.githubusercontent.com
    // content covers the same signals for one request less.
    expect(quotaRequests.length).toBe(6);

    for (const request of quotaRequests) {
      request.flush({});
    }
    for (const request of httpMock.match((r) =>
      r.url.startsWith('https://raw.githubusercontent.com/'),
    )) {
      request.flush('', { status: 404, statusText: 'Not Found' });
    }
  });

  it('produces a partial snapshot when optional sources fail (§6.3)', () => {
    let snapshot: RepositorySnapshot | null = null;
    let errored = false;
    service.loadSnapshot(REF).subscribe({
      next: (value) => (snapshot = value),
      error: () => (errored = true),
    });

    httpMock.expectOne(BASE).flush(METADATA);
    flushSecondary({
      fail: [`${BASE}/actions/workflows`, `${BASE}/stats/commit_activity`],
    });

    // One flaky endpoint must not discard an otherwise usable analysis.
    expect(errored).toBe(false);
    const value = snapshot as unknown as RepositorySnapshot;
    expect(value.workflows).toBeNull();
    expect(value.weeklyCommits).toBeNull();
    // What did succeed is still present.
    expect(value.tree).not.toBeNull();
    expect(value.metadata.fullName).toBe('expressjs/express');
  });

  it('fails the scan when repository metadata is unavailable', () => {
    // Metadata is the one source whose absence makes analysis meaningless.
    let error: AppError | null = null;
    service.loadSnapshot(REF).subscribe({ error: (e: AppError) => (error = e) });

    httpMock
      .expectOne(BASE)
      .flush({ message: 'Not Found' }, { status: 404, statusText: 'Not Found' });

    expect((error as unknown as AppError).kind).toBe('repository-not-found');
    // No secondary requests should have been issued; verify() enforces this.
  });

  it('cancels every in-flight request when the caller unsubscribes', () => {
    const subscription = service.loadSnapshot(REF).subscribe();
    httpMock.expectOne(BASE).flush(METADATA);

    const inFlight = httpMock.match(() => true);
    expect(inFlight.length).toBeGreaterThan(0);

    subscription.unsubscribe();
    for (const request of inFlight) {
      expect(request.cancelled).toBe(true);
    }
  });

  it('reports a missing SBOM as null rather than failing', () => {
    let sbom: unknown = 'untouched';
    service.loadSbom(REF).subscribe((value) => (sbom = value));

    httpMock
      .expectOne(`${BASE}/dependency-graph/sbom`)
      .flush({ message: 'Not Found' }, { status: 404, statusText: 'Not Found' });

    expect(sbom).toBeNull();
  });
});
