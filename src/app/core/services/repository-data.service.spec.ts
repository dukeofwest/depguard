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

    // Drained in stages, because the tree is now fetched before the other sources: the
    // workflow files whose contents the CodeQL check reads are discovered from it.
    // That changes the ordering, not the count.
    let quotaRequests = 0;
    for (;;) {
      const pending = httpMock.match((r) => r.url.startsWith('https://api.github.com/'));
      if (pending.length === 0) {
        break;
      }
      quotaRequests += pending.length;
      for (const request of pending) {
        request.flush(
          request.request.url.includes('git/trees') ? { tree: [], truncated: false } : {},
        );
      }
      // Raw content is drained alongside, since the snapshot waits on it.
      for (const request of httpMock.match((r) =>
        r.url.startsWith('https://raw.githubusercontent.com/'),
      )) {
        request.flush('', { status: 404, statusText: 'Not Found' });
      }
    }

    // 6 secondary + 1 metadata = 7 quota-consuming requests for a snapshot, plus the
    // SBOM fetched separately = 8 per scan. ADR-0004 budgeted 9 because it included
    // `/community/profile`; the recursive tree plus free raw.githubusercontent.com
    // content covers the same signals for one request less.
    expect(quotaRequests).toBe(6);
  });

  // ---- P1-2 / P1-6: why a source is absent, not merely that it is --------

  it('records why an optional source was unavailable', () => {
    let snapshot: RepositorySnapshot | null = null;
    service.loadSnapshot(REF).subscribe((value) => (snapshot = value));

    httpMock.expectOne(BASE).flush(METADATA);
    // A 403 that is not a rate limit: access denied, which is not the same thing as the
    // resource not existing. Flattening both to null is what let the report assert
    // "GitHub has no dependency graph for this repository" after a transport failure.
    flushSecondary({ fail: [`${BASE}/actions/workflows`] });

    const value = snapshot as unknown as RepositorySnapshot;
    expect(value.workflows).toBeNull();
    expect(value.sourceStates['workflows']).toEqual({
      kind: 'unavailable',
      reason: 'access-denied',
      detail: expect.any(String),
    });
    // A source that succeeded carries no state at all.
    expect(value.sourceStates['tree']).toBeUndefined();
  });

  it('distinguishes pending commit statistics from a failure', () => {
    let snapshot: RepositorySnapshot | null = null;
    service.loadSnapshot(REF).subscribe((value) => (snapshot = value));

    httpMock.expectOne(BASE).flush(METADATA);

    httpMock
      .expectOne(`${BASE}/git/trees/master?recursive=1`)
      .flush({ tree: [], truncated: false });
    httpMock.expectOne(`${BASE}/actions/workflows`).flush({ workflows: [] });
    httpMock.expectOne(`${BASE}/releases/latest`).flush({ tag_name: 'v1' });
    httpMock.expectOne(`${BASE}/contributors?per_page=1&anon=true`).flush([{ login: 'a' }]);
    httpMock.expectOne(`${BASE}/languages`).flush({});
    // 202 Accepted: GitHub is computing the statistics, which is "not yet", not "none".
    httpMock
      .expectOne(`${BASE}/stats/commit_activity`)
      .flush(null, { status: 202, statusText: 'Accepted' });
    for (const request of httpMock.match((r) =>
      r.url.startsWith('https://raw.githubusercontent.com/'),
    )) {
      request.flush('', { status: 404, statusText: 'Not Found' });
    }

    const value = snapshot as unknown as RepositorySnapshot;
    expect(value.weeklyCommits).toBeNull();
    expect(value.sourceStates['commit-activity']?.kind).toBe('unavailable');
    expect(
      value.sourceStates['commit-activity']?.kind === 'unavailable' &&
        value.sourceStates['commit-activity'].reason,
    ).toBe('pending');
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

  it('reports a missing SBOM as not-found rather than failing', () => {
    let sbom: { body: unknown; state: { kind: string; reason?: string } } | null = null;
    service.loadSbom(REF).subscribe((value) => (sbom = value));

    httpMock
      .expectOne(`${BASE}/dependency-graph/sbom`)
      .flush({ message: 'Not Found' }, { status: 404, statusText: 'Not Found' });

    const value = sbom as unknown as { body: unknown; state: { kind: string; reason?: string } };
    expect(value.body).toBeNull();
    // A 404 is the one case where "GitHub has no dependency graph" is a fair statement.
    expect(value.state.reason).toBe('not-found');
  });

  it('distinguishes a rate-limited SBOM request from a missing dependency graph', () => {
    let sbom: { body: unknown; state: { kind: string; reason?: string } } | null = null;
    service.loadSbom(REF).subscribe((value) => (sbom = value));

    httpMock.expectOne(`${BASE}/dependency-graph/sbom`).flush(
      { message: 'rate limited' },
      {
        status: 403,
        statusText: 'Forbidden',
        headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '9999999999' },
      },
    );

    const value = sbom as unknown as { body: unknown; state: { kind: string; reason?: string } };
    expect(value.body).toBeNull();
    // This is the defect P1-2 names: flattening it to null made the report say the
    // repository has no dependency graph, which is a claim nothing established.
    expect(value.state.reason).toBe('rate-limited');
  });
});
