import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Subject } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { GithubApiService } from './api/github-api.service';
import { CacheService } from './services/cache.service';
import { RateLimitService } from './services/rate-limit.service';
import { ReportExportService } from './services/report-export.service';
import { RepositoryAnalysisService } from './services/repository-analysis.service';
import { ScanStore } from './state/scan.store';
import { RESPONSE_LIMITS } from './config/api.config';
import type { AppError } from './models/api-error.model';
import type { RepositoryRef } from './models/repository.model';
import type { HealthReport } from './models/health-report.model';
import type { AnalysisProgress } from './services/repository-analysis.service';

const REF: RepositoryRef = { owner: 'expressjs', repo: 'express' };
const REPO_URL = 'https://api.github.com/repos/expressjs/express';

/**
 * Timeouts, cancellation, races and export handling
 * (MANDATORY_SECURITY_REQUIREMENT §C15, §D, §H).
 *
 * These are the availability and correctness properties that a hostile or merely broken
 * third party can attack without sending a single malicious byte: by answering slowly,
 * by answering late, or by answering a request the user already abandoned.
 */
describe('request timeouts', () => {
  let service: GithubApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    vi.useFakeTimers();
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
    TestBed.inject(CacheService).clear();
  });

  afterEach(() => {
    vi.useRealTimers();
    TestBed.resetTestingModule();
  });

  it('gives up on a request that never answers, rather than hanging indefinitely', () => {
    let error: AppError | null = null;
    service.getRepository(REF).subscribe({
      error: (e: AppError) => {
        error = e;
      },
    });

    // The request is made and simply never responded to - the behaviour of a stalled
    // connection, which no HTTP status code represents.
    httpMock.expectOne(REPO_URL);

    // Nothing has failed yet: the request is simply outstanding.
    vi.advanceTimersByTime(RESPONSE_LIMITS.requestTimeoutMs - 1);
    expect(error).toBeNull();

    // A timeout is retryable, so the first one schedules a retry rather than failing the
    // call. Advancing well past the full retry budget - two retries with exponential
    // backoff, each able to time out again - is what settles it.
    vi.advanceTimersByTime(RESPONSE_LIMITS.requestTimeoutMs * 4);
    expect(error).not.toBeNull();

    // The user-facing outcome must be a typed, user-safe error, not a raw timeout.
    const settled = error as AppError | null;
    expect(settled?.kind).toBe('network');
    expect(settled?.message).not.toContain('TimeoutError');
  });

  it('bounds every endpoint with the same timeout, not just the large ones', () => {
    // A slow /languages response must not keep a scan alive forever either.
    let errored = false;
    service.getLanguages(REF).subscribe({
      error: () => {
        errored = true;
      },
    });
    httpMock.expectOne(`${REPO_URL}/languages`);
    vi.advanceTimersByTime(RESPONSE_LIMITS.requestTimeoutMs * 4);
    expect(errored).toBe(true);
  });
});

describe('cancellation and races', () => {
  let store: ScanStore;
  let analysis: { analyse: ReturnType<typeof vi.fn> };
  let subjects: Subject<AnalysisProgress>[];

  beforeEach(() => {
    subjects = [];
    analysis = {
      analyse: vi.fn(() => {
        const subject = new Subject<AnalysisProgress>();
        subjects.push(subject);
        return subject.asObservable();
      }),
    };

    TestBed.configureTestingModule({
      providers: [
        { provide: RepositoryAnalysisService, useValue: analysis },
        RateLimitService,
        ScanStore,
      ],
    });
    store = TestBed.inject(ScanStore);
  });

  afterEach(() => {
    TestBed.resetTestingModule();
  });

  function progress(report: HealthReport): AnalysisProgress {
    return { kind: 'report', report };
  }

  it('discards a result that arrives after the scan was cancelled', () => {
    store.start('https://github.com/expressjs/express');
    expect(store.isRunning()).toBe(true);

    store.cancel();
    expect(store.current().kind).toBe('cancelled');

    // The network does not know the user clicked cancel. A response in flight still
    // arrives, and must not repopulate the page the user has walked away from.
    subjects[0]?.next(progress({ overall: { kind: 'scored' } } as unknown as HealthReport));
    subjects[0]?.complete();

    expect(store.current().kind).toBe('cancelled');
    expect(store.report()).toBeNull();
  });

  it('discards an error that arrives after cancellation', () => {
    store.start('https://github.com/expressjs/express');
    store.cancel();

    subjects[0]?.error({ kind: 'network', message: 'too late' });

    expect(store.current().kind).toBe('cancelled');
    expect(store.error()).toBeNull();
  });

  it('ignores the first scan entirely when a second is started before it finishes', () => {
    // The race that matters: a user who pastes a second repository while the first is
    // still running must never see the first repository's report attributed to the
    // second, which would be a false report about the wrong project.
    store.start('https://github.com/expressjs/express');
    store.start('https://github.com/npm/cli');

    expect(subjects.length).toBe(2);

    const stale = { repository: { ref: REF } } as unknown as HealthReport;
    subjects[0]?.next(progress(stale));
    subjects[0]?.complete();

    const state = store.current();
    expect(state.kind).toBe('running');
    if (state.kind === 'running') {
      expect(state.ref).toEqual({ owner: 'npm', repo: 'cli' });
    }
    expect(store.report()).toBeNull();
  });

  it('accepts the result of the scan that is actually current', () => {
    store.start('https://github.com/expressjs/express');
    store.start('https://github.com/npm/cli');

    const fresh = { repository: { ref: { owner: 'npm', repo: 'cli' } } } as unknown as HealthReport;
    subjects[1]?.next(progress(fresh));
    subjects[1]?.complete();

    expect(store.current().kind).toBe('completed');
    expect(store.report()).toBe(fresh);
  });

  it('unsubscribes from the superseded scan, so its requests stop', () => {
    store.start('https://github.com/expressjs/express');
    expect(subjects[0]?.observed).toBe(true);
    store.start('https://github.com/npm/cli');
    // An abandoned scan must release its in-flight requests rather than continuing to
    // spend the hourly budget on a result nobody will see.
    expect(subjects[0]?.observed).toBe(false);
  });

  it('refuses a scan whose URL does not validate, without starting any request', () => {
    store.start('https://evil.example.com/owner/repo');
    expect(analysis.analyse).not.toHaveBeenCalled();
    expect(store.current().kind).toBe('failed');
  });
});

describe('report export', () => {
  let exporter: ReportExportService;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [ReportExportService] });
    exporter = TestBed.inject(ReportExportService);
  });

  afterEach(() => {
    TestBed.resetTestingModule();
  });

  function reportWith(value: string): HealthReport {
    return {
      schemaVersion: '1.0.0',
      generatedAt: '2026-11-13T00:00:00.000Z',
      repository: {
        ref: { owner: value, repo: value },
        metadata: { description: value, fullName: value },
      },
      summary: value,
    } as unknown as HealthReport;
  }

  it('escapes hostile content so the export cannot be reinterpreted as markup', () => {
    const payloads = [
      '<script>alert(1)</script>',
      '</script><script>alert(1)</script>',
      '"><img src=x onerror=alert(1)>',
      '\u2028\u2029',
      '\u0000',
    ];

    for (const payload of payloads) {
      const json = exporter.serialise(reportWith(payload));
      // Valid JSON in, valid JSON out - the export must survive a round trip.
      expect(() => JSON.parse(json), payload).not.toThrow();
      // The payload survives a round trip but never appears as live markup in the file.
      expect(json, payload).not.toContain('<script>');
      expect(json, payload).not.toContain('</script>');
      expect(json, payload).not.toContain('<img');
    }
  });

  it('round-trips the content faithfully, since an export must not alter findings', () => {
    const payload = '<script>alert(1)</script>';
    const parsed = JSON.parse(exporter.serialise(reportWith(payload))) as {
      summary: string;
    };
    expect(parsed.summary).toBe(payload);
  });

  it('produces a file name that cannot escape its directory', () => {
    const report = reportWith('x');
    const hostile = {
      ...report,
      repository: { ref: { owner: '../../etc', repo: '..\\..\\windows' } },
      generatedAt: '2026-11-13T00:00:00.000Z',
    } as unknown as HealthReport;

    const name = exporter.fileName(hostile);
    expect(name).not.toContain('/');
    expect(name).not.toContain('\\');
    expect(name).not.toContain('..');
    expect(name.endsWith('.json')).toBe(true);
  });

  it('carries no credential-shaped value, because none exists to carry', () => {
    // DepGuard holds no credentials (§9.1), so this asserts the structural property
    // rather than a redaction step that could be forgotten.
    const json = exporter.serialise(reportWith('express'));
    for (const pattern of [/gh[pousr]_[A-Za-z0-9]{16,}/, /authorization/i, /bearer /i]) {
      expect(pattern.test(json), String(pattern)).toBe(false);
    }
  });

  it('serialises a report containing an over-long string without stalling', () => {
    const started = performance.now();
    exporter.serialise(reportWith('x'.repeat(100_000)));
    expect(performance.now() - started).toBeLessThan(500);
  });
});

describe('destination allowlist', () => {
  let service: GithubApiService;
  let httpMock: HttpTestingController;

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
    TestBed.inject(CacheService).clear();
  });

  afterEach(() => {
    httpMock.verify();
    TestBed.resetTestingModule();
  });

  it('refuses a raw-content path that tries to leave the repository', () => {
    // The path argument comes from a fixed allowlist, never from repository content. This
    // asserts that even if that changed, traversal could not reach another repository.
    service.getRawFile(REF, 'main', '../../../other/repo/secrets').subscribe({
      next: () => undefined,
      error: () => undefined,
    });

    const requests = httpMock.match(() => true);
    for (const request of requests) {
      expect(request.request.url).toMatch(/^https:\/\/raw\.githubusercontent\.com\//);
      expect(request.request.url).not.toContain('..');
      request.flush(null, { status: 404, statusText: 'Not Found' });
    }
  });

  it('sends every request to one of the three approved origins', () => {
    const calls = [
      () => service.getRepository(REF),
      () => service.getTree(REF, 'main'),
      () => service.getWorkflows(REF),
      () => service.getLatestRelease(REF),
      () => service.getLanguages(REF),
      () => service.getWeeklyCommits(REF),
      () => service.getContributorCount(REF),
      () => service.getSbom(REF),
    ];

    for (const call of calls) {
      call().subscribe({ next: () => undefined, error: () => undefined });
    }

    const approved = [
      'https://api.github.com/',
      'https://raw.githubusercontent.com/',
      'https://api.osv.dev/',
    ];
    const requests = httpMock.match(() => true);
    expect(requests.length).toBeGreaterThan(0);
    for (const request of requests) {
      expect(
        approved.some((origin) => request.request.url.startsWith(origin)),
        request.request.url,
      ).toBe(true);
      request.flush(null, { status: 404, statusText: 'Not Found' });
    }
  });
});
