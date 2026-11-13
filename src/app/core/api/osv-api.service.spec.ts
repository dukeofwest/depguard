import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { OsvApiService, type OsvQueryResult } from './osv-api.service';
import { OSV_LIMITS } from '../config/api.config';
import type { NormalizedPackage } from '../models/dependency.model';

const BATCH_URL = 'https://api.osv.dev/v1/querybatch';

function pkg(
  name: string,
  version: string,
  overrides: Partial<NormalizedPackage> = {},
): NormalizedPackage {
  return {
    key: `npm|${name}|${version}`,
    name,
    purlType: 'npm',
    ecosystem: 'npm',
    declaredVersion: version,
    versionKind: 'exact',
    relationship: 'unknown',
    licenseConcluded: null,
    skipReason: null,
    ...overrides,
  };
}

describe('OsvApiService', () => {
  let service: OsvApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), OsvApiService],
    });
    service = TestBed.inject(OsvApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    try {
      httpMock.verify();
    } finally {
      TestBed.resetTestingModule();
    }
  });

  it('queries packages and fetches advisory details', () => {
    let result: OsvQueryResult | null = null;
    service.queryPackages([pkg('lodash', '4.17.15')]).subscribe((value) => (result = value));

    const batch = httpMock.expectOne(BATCH_URL);
    expect(batch.request.method).toBe('POST');
    expect(batch.request.body).toEqual({
      queries: [{ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.15' }],
    });

    batch.flush({ results: [{ vulns: [{ id: 'GHSA-1' }, { id: 'GHSA-2' }] }] });

    // Details are fetched per unique advisory, not per package.
    httpMock.expectOne('https://api.osv.dev/v1/vulns/GHSA-1').flush({ id: 'GHSA-1' });
    httpMock.expectOne('https://api.osv.dev/v1/vulns/GHSA-2').flush({ id: 'GHSA-2' });

    const value = result as unknown as OsvQueryResult;
    expect(value.records).toHaveLength(2);
    expect(value.matches).toHaveLength(2);
    expect(value.packagesChecked).toBe(1);
    expect(value.packagesFailed).toBe(0);
  });

  it('never sends a package whose version is not exact (ADR-0002)', () => {
    // The hard rule: OSV silently returns wrong results for a range, so the service
    // refuses them even if a caller passes them in.
    let result: OsvQueryResult | null = null;
    service
      .queryPackages([
        pkg('lodash', '^4.17.15', { versionKind: 'range' }),
        pkg('left-pad', '', { versionKind: 'missing', declaredVersion: null }),
        pkg('actions/checkout', '4', { ecosystem: null, purlType: 'githubactions' }),
      ])
      .subscribe((value) => (result = value));

    // No request is made at all; verify() in afterEach enforces it.
    const value = result as unknown as OsvQueryResult;
    expect(value.packagesChecked).toBe(0);
    expect(value.records).toEqual([]);
  });

  it('deduplicates advisory detail requests across packages', () => {
    let result: OsvQueryResult | null = null;
    service
      .queryPackages([pkg('a', '1.0.0'), pkg('b', '2.0.0')])
      .subscribe((value) => (result = value));

    // Both packages are affected by the same advisory.
    httpMock
      .expectOne(BATCH_URL)
      .flush({ results: [{ vulns: [{ id: 'GHSA-X' }] }, { vulns: [{ id: 'GHSA-X' }] }] });

    // One detail request, not two.
    httpMock.expectOne('https://api.osv.dev/v1/vulns/GHSA-X').flush({ id: 'GHSA-X' });

    const value = result as unknown as OsvQueryResult;
    expect(value.records).toHaveLength(1);
    // Both package matches are retained, so the engine knows what each advisory affects.
    expect(value.matches).toHaveLength(2);
  });

  it('chunks large inventories within the measured 1,000-query cap', () => {
    const packages = Array.from({ length: 1200 }, (_, i) => pkg(`pkg-${i}`, '1.0.0'));
    service.queryPackages(packages).subscribe();

    // Chunks are sequential, so only the first is in flight initially.
    const first = httpMock.expectOne(BATCH_URL);
    const firstBody = first.request.body as { queries: unknown[] };
    expect(firstBody.queries.length).toBe(OSV_LIMITS.chunkSize);
    expect(firstBody.queries.length).toBeLessThanOrEqual(OSV_LIMITS.maxQueriesPerBatch);
    first.flush({ results: firstBody.queries.map(() => ({})) });

    const second = httpMock.expectOne(BATCH_URL);
    const secondBody = second.request.body as { queries: unknown[] };
    second.flush({ results: secondBody.queries.map(() => ({})) });

    const third = httpMock.expectOne(BATCH_URL);
    const thirdBody = third.request.body as { queries: unknown[] };
    expect(thirdBody.queries.length).toBe(200);
    third.flush({ results: thirdBody.queries.map(() => ({})) });
  });

  it('reports a partial result when a chunk fails, rather than failing the scan', () => {
    const packages = Array.from({ length: 600 }, (_, i) => pkg(`pkg-${i}`, '1.0.0'));
    let result: OsvQueryResult | null = null;
    let errored = false;
    service.queryPackages(packages).subscribe({
      next: (value) => (result = value),
      error: () => (errored = true),
    });

    httpMock.expectOne(BATCH_URL).flush({ message: 'boom' }, { status: 500, statusText: 'Error' });

    const second = httpMock.expectOne(BATCH_URL);
    const body = second.request.body as { queries: unknown[] };
    second.flush({ results: body.queries.map(() => ({ vulns: [{ id: 'GHSA-OK' }] })) });

    httpMock.expectOne('https://api.osv.dev/v1/vulns/GHSA-OK').flush({ id: 'GHSA-OK' });

    expect(errored).toBe(false);
    const value = result as unknown as OsvQueryResult;
    // The failure is reported, not hidden: 500 checked, 500 failed.
    expect(value.packagesFailed).toBe(500);
    expect(value.packagesChecked).toBe(100);
    expect(value.failureReason).toContain('temporarily unavailable');
  });

  it('ignores a misaligned batch response rather than attributing advisories wrongly', () => {
    // Results are positional. A length mismatch means we cannot tell which advisory
    // belongs to which package, and a wrong attribution is worse than none.
    let result: OsvQueryResult | null = null;
    service
      .queryPackages([pkg('a', '1.0.0'), pkg('b', '2.0.0')])
      .subscribe((value) => (result = value));

    httpMock.expectOne(BATCH_URL).flush({ results: [{ vulns: [{ id: 'GHSA-1' }] }] });

    expect((result as unknown as OsvQueryResult).matches).toEqual([]);
  });

  it('survives malformed batch responses', () => {
    const malformed: readonly unknown[] = [null, 'string', 42, {}, { results: 'nope' }];
    for (const body of malformed) {
      let result: OsvQueryResult | null = null;
      service.queryPackages([pkg('a', '1.0.0')]).subscribe((value) => (result = value));
      httpMock.expectOne(BATCH_URL).flush(body as object);
      expect((result as unknown as OsvQueryResult).matches).toEqual([]);
    }
  });

  it('continues when a single advisory detail request fails', () => {
    let result: OsvQueryResult | null = null;
    service.queryPackages([pkg('a', '1.0.0')]).subscribe((value) => (result = value));

    httpMock
      .expectOne(BATCH_URL)
      .flush({ results: [{ vulns: [{ id: 'GHSA-1' }, { id: 'GHSA-2' }] }] });

    httpMock.expectOne('https://api.osv.dev/v1/vulns/GHSA-1').flush({ id: 'GHSA-1' });
    httpMock
      .expectOne('https://api.osv.dev/v1/vulns/GHSA-2')
      .flush({}, { status: 500, statusText: 'Error' });

    // One lost record must not discard the other.
    expect((result as unknown as OsvQueryResult).records).toHaveLength(1);
  });

  it('caps the number of advisory detail requests', () => {
    const ids = Array.from({ length: OSV_LIMITS.maxDetailRequests + 50 }, (_, i) => ({
      id: `GHSA-${String(i).padStart(4, '0')}`,
    }));

    let result: OsvQueryResult | null = null;
    service.queryPackages([pkg('a', '1.0.0')]).subscribe((value) => (result = value));
    httpMock.expectOne(BATCH_URL).flush({ results: [{ vulns: ids }] });

    // Detail requests run with bounded concurrency, so only a few are ever in flight at
    // once. Drain in waves, asserting the limit is respected and counting the total.
    let total = 0;
    let wave = httpMock.match((r) => r.url.includes('/v1/vulns/'));
    while (wave.length > 0) {
      expect(wave.length).toBeLessThanOrEqual(OSV_LIMITS.detailConcurrency);
      total += wave.length;
      for (const request of wave) {
        request.flush({ id: 'x' });
      }
      wave = httpMock.match((r) => r.url.includes('/v1/vulns/'));
    }

    expect(total).toBe(OSV_LIMITS.maxDetailRequests);

    const value = result as unknown as OsvQueryResult;
    expect(value.advisoriesOmitted).toBe(50);
    // The omission is disclosed rather than silently truncated.
    expect(value.failureReason).toContain('not retrieved');
  });

  it('cancels in-flight requests when the caller unsubscribes', () => {
    const subscription = service.queryPackages([pkg('a', '1.0.0')]).subscribe();
    const batch = httpMock.expectOne(BATCH_URL);
    expect(batch.cancelled).toBe(false);

    subscription.unsubscribe();
    expect(batch.cancelled).toBe(true);
  });

  it('makes no request for an empty package list', () => {
    let result: OsvQueryResult | null = null;
    service.queryPackages([]).subscribe((value) => (result = value));
    expect((result as unknown as OsvQueryResult).packagesChecked).toBe(0);
  });
});
