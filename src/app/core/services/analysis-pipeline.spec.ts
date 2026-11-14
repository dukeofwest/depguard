import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { RepositoryAnalysisService } from './repository-analysis.service';
import { CacheService } from './cache.service';
import type { HealthReport } from '../models/health-report.model';
import type { RepositoryRef } from '../models/repository.model';

/**
 * End-to-end analysis pipeline, with deterministic mocked responses.
 *
 * These tests assert the **final, user-visible report** rather than an intermediate
 * observable emission. That distinction is the whole point: the defect this file was
 * created for (P0-1) was invisible at the service level — `OsvApiService` behaved exactly
 * as its own test asserted — and only became wrong once the report was assembled and the
 * summary sentence was written.
 *
 * Deliberately not a live test: `analysis-pipeline.live.spec.ts` covers real APIs behind
 * `DEPGUARD_LIVE=1`.
 */

const REF: RepositoryRef = { owner: 'octocat', repo: 'demo' };
const BASE = 'https://api.github.com/repos/octocat/demo';
const BATCH_URL = 'https://api.osv.dev/v1/querybatch';

const METADATA = {
  full_name: 'octocat/demo',
  html_url: 'https://github.com/octocat/demo',
  default_branch: 'main',
  pushed_at: new Date().toISOString(),
  stargazers_count: 1,
  license: { spdx_id: 'MIT', name: 'MIT License' },
};

/** An SPDX document with one npm package at an exact version, so one OSV query follows. */
const SBOM = {
  sbom: {
    spdxVersion: 'SPDX-2.3',
    name: 'com.github.octocat/demo',
    packages: [
      {
        SPDXID: 'SPDXRef-npm-lodash-4.17.20',
        name: 'npm:lodash',
        versionInfo: '4.17.20',
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: 'pkg:npm/lodash@4.17.20',
          },
        ],
      },
    ],
  },
};

describe('analysis pipeline', () => {
  let service: RepositoryAnalysisService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), RepositoryAnalysisService],
    });
    service = TestBed.inject(RepositoryAnalysisService);
    httpMock = TestBed.inject(HttpTestingController);
    TestBed.inject(CacheService).clear();
  });

  afterEach(() => {
    try {
      httpMock.verify();
    } finally {
      TestBed.resetTestingModule();
    }
  });

  /** Runs a scan and returns the report, once every mocked exchange has been answered. */
  function analyse(options: {
    readonly sbom?: object | null;
    readonly advisoryIds?: readonly string[];
    /** Advisory ids whose detail request should fail. */
    readonly failDetails?: readonly string[];
    /** Extra blobs to place in the repository tree. */
    readonly treePaths?: readonly string[];
    /** Body to serve for a discovered lockfile, or null to 404 it. */
    readonly lockfile?: string | null;
    /** Fail the SBOM request with this status instead of serving a body. */
    readonly sbomStatus?: number;
  }): HealthReport {
    let report: HealthReport | null = null;
    service.analyse(REF).subscribe((progress) => {
      if (progress.kind === 'report') {
        report = progress.report;
      }
    });

    httpMock.expectOne(BASE).flush(METADATA);

    httpMock.expectOne(`${BASE}/git/trees/main?recursive=1`).flush({
      tree: [
        { path: 'README.md', type: 'blob', size: 10 },
        ...(options.treePaths ?? []).map((path) => ({ path, type: 'blob', size: 100 })),
      ],
      truncated: false,
    });
    httpMock
      .expectOne(`${BASE}/actions/workflows`)
      .flush({ workflows: [{ path: '.github/workflows/ci.yml', name: 'CI' }] });
    httpMock.expectOne(`${BASE}/releases/latest`).flush({ tag_name: 'v1', published_at: null });
    httpMock.expectOne(`${BASE}/contributors?per_page=1&anon=true`).flush([{ login: 'a' }]);
    httpMock.expectOne(`${BASE}/languages`).flush({ TypeScript: 1 });
    httpMock.expectOne(`${BASE}/stats/commit_activity`).flush([{ total: 2 }]);

    for (const request of httpMock.match((r) =>
      r.url.startsWith('https://raw.githubusercontent.com/'),
    )) {
      request.flush('', { status: 404, statusText: 'Not Found' });
    }

    const sbom = options.sbom === undefined ? SBOM : options.sbom;
    const sbomRequest = httpMock.expectOne(`${BASE}/dependency-graph/sbom`);
    if (options.sbomStatus !== undefined) {
      sbomRequest.flush(
        { message: 'nope' },
        {
          status: options.sbomStatus,
          statusText: 'Error',
          headers: { 'x-ratelimit-remaining': '0' },
        },
      );
    } else if (sbom === null) {
      sbomRequest.flush('', { status: 404, statusText: 'Not Found' });
    } else {
      sbomRequest.flush(sbom);
    }

    // With no dependency graph, discovery looks for a lockfile at the tree-listed paths.
    const hasInventory = options.sbomStatus === undefined && sbom !== null;
    if (!hasInventory) {
      for (;;) {
        const requests = httpMock.match((r) =>
          r.url.startsWith('https://raw.githubusercontent.com/'),
        );
        if (requests.length === 0) {
          break;
        }
        for (const request of requests) {
          if (options.lockfile === undefined || options.lockfile === null) {
            request.flush('', { status: 404, statusText: 'Not Found' });
          } else {
            request.flush(options.lockfile);
          }
        }
      }
    }

    const advisoryIds = options.advisoryIds ?? [];

    // OSV is only queried when an inventory was obtained from some source. A failed or
    // absent one short-circuits to the report, so expecting a batch would hang the test.
    const batch = httpMock.match(BATCH_URL);
    if (batch.length > 0) {
      const request = batch[0];
      if (request === undefined) {
        throw new Error('unreachable');
      }

      // One result per query, in order, sized from the request actually sent — so the
      // helper does not have to know how many packages the inventory yielded.
      const body = request.request.body as { queries?: readonly unknown[] } | null;
      const queryCount = body?.queries?.length ?? 1;
      const results = Array.from({ length: queryCount }, (_, index) =>
        index === 0 ? { vulns: advisoryIds.map((id) => ({ id })) } : {},
      );
      request.flush({ results });

      const failDetails = options.failDetails ?? [];
      for (const id of advisoryIds) {
        const detail = httpMock.expectOne(`https://api.osv.dev/v1/vulns/${id}`);
        if (failDetails.includes(id)) {
          detail.flush({}, { status: 500, statusText: 'Server Error' });
        } else {
          detail.flush({
            id,
            summary: `Summary for ${id}`,
            severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
            affected: [{ package: { ecosystem: 'npm', name: 'lodash' } }],
          });
        }
      }
    }

    const value = report as unknown as HealthReport;
    expect(value).not.toBeNull();
    return value;
  }

  /** The dependency-security category, which is where a lost advisory would hide. */
  function securityCategory(report: HealthReport) {
    const category = report.categories.find((entry) => entry.id === 'dependency-security');
    expect(category).toBeDefined();
    return category as NonNullable<typeof category>;
  }

  // ---- P0-1: a confirmed advisory must never vanish -----------------------

  it('Scenario A: reports a complete result when every advisory detail is retrieved', () => {
    const report = analyse({ advisoryIds: ['GHSA-1'] });

    expect(report.vulnerabilities.kind).toBe('completed');
    expect(
      report.vulnerabilities.kind === 'completed' && report.vulnerabilities.findings,
    ).toHaveLength(1);

    // A successful scan must not be marked partial merely because details were fetched.
    const category = securityCategory(report);
    expect(category.kind).toBe('scored');
  });

  it('Scenario B: a lost advisory detail must not produce a clean result', () => {
    const report = analyse({ advisoryIds: ['GHSA-1'], failDetails: ['GHSA-1'] });

    // The result is partial, and names what it lost.
    expect(report.vulnerabilities.kind).toBe('partial');
    if (report.vulnerabilities.kind !== 'partial') {
      throw new Error('expected a partial result');
    }
    expect(report.vulnerabilities.advisoriesUnretrieved).toEqual(['GHSA-1']);
    expect(report.vulnerabilities.reason).toContain('GHSA-1');

    // The regression that matters: the category must not claim cleanliness. This is the
    // assertion the original implementation failed — it reported "No known
    // vulnerabilities were found" for a vulnerability OSV had just confirmed.
    const category = securityCategory(report);
    if (category.kind !== 'scored') {
      throw new Error('expected a scored category');
    }
    expect(category.summary).not.toContain('No known vulnerabilities were found');
    expect(category.summary).toContain('could not be retrieved');

    // And it must cost score, rather than being silently free.
    expect(category.score).toBeLessThan(100);
    expect(category.deductions.some((d) => d.reason.includes('GHSA-1'))).toBe(true);

    // The report's own limitations must disclose it.
    expect(
      report.limitations.some(
        (limitation) =>
          limitation.scope === 'Vulnerability query' && limitation.detail.includes('GHSA-1'),
      ),
    ).toBe(true);
  });

  it('Scenario C: keeps the retrieved advisory and discloses the lost one', () => {
    const report = analyse({
      advisoryIds: ['GHSA-1', 'GHSA-2'],
      failDetails: ['GHSA-2'],
    });

    expect(report.vulnerabilities.kind).toBe('partial');
    if (report.vulnerabilities.kind !== 'partial') {
      throw new Error('expected a partial result');
    }

    // §10.5: a partial result must stay useful. The retrieved advisory survives.
    expect(report.vulnerabilities.findings).toHaveLength(1);
    expect(report.vulnerabilities.findings[0]?.advisoryIds).toContain('GHSA-1');
    expect(report.vulnerabilities.advisoriesUnretrieved).toEqual(['GHSA-2']);

    const category = securityCategory(report);
    if (category.kind !== 'scored') {
      throw new Error('expected a scored category');
    }
    // Both the described finding and the undescribed one are deducted for.
    expect(category.deductions.some((d) => d.reason.includes('GHSA-2'))).toBe(true);
    expect(category.summary).toContain('could not be retrieved');
  });

  it('every advisory detail failing still reports the advisories, not a clean scan', () => {
    const report = analyse({
      advisoryIds: ['GHSA-1', 'GHSA-2'],
      failDetails: ['GHSA-1', 'GHSA-2'],
    });

    expect(report.vulnerabilities.kind).toBe('partial');
    if (report.vulnerabilities.kind !== 'partial') {
      throw new Error('expected a partial result');
    }
    expect(report.vulnerabilities.findings).toHaveLength(0);
    expect(report.vulnerabilities.advisoriesUnretrieved).toEqual(['GHSA-1', 'GHSA-2']);

    const category = securityCategory(report);
    if (category.kind !== 'scored') {
      throw new Error('expected a scored category');
    }
    expect(category.summary).not.toContain('No known vulnerabilities were found');
    expect(category.score).toBeLessThan(100);
  });

  // ---- P1-1: the lockfile fallback, end to end ---------------------------

  describe('dependency discovery fallback', () => {
    const LOCKFILE = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { lodash: '^4.17.20' } },
        'node_modules/lodash': { version: '4.17.20' },
        'node_modules/ms': { version: '2.1.3', dev: true },
      },
    });

    it('builds an inventory from the repository when GitHub has no graph', () => {
      const report = analyse({
        sbom: null,
        treePaths: ['package-lock.json'],
        lockfile: LOCKFILE,
        advisoryIds: [],
      });

      // Before this existed, the same scan reported "No dependency inventory was
      // available" for a repository with a complete lockfile in it.
      expect(report.dependencyCoverage).not.toBeNull();
      expect(report.dependencyCoverage?.totalPackages).toBe(2);
      expect(report.dependencyCoverage?.inventorySource).toBe('package-lock.json');
      expect(report.dependencies).toHaveLength(2);

      // Both dependency categories now score instead of reporting insufficient data.
      const security = securityCategory(report);
      expect(security.kind).toBe('scored');
      expect(report.categories.find((c) => c.id === 'dependency-health')?.kind).toBe('scored');
    });

    it('states that the inventory came from the repository, not from GitHub', () => {
      const report = analyse({
        sbom: null,
        treePaths: ['package-lock.json'],
        lockfile: LOCKFILE,
        advisoryIds: [],
      });

      // A reader who is not told the source could reasonably assume GitHub's graph
      // agreed with this inventory.
      const limitation = report.limitations.find((l) => l.detail.includes('package-lock.json'));
      expect(limitation).toBeDefined();
      expect(limitation?.detail).toContain('no dependency graph');
    });

    it('still finds vulnerabilities in a discovered inventory', () => {
      const report = analyse({
        sbom: null,
        treePaths: ['package-lock.json'],
        lockfile: LOCKFILE,
        advisoryIds: ['GHSA-lodash'],
      });

      expect(report.vulnerabilities.kind).toBe('completed');
      expect(
        report.vulnerabilities.kind === 'completed' && report.vulnerabilities.findings,
      ).toHaveLength(1);
    });

    it('reports no inventory honestly when there is no lockfile either', () => {
      const report = analyse({ sbom: null, advisoryIds: [] });

      expect(report.dependencyCoverage).toBeNull();
      expect(report.vulnerabilities.kind).toBe('unavailable');
      if (report.vulnerabilities.kind !== 'unavailable') return;

      // Both halves of the truth: GitHub had no graph, AND no lockfile was found.
      expect(report.vulnerabilities.reason).toContain('no dependency graph');
      expect(report.vulnerabilities.reason).toContain('No supported dependency lockfile');
    });

    // ---- P1-2: a transport failure is not a confirmed absence ------------

    it('never presents a rate limit as proof that there are no dependencies', () => {
      const report = analyse({ sbomStatus: 429, treePaths: ['package-lock.json'], lockfile: null });

      expect(report.vulnerabilities.kind).toBe('unavailable');
      if (report.vulnerabilities.kind !== 'unavailable') return;

      // The old behaviour flattened every transport failure to null and rendered it as
      // "GitHub has no dependency graph for this repository" — a claim about GitHub's
      // state derived from a swallowed exception.
      expect(report.vulnerabilities.reason).not.toContain('has no dependency graph');
      expect(report.dependencyCoverage).toBeNull();
    });

    it('falls back to the lockfile even when the SBOM request failed outright', () => {
      const report = analyse({
        sbomStatus: 403,
        treePaths: ['package-lock.json'],
        lockfile: LOCKFILE,
        advisoryIds: [],
      });

      // An API failure must not cost the user their inventory when the repository
      // carries one.
      expect(report.dependencyCoverage?.totalPackages).toBe(2);
    });

    it('reports a malformed lockfile as unreadable, not as an empty inventory', () => {
      const report = analyse({
        sbom: null,
        treePaths: ['package-lock.json'],
        lockfile: '{ not json',
      });

      expect(report.dependencyCoverage).toBeNull();
      expect(report.vulnerabilities.kind).toBe('unavailable');
      if (report.vulnerabilities.kind !== 'unavailable') return;
      expect(report.vulnerabilities.reason).toContain('A dependency inventory may well exist');
    });

    it('spends no additional GitHub API quota', () => {
      let report: HealthReport | null = null;
      service.analyse(REF).subscribe((progress) => {
        if (progress.kind === 'report') report = progress.report;
      });

      httpMock.expectOne(BASE).flush(METADATA);
      const quota: string[] = [BASE];

      // The hosts interleave: the snapshot's forkJoin waits on raw file contents before
      // completing, and only then is the SBOM requested. So drain whatever is pending,
      // whichever host it belongs to, until the scan settles.
      for (;;) {
        const requests = httpMock.match(() => true);
        if (requests.length === 0) {
          break;
        }

        for (const request of requests) {
          const url = request.request.url;

          if (url.startsWith('https://api.github.com/')) {
            quota.push(url);
            if (url.includes('dependency-graph/sbom')) {
              request.flush('', { status: 404, statusText: 'Not Found' });
            } else if (url.includes('git/trees')) {
              request.flush({
                tree: [{ path: 'package-lock.json', type: 'blob', size: 100 }],
                truncated: false,
              });
            } else {
              request.flush({});
            }
            continue;
          }

          if (url.endsWith('/package-lock.json')) {
            request.flush(LOCKFILE);
          } else if (url.startsWith('https://raw.githubusercontent.com/')) {
            request.flush('', { status: 404, statusText: 'Not Found' });
          } else {
            // OSV: no matches, so no detail requests follow.
            request.flush({ results: [{}, {}] });
          }
        }
      }

      expect(report).not.toBeNull();
      // The documented budget: 8 quota-consuming requests per scan. Discovery adds none,
      // because it reuses the tree and fetches from the quota-free raw host.
      expect(quota).toHaveLength(8);
    });
  });

  it('Scenario D: no matches is a clean result, not a partial one', () => {
    const report = analyse({ advisoryIds: [] });

    // Nothing was lost, so nothing may be reported as incomplete.
    expect(report.vulnerabilities.kind).toBe('completed');

    const category = securityCategory(report);
    if (category.kind !== 'scored') {
      throw new Error('expected a scored category');
    }
    expect(category.summary).toContain('No known vulnerabilities were found');
    expect(category.score).toBe(100);
  });
});
