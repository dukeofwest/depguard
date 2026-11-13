import { describe, expect, it } from 'vitest';

import { parseSbom, queryablePackages } from './sbom/spdx-parser';
import { processVulnerabilities } from './security/vulnerability-processor';
import { buildReport } from './report/report-builder';
import type { RepositorySnapshot } from '../core/models/repository.model';

/**
 * The engine takes its package cap as an argument rather than reading application
 * configuration, so the test supplies its own value. Importing `RESPONSE_LIMITS` here
 * would give an engine file a runtime dependency on `core/`, which the purity rules
 * reject — and which ESLint caught when this test first tried it.
 *
 * Kept in step with `MAX_PACKAGES` in api.config.ts.
 */
const MAX_PACKAGES = 20000;

/**
 * Performance and resource limits (§12).
 *
 * Phase 0 measured the largest real SBOM — `npm/cli`, 1.1 MB and 1,208 packages — parsing
 * in 2.8 ms in a browser, which is why no Web Worker was introduced. These tests cover an
 * order of magnitude beyond that, and assert that the documented caps actually bound the
 * work rather than merely being declared.
 *
 * Timing thresholds are deliberately generous: this is a guard against pathological
 * behaviour such as quadratic matching, not a benchmark, and a tight bound would make the
 * suite flaky on a loaded machine.
 */

function syntheticSbom(packageCount: number): unknown {
  return {
    sbom: {
      spdxVersion: 'SPDX-2.3',
      name: 'synthetic',
      packages: Array.from({ length: packageCount }, (_, i) => ({
        name: `package-${i}`,
        SPDXID: `SPDXRef-npm-package-${i}`,
        versionInfo: i % 3 === 0 ? `^1.0.${i % 50}` : `1.0.${i % 50}`,
        licenseConcluded: 'MIT',
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: `pkg:npm/package-${i}@${i % 3 === 0 ? '%5E' : ''}1.0.${i % 50}`,
          },
        ],
      })),
      relationships: Array.from({ length: packageCount }, (_, i) => ({
        spdxElementId: 'SPDXRef-DOCUMENT',
        relatedSpdxElement: `SPDXRef-npm-package-${i}`,
        relationshipType: 'DEPENDS_ON',
      })),
    },
  };
}

function snapshot(): RepositorySnapshot {
  return {
    metadata: {
      ref: { owner: 'big', repo: 'repo' },
      fullName: 'big/repo',
      description: null,
      htmlUrl: 'https://github.com/big/repo',
      defaultBranch: 'main',
      isArchived: false,
      isDisabled: false,
      isFork: false,
      visibility: 'public',
      stars: 0,
      forks: 0,
      openIssues: 0,
      sizeKb: 0,
      primaryLanguage: null,
      licenseSpdxId: null,
      licenseName: null,
      topics: [],
      createdAt: null,
      updatedAt: null,
      pushedAt: '2026-11-01T00:00:00Z',
    },
    tree: { entries: [], truncated: false },
    workflows: [],
    latestRelease: null,
    contributorCount: null,
    languages: null,
    weeklyCommits: null,
    fileContents: {},
    retrievedAt: '2026-11-13T12:00:00.000Z',
  };
}

describe('performance and resource limits (§12)', () => {
  it('parses 20,000 packages well within one frame budget per 1,000', () => {
    const sbom = syntheticSbom(20000);

    const start = performance.now();
    const result = parseSbom(sbom, MAX_PACKAGES);
    const elapsed = performance.now() - start;

    expect(result.kind).toBe('parsed');
    if (result.kind !== 'parsed') return;

    expect(result.coverage.totalPackages).toBe(20000);
    // ~16x the largest real SBOM observed. A quadratic implementation would blow this.
    expect(elapsed, `parse took ${elapsed.toFixed(0)}ms`).toBeLessThan(3000);
  });

  it('enforces the package cap on an oversized inventory', () => {
    const sbom = syntheticSbom(MAX_PACKAGES + 5000);
    const result = parseSbom(sbom, MAX_PACKAGES);

    if (result.kind !== 'parsed') throw new Error('expected a parsed SBOM');
    // Bounded memory: the excess is dropped rather than held.
    expect(result.coverage.totalPackages).toBe(MAX_PACKAGES);
  });

  it('matches thousands of advisories against thousands of packages without blowing up', () => {
    const sbom = syntheticSbom(5000);
    const parsed = parseSbom(sbom, MAX_PACKAGES);
    if (parsed.kind !== 'parsed') throw new Error('expected a parsed SBOM');

    const packages = queryablePackages(parsed.packages);
    expect(packages.length).toBeGreaterThan(3000);

    // 400 advisories, each affecting 5 packages: the realistic worst case bounded by
    // OSV_LIMITS.maxDetailRequests.
    const records = Array.from({ length: 400 }, (_, i) => ({
      id: `GHSA-${i}`,
      summary: `Advisory ${i}`,
      database_specific: { severity: 'HIGH' },
      affected: [{ package: { name: `package-${i}` }, ranges: [{ events: [{ fixed: '2.0.0' }] }] }],
    }));
    const matches = records.flatMap((record, i) =>
      packages.slice(i * 5, i * 5 + 5).map((pkg) => ({ advisoryId: record.id, package: pkg })),
    );

    const start = performance.now();
    const findings = processVulnerabilities(records, matches);
    const elapsed = performance.now() - start;

    expect(findings.length).toBeGreaterThan(0);
    expect(elapsed, `matching took ${elapsed.toFixed(0)}ms`).toBeLessThan(3000);
  });

  it('builds a report from a large inventory in reasonable time', () => {
    const sbom = syntheticSbom(10000);
    const parsed = parseSbom(sbom, MAX_PACKAGES);
    if (parsed.kind !== 'parsed') throw new Error('expected a parsed SBOM');

    const start = performance.now();
    const report = buildReport({
      snapshot: snapshot(),
      packages: parsed.packages,
      dependencyCoverage: parsed.coverage,
      vulnerabilities: { kind: 'completed', findings: [], packagesChecked: 6667 },
      sbomUnavailableReason: null,
      now: new Date('2026-11-13T12:00:00.000Z'),
    });
    const elapsed = performance.now() - start;

    expect(report.dependencies).toHaveLength(10000);
    expect(elapsed, `report build took ${elapsed.toFixed(0)}ms`).toBeLessThan(3000);
  });

  it('serialises a large report without pathological cost', () => {
    const sbom = syntheticSbom(5000);
    const parsed = parseSbom(sbom, MAX_PACKAGES);
    if (parsed.kind !== 'parsed') throw new Error('expected a parsed SBOM');

    const report = buildReport({
      snapshot: snapshot(),
      packages: parsed.packages,
      dependencyCoverage: parsed.coverage,
      vulnerabilities: { kind: 'completed', findings: [], packagesChecked: 3333 },
      sbomUnavailableReason: null,
      now: new Date('2026-11-13T12:00:00.000Z'),
    });

    const start = performance.now();
    const json = JSON.stringify(report);
    const elapsed = performance.now() - start;

    expect(json.length).toBeGreaterThan(1000);
    expect(elapsed, `serialisation took ${elapsed.toFixed(0)}ms`).toBeLessThan(2000);
  });

  it('handles a deeply nested hostile SBOM without recursing', () => {
    // A guard against stack exhaustion from attacker-shaped input.
    let nested: unknown = { name: 'deep', SPDXID: 'x' };
    for (let i = 0; i < 5000; i++) {
      nested = { nested };
    }

    expect(() => parseSbom({ sbom: { packages: [nested] } }, 100)).not.toThrow();
  });

  it('handles very long strings in package metadata', () => {
    const huge = 'a'.repeat(1_000_000);
    const result = parseSbom(
      {
        sbom: {
          packages: [{ name: huge, SPDXID: 'x', versionInfo: huge }],
        },
      },
      100,
    );
    expect(result.kind).toBe('parsed');
  });
});
