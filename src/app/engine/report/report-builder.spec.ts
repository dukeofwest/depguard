import { describe, expect, it } from 'vitest';

import { buildReport, type BuildReportInput } from './report-builder';
import { parseSbom } from '../sbom/spdx-parser';
import expressSbom from '../__fixtures__/sbom-express.json';
import requestRequestSbom from '../__fixtures__/sbom-request-request.json';
import npmCliSbom from '../__fixtures__/sbom-npm-cli.json';
import type { RepositorySnapshot, TreeEntry } from '../../core/models/repository.model';
import type { VulnerabilityResult } from '../../core/models/vulnerability.model';

/**
 * End-to-end engine tests.
 *
 * These run the whole pipeline — real SBOM fixtures through parsing, scoring, coverage,
 * recommendations and report assembly — because the individual pieces being correct does
 * not guarantee the report they produce is honest.
 */

const NOW = new Date('2026-11-13T12:00:00.000Z');

function tree(paths: readonly string[], truncated = false) {
  const entries: TreeEntry[] = paths.map((path) => ({
    path,
    type: 'blob',
    sizeBytes: 100,
  }));
  return { entries, truncated };
}

function snapshot(partial: Partial<RepositorySnapshot> = {}): RepositorySnapshot {
  return {
    metadata: {
      ref: { owner: 'expressjs', repo: 'express' },
      fullName: 'expressjs/express',
      description: 'Fast, unopinionated, minimalist web framework for node.',
      htmlUrl: 'https://github.com/expressjs/express',
      defaultBranch: 'master',
      isArchived: false,
      isDisabled: false,
      isFork: false,
      visibility: 'public',
      stars: 69675,
      forks: 25439,
      openIssues: 262,
      sizeKb: 10074,
      primaryLanguage: 'JavaScript',
      licenseSpdxId: 'MIT',
      licenseName: 'MIT License',
      topics: ['express', 'nodejs'],
      createdAt: '2009-06-26T18:56:01Z',
      updatedAt: '2026-11-13T03:15:13Z',
      pushedAt: '2026-11-02T20:15:26Z',
      ...partial.metadata,
    },
    tree: tree([
      'Readme.md',
      'LICENSE',
      'SECURITY.md',
      '.github/dependabot.yml',
      '.github/workflows/ci.yml',
      'test/app.js',
    ]),
    workflows: [
      { name: 'CI', path: '.github/workflows/ci.yml', state: 'active', isRepositoryDefined: true },
      {
        name: 'CodeQL',
        path: '.github/workflows/codeql.yml',
        state: 'active',
        isRepositoryDefined: true,
      },
    ],
    latestRelease: {
      tagName: 'v5.3.0',
      name: null,
      publishedAt: '2026-10-09T12:50:31Z',
      isPrerelease: false,
    },
    contributorCount: 372,
    languages: { JavaScript: 1000 },
    weeklyCommits: [1, 2, 3],
    fileContents: {
      '.github/dependabot.yml': 'version: 2\nupdates:\n  - package-ecosystem: npm\n',
    },
    retrievedAt: '2026-11-13T12:00:00.000Z',
    ...partial,
  };
}

function inputFor(
  sbomFixture: unknown,
  vulnerabilities: VulnerabilityResult,
  snapshotOverrides: Partial<RepositorySnapshot> = {},
): BuildReportInput {
  const parsed = parseSbom(sbomFixture, 20000);
  if (parsed.kind !== 'parsed') {
    throw new Error(`fixture did not parse: ${parsed.kind}`);
  }
  return {
    snapshot: snapshot(snapshotOverrides),
    packages: parsed.packages,
    dependencyCoverage: parsed.coverage,
    vulnerabilities,
    sbomUnavailableReason: null,
    now: NOW,
  };
}

describe('buildReport', () => {
  describe('request/request — the case that must never read as "no vulnerabilities"', () => {
    const report = buildReport(
      inputFor(
        requestRequestSbom,
        { kind: 'not-applicable', reason: 'No dependency had an exact version to check.' },
        {
          metadata: {
            ...snapshot().metadata,
            ref: { owner: 'request', repo: 'request' },
            fullName: 'request/request',
            pushedAt: '2024-08-14T00:09:41Z',
            licenseSpdxId: null,
            licenseName: null,
          },
        },
      ),
    );

    it('reports dependency security as insufficient data, not as a score', () => {
      const category = report.categories.find((c) => c.id === 'dependency-security');
      expect(category?.kind).toBe('insufficient-data');
    });

    it('states explicitly that this is not evidence of safety', () => {
      const category = report.categories.find((c) => c.id === 'dependency-security');
      if (category?.kind !== 'insufficient-data') throw new Error('expected insufficient data');
      expect(category.reason).toContain('not evidence');
    });

    it('still produces an overall score from the categories that could be assessed', () => {
      // Excluding a category must not block the whole report.
      expect(report.overall.kind).toBe('scored');
      if (report.overall.kind !== 'scored') return;
      expect(report.overall.excludedCategories).toContain('dependency-security');
      // Coverage must make the gap visible.
      expect(report.overall.coverage).toBeLessThan(1);
    });

    it('recommends committing a lockfile, with evidence', () => {
      const recommendation = report.recommendations.find((r) => r.id === 'commit-lockfile');
      expect(recommendation).toBeDefined();
      expect(recommendation?.priority).toBe('High');
      expect(recommendation?.evidence.limitation).toContain('not evidence');
    });

    it('marks every dependency as unchecked in the inventory', () => {
      expect(report.dependencies.length).toBeGreaterThan(0);
      for (const row of report.dependencies) {
        // Zero vulnerabilities AND never checked — a different statement from "clean".
        expect(row.wasChecked).toBe(false);
        expect(row.vulnerabilityCount).toBe(0);
        expect(row.highestSeverity).toBeNull();
      }
    });

    it('records the coverage limitation', () => {
      const limitation = report.limitations.find((l) => l.scope === 'Dependency coverage');
      expect(limitation?.detail).toContain('could not be checked');
    });
  });

  describe('expressjs/express — partial coverage', () => {
    const report = buildReport(
      inputFor(expressSbom, { kind: 'completed', findings: [], packagesChecked: 8 }),
    );

    it('refuses to score dependency security below the coverage floor', () => {
      // 8 of 53 packages is ~15%, far below the 50% floor.
      const category = report.categories.find((c) => c.id === 'dependency-security');
      expect(category?.kind).toBe('insufficient-data');
    });

    it('credits the security configuration it can verify', () => {
      const checks = report.securityChecks;
      expect(checks.find((c) => c.id === 'security-policy')?.status).toBe('Configured');
      expect(checks.find((c) => c.id === 'dependabot-config')?.status).toBe('Configured');
      expect(checks.find((c) => c.id === 'codeql-workflow')?.status).toBe('Configured');
      expect(checks.find((c) => c.id === 'license')?.status).toBe('Configured');
    });

    it('never claims a GitHub feature is enabled', () => {
      const dependabot = report.securityChecks.find((c) => c.id === 'dependabot-config');
      expect(dependabot?.evidence.explanation).toContain('does not prove');
      expect(dependabot?.evidence.limitation).toContain('authenticated');
    });

    it('describes tests as detected, never as adequate', () => {
      const tests = report.engineering.checks.find((c) => c.id === 'tests');
      expect(tests?.status).toBe('Configured');
      expect(tests?.evidence.explanation).toContain('says nothing about');
      expect(tests?.evidence.explanation).not.toMatch(/comprehensive|good coverage|well tested/i);
    });
  });

  describe('npm/cli — a lockfile repository with real findings', () => {
    it('scores dependency security when coverage is sufficient', () => {
      const report = buildReport(
        inputFor(npmCliSbom, { kind: 'completed', findings: [], packagesChecked: 1026 }),
      );
      const category = report.categories.find((c) => c.id === 'dependency-security');
      expect(category?.kind).toBe('scored');
      if (category?.kind !== 'scored') return;
      // 85% coverage with no findings — high, but not a perfect score, because 15% was
      // never checked.
      expect(category.score).toBeGreaterThan(80);
      expect(category.score).toBeLessThan(100);
    });
  });

  describe('missing SBOM', () => {
    const report = buildReport({
      snapshot: snapshot(),
      packages: [],
      dependencyCoverage: null,
      vulnerabilities: { kind: 'unavailable', reason: 'No dependency graph is available.' },
      sbomUnavailableReason: 'GitHub has no dependency graph for this repository.',
      now: NOW,
    });

    it('excludes both dependency categories rather than scoring them zero', () => {
      expect(report.categories.find((c) => c.id === 'dependency-security')?.kind).toBe(
        'insufficient-data',
      );
      expect(report.categories.find((c) => c.id === 'dependency-health')?.kind).toBe(
        'insufficient-data',
      );
    });

    it('still scores the three categories it can assess', () => {
      // 25 + 20 + 15 = 60% of weight, above the 50% floor.
      expect(report.overall.kind).toBe('scored');
    });

    it('records why the inventory is missing', () => {
      expect(report.limitations.some((l) => l.scope === 'Dependency inventory')).toBe(true);
      expect(report.dataSources.find((s) => s.name.includes('SBOM'))?.status).toBe('unavailable');
    });
  });

  describe('truncated file tree', () => {
    const report = buildReport(
      inputFor(
        expressSbom,
        { kind: 'completed', findings: [], packagesChecked: 8 },
        {
          tree: tree([], true),
          workflows: null,
          fileContents: {},
        },
      ),
    );

    it('reports unknown rather than not detected when absence cannot be trusted', () => {
      // A path missing from a truncated list is not proof the file is absent.
      const policy = report.securityChecks.find((c) => c.id === 'security-policy');
      expect(policy?.status).toBe('Unknown');
      expect(policy?.evidence.limitation).toContain('truncated');
    });

    it('does not recommend adding something it could not check for', () => {
      // Advice based on an assumption is exactly what §7.1 forbids.
      expect(report.recommendations.some((r) => r.id === 'add-security-policy')).toBe(false);
    });

    it('records the truncation as a limitation', () => {
      expect(report.limitations.some((l) => l.scope === 'File inspection')).toBe(true);
    });
  });

  describe('archived repository', () => {
    const report = buildReport(
      inputFor(
        expressSbom,
        { kind: 'completed', findings: [], packagesChecked: 8 },
        {
          metadata: { ...snapshot().metadata, isArchived: true, pushedAt: '2024-04-12T17:43:16Z' },
        },
      ),
    );

    it('classifies it as archived', () => {
      expect(report.maintenance.classification).toBe('Archived');
      expect(report.maintenance.isArchived).toBe(true);
    });

    it('raises it as a high-priority recommendation, not a vulnerability', () => {
      const recommendation = report.recommendations.find((r) => r.id === 'archived-repository');
      expect(recommendation?.priority).toBe('High');
      expect(recommendation?.category).toBe('maintenance');
    });

    it('does not double-count archived and stale', () => {
      const maintenance = report.categories.find((c) => c.id === 'maintenance');
      if (maintenance?.kind !== 'scored') throw new Error('expected a score');
      expect(maintenance.deductions).toHaveLength(1);
    });
  });

  describe('report integrity', () => {
    const report = buildReport(
      inputFor(expressSbom, { kind: 'completed', findings: [], packagesChecked: 8 }),
    );

    it('is deterministic for identical input', () => {
      const again = buildReport(
        inputFor(expressSbom, { kind: 'completed', findings: [], packagesChecked: 8 }),
      );
      expect(JSON.stringify(report)).toBe(JSON.stringify(again));
    });

    it('is serialisable as JSON without loss', () => {
      const roundTripped: unknown = JSON.parse(JSON.stringify(report));
      expect(roundTripped).toEqual(report);
    });

    it('carries a schema version', () => {
      expect(report.schemaVersion).toBe('1.0.0');
    });

    it('contains no credentials or tokens (§7.3)', () => {
      const serialised = JSON.stringify(report);

      // Credential-bearing KEYS, not words. A substring search for "password" would flag
      // `pbkdf2-password`, a genuine express dependency — the package inventory
      // legitimately contains security-related package names.
      for (const key of ['authorization', 'password', 'token', 'secret', 'api_key', 'apikey']) {
        expect(
          new RegExp(`"${key}"\\s*:`, 'i').test(serialised),
          `report must not contain a "${key}" field`,
        ).toBe(false);
      }

      // Token-shaped VALUES, in any field.
      const tokenPatterns = [
        /ghp_[A-Za-z0-9]{20,}/, // GitHub personal access token
        /github_pat_[A-Za-z0-9_]{20,}/, // fine-grained PAT
        /gho_[A-Za-z0-9]{20,}/, // OAuth token
        /\bBearer\s+[A-Za-z0-9._-]{10,}/i,
      ];
      for (const pattern of tokenPatterns) {
        expect(pattern.test(serialised), `report must not contain ${pattern}`).toBe(false);
      }
    });

    it('does carry security-related package names through unaltered', () => {
      // The flip side of the test above: the inventory must not be sanitised. Dropping a
      // package because its name contains "password" would hide a real dependency.
      const names = report.dependencies.map((row) => row.package.name);
      expect(names).toContain('pbkdf2-password');
    });

    it('gives every recommendation supporting evidence (§7.1)', () => {
      expect(report.recommendations.length).toBeGreaterThan(0);
      for (const recommendation of report.recommendations) {
        expect(recommendation.evidence.checked.length).toBeGreaterThan(0);
        expect(recommendation.evidence.found.length).toBeGreaterThan(0);
        expect(recommendation.evidence.explanation.length).toBeGreaterThan(0);
      }
    });

    it('gives every check supporting evidence (§5.3)', () => {
      for (const check of [...report.securityChecks, ...report.engineering.checks]) {
        expect(check.evidence.checked.length).toBeGreaterThan(0);
        expect(check.evidence.source.length).toBeGreaterThan(0);
        expect(check.evidence.explanation.length).toBeGreaterThan(0);
      }
    });

    it('discloses ecosystems whose matching has not been verified (§5.2)', () => {
      // psf/requests is a PyPI project, which Phase 0 verified, so no notice is due.
      const verifiedOnly = buildReport(
        inputFor(expressSbom, { kind: 'completed', findings: [], packagesChecked: 8 }),
      );
      expect(verifiedOnly.limitations.some((l) => l.scope === 'Ecosystem coverage')).toBe(false);

      // A Cargo dependency is mapped from documentation only, so it must be disclosed.
      const withUnverified = buildReport({
        ...inputFor(expressSbom, { kind: 'completed', findings: [], packagesChecked: 8 }),
        packages: [
          {
            key: 'crates.io|serde|1.0.0',
            name: 'serde',
            purlType: 'cargo',
            ecosystem: 'crates.io',
            declaredVersion: '1.0.0',
            versionKind: 'exact',
            relationship: 'unknown',
            licenseConcluded: null,
            skipReason: null,
          },
        ],
      });

      const notice = withUnverified.limitations.find((l) => l.scope === 'Ecosystem coverage');
      expect(notice).toBeDefined();
      expect(notice?.detail).toContain('crates.io');
      expect(notice?.detail).toContain('has not been confirmed');
    });

    it('always states its standing limitations', () => {
      const scopes = report.limitations.map((l) => l.scope);
      expect(scopes).toContain('Scope of analysis');
      expect(scopes).toContain('Vulnerability data');
      expect(scopes).toContain('Version freshness');
    });

    it('never labels a missing README as critical (§7.2)', () => {
      const report2 = buildReport(
        inputFor(
          expressSbom,
          { kind: 'completed', findings: [], packagesChecked: 8 },
          {
            tree: tree(['index.js']),
            workflows: [],
            fileContents: {},
          },
        ),
      );
      for (const recommendation of report2.recommendations) {
        if (recommendation.id === 'add-readme') {
          expect(recommendation.priority).not.toBe('Critical');
          expect(recommendation.priority).not.toBe('High');
        }
      }
    });

    it('orders recommendations by priority', () => {
      const order = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
      const ranks = report.recommendations.map((r) => order.indexOf(r.priority));
      const sorted = [...ranks].sort((a, b) => a - b);
      expect(ranks).toEqual(sorted);
    });
  });
});
