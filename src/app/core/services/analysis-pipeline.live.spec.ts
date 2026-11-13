import { describe, expect, it } from 'vitest';

import { parseSbom, queryablePackages } from '../../engine/sbom/spdx-parser';
import { processVulnerabilities } from '../../engine/security/vulnerability-processor';
import { tallySeverities } from '../../engine/security/vulnerability-processor';
import type { NormalizedPackage } from '../models/dependency.model';

/**
 * Live end-to-end pipeline test: real GitHub SBOM → real OSV queries → real findings.
 *
 * Opt-in, because it spends the shared 60 requests/hour GitHub budget:
 *
 *   DEPGUARD_LIVE=1 npm run test:ci
 *
 * This is the test that would catch a change in either API's behaviour. Assertions check
 * invariants and relationships rather than exact counts, because advisory data changes
 * daily and a test that fails when a new CVE is published is noise, not signal.
 */

const LIVE = import.meta.env['DEPGUARD_LIVE'] === '1';
const describeLive = LIVE ? describe : describe.skip;

const GITHUB_HEADERS = { Accept: 'application/vnd.github+json' };

async function fetchSbom(repo: string): Promise<unknown> {
  const response = await fetch(`https://api.github.com/repos/${repo}/dependency-graph/sbom`, {
    headers: GITHUB_HEADERS,
  });
  if (!response.ok) {
    return null;
  }
  return response.json();
}

/** Mirrors OsvApiService's two-pass flow, without Angular's HTTP stack. */
async function queryOsv(packages: readonly NormalizedPackage[]): Promise<{
  records: unknown[];
  matches: { advisoryId: string; package: NormalizedPackage }[];
}> {
  const matches: { advisoryId: string; package: NormalizedPackage }[] = [];

  for (let i = 0; i < packages.length; i += 500) {
    const chunk = packages.slice(i, i + 500);
    const response = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        queries: chunk.map((pkg) => ({
          package: { name: pkg.name, ecosystem: pkg.ecosystem },
          version: pkg.declaredVersion,
        })),
      }),
    });
    expect(response.status, 'OSV querybatch must accept the request').toBe(200);

    const body = (await response.json()) as { results: { vulns?: { id: string }[] }[] };
    expect(body.results.length, 'results must align with queries').toBe(chunk.length);

    body.results.forEach((result, index) => {
      const pkg = chunk[index];
      if (pkg === undefined) return;
      for (const vuln of result.vulns ?? []) {
        matches.push({ advisoryId: vuln.id, package: pkg });
      }
    });
  }

  const uniqueIds = [...new Set(matches.map((m) => m.advisoryId))].slice(0, 120);
  const records = await Promise.all(
    uniqueIds.map((id) => fetch(`https://api.osv.dev/v1/vulns/${id}`).then((r) => r.json())),
  );

  return { records, matches };
}

describeLive('live analysis pipeline', () => {
  it('finds real vulnerabilities in a lockfile repository (npm/cli)', async () => {
    const sbom = await fetchSbom('npm/cli');
    expect(sbom, 'npm/cli should expose an SBOM').not.toBeNull();

    const parsed = parseSbom(sbom, 20000);
    expect(parsed.kind).toBe('parsed');
    if (parsed.kind !== 'parsed') return;

    // A committed lockfile should yield high coverage.
    expect(parsed.coverage.queryableRatio).toBeGreaterThan(0.6);

    const toQuery = queryablePackages(parsed.packages);
    const { records, matches } = await queryOsv(toQuery);
    const findings = processVulnerabilities(records, matches);

    // Deduplication must never increase the count.
    const uniqueAdvisoryIds = new Set(matches.map((m) => m.advisoryId));
    expect(findings.length).toBeLessThanOrEqual(uniqueAdvisoryIds.size);

    for (const finding of findings) {
      // Every finding must be attributable to a real package at a real version.
      expect(finding.advisoryIds.length).toBeGreaterThan(0);
      for (const affected of finding.affected) {
        expect(affected.installedVersion).toBeTruthy();
        // The core ADR-0002 invariant, against live data: never a range.
        expect(affected.installedVersion).not.toMatch(/[\^~<>*|]/);
      }
    }

    const tally = tallySeverities(findings);
    const total = Object.values(tally).reduce((sum, n) => sum + n, 0);
    expect(total).toBe(findings.length);
  }, 120000);

  it('can check nothing in a repository with no lockfile (request/request)', async () => {
    const sbom = await fetchSbom('request/request');
    expect(sbom).not.toBeNull();

    const parsed = parseSbom(sbom, 20000);
    if (parsed.kind !== 'parsed') throw new Error('expected a parsed SBOM');

    // The defining case: an inventory exists, but nothing in it is checkable.
    expect(parsed.coverage.totalPackages).toBeGreaterThan(0);
    expect(queryablePackages(parsed.packages)).toHaveLength(0);
    expect(parsed.coverage.rangeVersionsDominant).toBe(true);
  }, 60000);

  it('matches a known-vulnerable version and clears a patched one', async () => {
    // A direct control on matching correctness, using a well-known advisory.
    const vulnerable: NormalizedPackage = {
      key: 'npm|lodash|4.17.15',
      name: 'lodash',
      purlType: 'npm',
      ecosystem: 'npm',
      declaredVersion: '4.17.15',
      versionKind: 'exact',
      relationship: 'unknown',
      licenseConcluded: null,
      skipReason: null,
    };
    const patched: NormalizedPackage = {
      ...vulnerable,
      key: 'npm|lodash|4.17.21',
      declaredVersion: '4.17.21',
    };

    const vulnerableResult = await queryOsv([vulnerable]);
    const patchedResult = await queryOsv([patched]);

    const vulnerableFindings = processVulnerabilities(
      vulnerableResult.records,
      vulnerableResult.matches,
    );
    const patchedFindings = processVulnerabilities(patchedResult.records, patchedResult.matches);

    // The older version must report strictly more advisories than the patched one.
    expect(vulnerableFindings.length).toBeGreaterThan(patchedFindings.length);

    // A remediation target must be offered for the vulnerable version.
    const withFix = vulnerableFindings.filter((f) =>
      f.affected.some((a) => a.fixedVersions.length > 0),
    );
    expect(withFix.length).toBeGreaterThan(0);
  }, 60000);

  it('does not flag a package version with no known advisories', async () => {
    // Guards against the opposite failure: reporting vulnerabilities that do not exist.
    const safe: NormalizedPackage = {
      key: 'npm|depguard-nonexistent-package-xyz|1.0.0',
      name: 'depguard-nonexistent-package-xyz',
      purlType: 'npm',
      ecosystem: 'npm',
      declaredVersion: '1.0.0',
      versionKind: 'exact',
      relationship: 'unknown',
      licenseConcluded: null,
      skipReason: null,
    };

    const { records, matches } = await queryOsv([safe]);
    expect(processVulnerabilities(records, matches)).toHaveLength(0);
  }, 60000);
});
