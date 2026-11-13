import { describe, expect, it } from 'vitest';

import {
  contributorCountFromLink,
  toLanguages,
  toReleaseInfo,
  toRepositoryMetadata,
  toRepositoryTree,
  toWeeklyCommits,
  toWorkflowSummaries,
} from './github-response';
import type { RepositoryRef } from '../models/repository.model';

/**
 * Live integration test against the real GitHub API.
 *
 * Mocked tests only prove the code handles payloads *we imagined*. This one proves the
 * normalisers handle what GitHub actually returns today, which is the Phase 2 acceptance
 * criterion ("Real public repositories can be analysed at the data-retrieval level").
 *
 * Opt-in, because it makes unauthenticated network calls against a 60 requests/hour
 * budget and would otherwise make CI flaky and quota-bound:
 *
 *   DEPGUARD_LIVE=1 npm run test:ci
 *
 * Costs ~8 requests. Assertions deliberately check *shape and invariants*, not values:
 * star counts and commit activity change daily, so asserting them would create a test
 * that fails for no good reason.
 */

// Vitest populates import.meta.env from the environment, so this needs no @types/node.
const LIVE = import.meta.env['DEPGUARD_LIVE'] === '1';
const describeLive = LIVE ? describe : describe.skip;

const REF: RepositoryRef = { owner: 'expressjs', repo: 'express' };
const BASE = 'https://api.github.com/repos/expressjs/express';
const HEADERS = { Accept: 'application/vnd.github+json' };

async function getJson(url: string): Promise<{ status: number; body: unknown; headers: Headers }> {
  const response = await fetch(url, { headers: HEADERS });
  const text = await response.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    // A 202 from the stats endpoint has an empty body; that is data, not a failure.
    body = null;
  }
  return { status: response.status, body, headers: response.headers };
}

describeLive('live GitHub API (opt-in)', () => {
  it('normalises real repository metadata', async () => {
    const { status, body, headers } = await getJson(BASE);
    expect(status).toBe(200);

    // The header the whole rate-limit UI depends on must be present and readable.
    expect(headers.get('x-ratelimit-remaining')).not.toBeNull();

    const metadata = toRepositoryMetadata(body, REF);
    expect(metadata).not.toBeNull();
    expect(metadata?.fullName).toBe('expressjs/express');
    expect(metadata?.defaultBranch).toBeTruthy();
    expect(metadata?.htmlUrl.startsWith('https://github.com/')).toBe(true);
    expect(typeof metadata?.stars).toBe('number');
    expect(metadata?.isArchived).toBe(false);
    // Dates must parse — a null here would mean the normaliser rejected a real value.
    expect(metadata?.pushedAt).not.toBeNull();
    expect(Number.isNaN(Date.parse(metadata?.pushedAt ?? ''))).toBe(false);
  }, 30000);

  it('normalises a real recursive tree and finds signal paths', async () => {
    const { body } = await getJson(`${BASE}/git/trees/master?recursive=1`);
    const tree = toRepositoryTree(body, 20000);

    expect(tree).not.toBeNull();
    expect(tree?.entries.length).toBeGreaterThan(50);
    expect(typeof tree?.truncated).toBe('boolean');

    const paths = (tree?.entries ?? []).map((entry) => entry.path);
    // The signals Categories C and E depend on must be reachable from this one request.
    expect(paths.some((p) => /^LICENSE/i.test(p))).toBe(true);
    expect(paths.some((p) => /^readme\.md$/i.test(p))).toBe(true);
    expect(paths.some((p) => p.startsWith('.github/workflows/'))).toBe(true);

    // Every entry must satisfy the model's invariants.
    for (const entry of tree?.entries ?? []) {
      expect(entry.path.length).toBeGreaterThan(0);
      expect(['blob', 'tree', 'commit']).toContain(entry.type);
    }
  }, 30000);

  it('normalises real workflows', async () => {
    const { body } = await getJson(`${BASE}/actions/workflows`);
    const workflows = toWorkflowSummaries(body);

    expect(workflows).not.toBeNull();
    expect(workflows?.length).toBeGreaterThan(0);

    // GitHub lists workflows it injects alongside the repository's own — live responses
    // include paths such as `dynamic/copilot-pull-request-reviewer`. Only committed
    // workflow files count as evidence the project configured CI.
    const repositoryDefined = (workflows ?? []).filter((w) => w.isRepositoryDefined);
    expect(repositoryDefined.length).toBeGreaterThan(0);
    for (const workflow of repositoryDefined) {
      expect(workflow.path).toContain('.github/workflows/');
    }

    // The distinction must be real, not merely available: every workflow outside
    // .github/workflows/ must be flagged as not repository-defined.
    for (const workflow of workflows ?? []) {
      if (!workflow.path.startsWith('.github/workflows/')) {
        expect(workflow.isRepositoryDefined).toBe(false);
      }
    }
  }, 30000);

  it('normalises a real release', async () => {
    const { status, body } = await getJson(`${BASE}/releases/latest`);
    if (status === 404) {
      // Legitimate: the repository has no releases.
      return;
    }
    const release = toReleaseInfo(body);
    expect(release).not.toBeNull();
    expect(release?.tagName).toBeTruthy();
  }, 30000);

  it('normalises real languages', async () => {
    const { body } = await getJson(`${BASE}/languages`);
    const languages = toLanguages(body);
    expect(languages).not.toBeNull();
    for (const bytes of Object.values(languages ?? {})) {
      expect(bytes).toBeGreaterThanOrEqual(0);
    }
  }, 30000);

  it('derives a contributor count from a real Link header', async () => {
    const response = await fetch(`${BASE}/contributors?per_page=1&anon=true`, { headers: HEADERS });
    const count = contributorCountFromLink(response.headers.get('link'));
    // express has many contributors, so a Link header is expected here.
    expect(count).not.toBeNull();
    expect(count).toBeGreaterThan(1);
  }, 30000);

  it('handles real commit activity, including the 202 "still computing" case', async () => {
    const { status, body } = await getJson(`${BASE}/stats/commit_activity`);
    const weeks = status === 202 ? null : toWeeklyCommits(body);
    if (weeks !== null) {
      expect(weeks.length).toBeGreaterThan(0);
      for (const total of weeks) {
        expect(total).toBeGreaterThanOrEqual(0);
      }
    }
  }, 30000);

  it('retrieves a real SBOM synchronously, with no polling or redirect', async () => {
    const response = await fetch(`${BASE}/dependency-graph/sbom`, { headers: HEADERS });

    // The core Phase 0 finding, re-asserted against live data: one request, document in
    // the body. If GitHub ever moves to an async workflow, this fails loudly.
    expect(response.status).toBe(200);
    expect(response.redirected).toBe(false);

    const body: unknown = await response.json();
    expect(body).toHaveProperty('sbom');

    const sbom = (body as { sbom: { spdxVersion?: unknown; packages?: unknown } }).sbom;
    expect(sbom.spdxVersion).toMatch(/^SPDX-/);
    expect(Array.isArray(sbom.packages)).toBe(true);
    expect((sbom.packages as unknown[]).length).toBeGreaterThan(0);
  }, 30000);

  it('returns 404 for a repository with no dependency graph', async () => {
    const response = await fetch(
      'https://api.github.com/repos/sindresorhus/is-odd/dependency-graph/sbom',
      { headers: HEADERS },
    );
    // A normal outcome that must stay distinguishable from an error.
    expect(response.status).toBe(404);
  }, 30000);
});
