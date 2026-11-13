/**
 * External API configuration and the destination allowlist.
 *
 * DepGuard contacts exactly three hosts and never follows a URL discovered inside
 * repository content (§9.2, §14). Every limit below was measured in Phase 0 rather than
 * guessed; see docs/phase-0/FEASIBILITY-REPORT.md.
 */

export const GITHUB_API_ORIGIN = 'https://api.github.com' as const;
export const GITHUB_RAW_ORIGIN = 'https://raw.githubusercontent.com' as const;
export const OSV_API_ORIGIN = 'https://api.osv.dev' as const;

/** The only hosts the application may contact. Enforced before every request. */
export const ALLOWED_ORIGINS: readonly string[] = [
  GITHUB_API_ORIGIN,
  GITHUB_RAW_ORIGIN,
  OSV_API_ORIGIN,
] as const;

/** GitHub REST requires this Accept header; it is CORS-safelisted so adds no preflight. */
export const GITHUB_ACCEPT_HEADER = 'application/vnd.github+json' as const;
export const GITHUB_API_VERSION_HEADER = '2022-11-28' as const;

/**
 * Rate limiting (ADR-0004).
 *
 * Anonymous GitHub REST allows 60 requests/hour/IP — confirmed, and the binding
 * constraint on the whole product. A scan costs about 9 requests, so a visitor gets
 * roughly 6 scans per hour.
 */
export const RATE_LIMIT = {
  /**
   * Quota-consuming GitHub requests for one scan: metadata, tree, workflows, latest
   * release, contributors, languages, commit activity, SBOM.
   *
   * ADR-0004 budgeted 9, which included `/community/profile`. That endpoint was dropped
   * during implementation: the recursive tree plus file contents from
   * raw.githubusercontent.com (which cost no quota) establish the same signals with one
   * request fewer, and from the repository itself rather than GitHub's org-level
   * fallbacks. Asserted by a test so the two cannot drift apart.
   */
  requestsPerScan: 8,
  /**
   * Refuse to start a scan below this, rather than failing halfway through.
   *
   * Set above `requestsPerScan` to leave headroom for the tree-truncation fallback,
   * which costs up to 2 extra requests on very large repositories.
   */
  minimumRemainingToStart: 10,
} as const;

/**
 * OSV limits.
 *
 * `querybatch` accepts at most 1,000 queries — measured: 1,000 returned HTTP 200 and
 * 1,001 returned HTTP 400. 500 is used as the working chunk size to keep individual
 * requests responsive and cancellable.
 */
export const OSV_LIMITS = {
  maxQueriesPerBatch: 1000,
  chunkSize: 500,
  /** Parallel `GET /v1/vulns/{id}` fetches. 8 concurrent completed in 299 ms in testing. */
  detailConcurrency: 8,
  maxDetailRequests: 400,
} as const;

/**
 * Response size and processing caps (§12).
 *
 * The largest SBOM measured was `npm/cli` at 1.1 MB / 1,208 packages, which parsed in
 * 2.8 ms in-browser. 16 MB leaves generous headroom while still bounding memory against a
 * hostile or pathological response.
 */
export const RESPONSE_LIMITS = {
  maxSbomBytes: 16 * 1024 * 1024,
  maxFileContentBytes: 512 * 1024,
  maxPackages: 20000,
  requestTimeoutMs: 30000,
} as const;

/**
 * Files fetched for their contents.
 *
 * A fixed allowlist, retrieved from raw.githubusercontent.com, which costs no API quota.
 * Paths are never taken from repository content. Matching is case-insensitive because
 * real repositories vary — `expressjs/express` ships `Readme.md`, not `README.md`.
 */
export const INSPECTED_FILE_PATHS: readonly string[] = [
  '.github/dependabot.yml',
  '.github/dependabot.yaml',
  'SECURITY.md',
  '.github/SECURITY.md',
] as const;

/** Builds a GitHub API URL. Segments are encoded by the caller after validation. */
export function githubApiUrl(path: string): string {
  return `${GITHUB_API_ORIGIN}${path}`;
}

/** True when a URL targets an allowlisted origin. */
export function isAllowedUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ALLOWED_ORIGINS.includes(parsed.origin);
  } catch {
    return false;
  }
}
