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
const ALLOWED_ORIGINS: readonly string[] = [
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
 * constraint on the whole product. A scan costs 8 requests, so a visitor gets
 * roughly 7 scans per hour.
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
   * Two requests of headroom above `requestsPerScan`, so a scan that begins with the
   * minimum does not fail on its last call if the budget is being spent concurrently
   * from the same IP — which is the normal case on a shared or corporate address.
   *
   * It previously claimed to leave room for "the tree-truncation fallback, which costs up
   * to 2 extra requests". No such fallback exists, and none is needed: a truncated tree is
   * carried through as `truncated: true` and turns file-based checks into `Unknown`, which
   * is both correct and free. The constant is unchanged; only the justification was
   * fiction (P2-3).
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

  /**
   * Bound on any JSON response body other than the SBOM, in bytes.
   *
   * Everything else GitHub or OSV returns is metadata; the largest measured was a
   * recursive tree for `torvalds/linux` at roughly 7 MB, so 12 MB is generous while
   * still bounding memory.
   */
  maxJsonBytes: 12 * 1024 * 1024,

  /**
   * Nesting depth, node count and string length are bounded in
   * `engine/validation/external-input.ts`, which the engine can import and this file
   * cannot be imported by. See MAX_JSON_DEPTH, MAX_JSON_NODES and
   * MAX_EXTERNAL_STRING_LENGTH there.
   */

  /**
   * Maximum length of a response header value parsed with a regular expression. Only
   * the `Link` header qualifies; GitHub's is around 200 characters.
   */
  maxHeaderLength: 8192,
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

/**
 * Manifest files DepGuard may fetch when GitHub's dependency graph is unavailable.
 *
 * ## Why this is not arbitrary file fetching
 *
 * `INSPECTED_FILE_PATHS` above is a fixed list of four exact paths. Dependency discovery
 * cannot work that way, because a lockfile's location varies per repository — a monorepo
 * has one per workspace. This list replaces *fixed paths* with *fixed basenames*, and
 * every other constraint is unchanged:
 *
 * - **Candidate paths come from the GitHub git/trees API**, which is structured metadata
 *   about this repository from an allowlisted origin. A path found *inside* a file is
 *   still never fetched — nothing reads a lockfile's `resolved` URLs, its `repository`
 *   field, or any other content-supplied location.
 * - **A path qualifies only if its basename is one of these**, compiled into the
 *   application. The list is as fixed as the four paths above; only its arity differs.
 * - **The URL is still built, not taken**: `raw.githubusercontent.com/{validated
 *   owner}/{validated repo}/{branch}/{path}`, with each segment filtered and encoded by
 *   the raw-file helpers in `GithubApiService`, and `isAllowedUrl` checked there before
 *   the request is issued. See the note on `isAllowedUrl` for exactly where that check
 *   lives, and for what it does not cover.
 * - **Bounded**: at most `maxManifestFiles` lockfiles plus `maxProjectFiles` project
 *   files per scan, each capped at `maxFileContentBytes`, and all of them together
 *   capped at `maxManifestBytes` — a limit enforced while responses are being consumed,
 *   not totalled afterwards. See `DISCOVERY_LIMITS`.
 *
 * So the reachable set grows from "four fixed paths in this repository" to "paths in this
 * repository whose basename DepGuard compiled in". No origin is added, and no
 * attacker-supplied string reaches a URL. See docs/audits/SECURITY-REVIEW.md §2.
 */
export const MANIFEST_FILE_NAMES: readonly string[] = [
  // npm
  'package-lock.json',
  'npm-shrinkwrap.json',
  // NuGet. `packages.lock.json` and `packages.config` state installed versions; the
  // project files state declarations, which are reported but never queried.
  'packages.lock.json',
  'packages.config',
  'Directory.Packages.props',
  'Directory.Build.props',
] as const;

/**
 * Project-file extensions that may be fetched.
 *
 * Separate from `MANIFEST_FILE_NAMES` because .NET project files are named after their
 * project, so there is no fixed basename to match — the *extension* is the fixed part.
 * The same reasoning and the same bounds apply: the path still comes from the tree, the
 * URL is still constructed, and the origin is still allowlisted.
 */
export const MANIFEST_FILE_EXTENSIONS: readonly string[] = [
  '.csproj',
  '.vbproj',
  '.fsproj',
] as const;

/**
 * Bounds on manifest discovery.
 *
 * `raw.githubusercontent.com` costs no GitHub API quota, which is what makes discovery
 * affordable — but it is not free: it costs the visitor's bandwidth and time, and a
 * hostile repository could otherwise ship thousands of candidate files. These limits are
 * what stop that, and reaching one is reported as incomplete discovery rather than
 * absorbed silently.
 */
export const DISCOVERY_LIMITS = {
  /** Lockfiles fetched per scan. A large monorepo is sampled, not exhausted. */
  maxManifestFiles: 8,
  /**
   * Total bytes received across every manifest in one scan.
   *
   * **Enforced during transfer, not totalled afterwards.** Each fetch is issued with an
   * allowance of whatever is left, `getBoundedRawFile` abandons a transfer that exceeds
   * its allowance, and once the budget is gone no further request is issued at all. The
   * bytes are charged whatever the response turned out to be — malformed, unsupported,
   * oversized or empty all cost what they cost.
   *
   * This matters because the per-file cap cannot bound the aggregate: 8 lockfiles plus
   * 24 project files at 512 KB each is 16 MB, four times this figure. A total computed
   * after the fetches would have reported that overrun rather than prevented it.
   *
   * The residual overrun is one chunk: a transfer is abandoned on the first progress
   * event that crosses the allowance, so the bytes already in that chunk are received.
   * `Content-Length`, when the server sends it, refuses an oversized file before its
   * body is read at all.
   *
   * The bound does not depend on progress events being reported. Where a backend reports
   * none, the assembled body is measured in encoded UTF-8 bytes rather than in string
   * length, so text outside the BMP cannot consume more than its allowance by being
   * counted in UTF-16 code units.
   */
  maxManifestBytes: 4 * 1024 * 1024,
  /**
   * Project files fetched per scan, on top of `maxManifestFiles`.
   *
   * Higher because .NET repositories legitimately have many: `dotnet/machinelearning` has
   * 83 `.csproj` files and no lockfile at all, so a limit of 8 would see almost nothing.
   * Still bounded, and still reported when reached.
   */
  maxProjectFiles: 24,
} as const;

/**
 * True when a repository path is one DepGuard may fetch for dependency discovery.
 *
 * Matches on the basename only, so `package-lock.json` and
 * `packages/app/package-lock.json` both qualify while `package-lock.json.bak` and
 * `docs/package-lock.json.md` do not. Rejects any path containing a traversal segment
 * before `getRawFile` sees it, even though `getRawFile` filters them too — a bound worth
 * having twice.
 */
export function isDiscoverableManifest(path: string): boolean {
  return manifestBasename(path) !== null;
}

/**
 * The basename of a discoverable manifest, or null when the path is not one.
 *
 * Matching is case-insensitive for the .NET files because MSBuild treats file names that
 * way and real repositories vary (`directory.packages.props` occurs). The npm lockfile
 * names are matched case-insensitively too, which is harmless: npm only ever writes the
 * lowercase form, so no additional path becomes reachable in practice.
 */
export function manifestBasename(path: string): string | null {
  if (path.length === 0 || path.length > 1024) {
    return null;
  }
  const segments = path.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    return null;
  }

  const basename = segments[segments.length - 1];
  if (basename === undefined) {
    return null;
  }

  const lowered = basename.toLowerCase();

  if (MANIFEST_FILE_NAMES.some((name) => name.toLowerCase() === lowered)) {
    return basename;
  }
  if (MANIFEST_FILE_EXTENSIONS.some((extension) => lowered.endsWith(extension))) {
    // An extension match must still leave a project name in front of it, so a file
    // literally named `.csproj` does not qualify.
    return lowered.length > 7 ? basename : null;
  }

  return null;
}

/** True when a path is a .NET project file rather than a lockfile or props file. */
export function isProjectFile(path: string): boolean {
  const basename = manifestBasename(path);
  if (basename === null) {
    return false;
  }
  const lowered = basename.toLowerCase();
  return MANIFEST_FILE_EXTENSIONS.some((extension) => lowered.endsWith(extension));
}

/**
 * Workflow files whose contents are fetched, so checks can read what a workflow does.
 *
 * A workflow's file name and display name prove nothing: `codeql.yml` could contain
 * anything at all. Reading the file is what lets the CodeQL check assert that the
 * workflow actually references the CodeQL action (P1-10).
 *
 * Bounded, because a repository can have many workflows and these are fetched on every
 * scan. The limit is generous relative to real repositories — DepGuard itself has two —
 * and reaching it degrades the check to `Unknown` rather than to a false negative.
 */
export const INSPECTED_WORKFLOW_LIMIT = 12;

/** True when a path is a GitHub Actions workflow definition. */
export function isWorkflowFile(path: string): boolean {
  if (path.length === 0 || path.length > 1024) {
    return false;
  }
  const lowered = path.toLowerCase();
  if (!lowered.startsWith('.github/workflows/')) {
    return false;
  }
  if (!lowered.endsWith('.yml') && !lowered.endsWith('.yaml')) {
    return false;
  }
  // Workflows live directly in the directory; GitHub does not recurse into it.
  const segments = path.split('/');
  if (segments.length !== 3) {
    return false;
  }
  return segments.every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

/**
 * True when a URL targets an allowlisted origin.
 *
 * ## Where this is actually enforced
 *
 * At the call sites in `GithubApiService` — `requestJson` for every `api.github.com`
 * request, and the raw-file helpers for every `raw.githubusercontent.com` request — each
 * checking the URL it has just constructed before issuing it.
 *
 * **There is no HTTP interceptor.** `provideHttpClient(withFetch())` is configured
 * without one, so this function is not applied to every outgoing request as a matter of
 * course. The OSV client does not call it: its two endpoints are built from the
 * `OSV_API_ORIGIN` constant plus a percent-encoded advisory id, so the origin is fixed by
 * construction rather than by a check. That is sound as written, but it is per-call-site
 * discipline, and a new client added later inherits nothing from it.
 *
 * ## Redirects
 *
 * This is checked against the URL the application asks for, and nothing more. `fetch`
 * follows redirects by default, Angular's backend does not set `redirect: 'manual'`, and
 * no code here inspects individual hops — a browser application cannot: the intermediate
 * URLs are not exposed to script.
 *
 * What restricts a redirect is therefore the browser, not DepGuard:
 *
 * - **CSP `connect-src`** restricts *connection destinations*. It names the same three
 *   origins and is applied to *every* hop, so a redirect leaving them is refused by the
 *   user agent before a connection is made. Proved in real Chrome by
 *   `tools/csp-test.mjs`.
 * - **CORS** governs *whether script may read a cross-origin response*. It does not
 *   prevent the request or the redirect; it decides whether the body ever becomes
 *   available to this application.
 *
 * Two different kinds of control, and neither is an application-controlled redirect
 * validator: both are enforced by the browser, the stronger of the two is lost if the
 * application is served without its CSP, and DepGuard neither observes nor reports that a
 * redirect happened. "DepGuard validates redirect destinations" would be the wrong claim;
 * "the browser confines them to three origins" is the right one.
 */
export function isAllowedUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ALLOWED_ORIGINS.includes(parsed.origin);
  } catch {
    return false;
  }
}
