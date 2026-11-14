/** Repository identity and metadata, normalised from the GitHub REST API. */

/** A validated `owner/repo` pair. Only produced by the URL validator (§11.2). */
export interface RepositoryRef {
  readonly owner: string;
  readonly repo: string;
}

/**
 * Repository metadata.
 *
 * Fields that GitHub may omit are explicitly nullable rather than defaulted. A repository
 * with no description has `null`, never `''`, so the UI can distinguish "no description"
 * from "empty description" without guessing.
 */
export interface RepositoryMetadata {
  readonly ref: RepositoryRef;
  readonly fullName: string;
  readonly description: string | null;
  readonly htmlUrl: string;
  readonly defaultBranch: string;
  readonly isArchived: boolean;
  readonly isDisabled: boolean;
  readonly isFork: boolean;
  readonly visibility: string;
  readonly stars: number;
  readonly forks: number;
  readonly openIssues: number;
  readonly sizeKb: number;
  readonly primaryLanguage: string | null;
  readonly licenseSpdxId: string | null;
  readonly licenseName: string | null;
  readonly topics: readonly string[];
  /** ISO 8601 timestamps, or null when GitHub omits them. */
  readonly createdAt: string | null;
  readonly updatedAt: string | null;
  readonly pushedAt: string | null;
}

/** One entry from the git tree API. `sizeBytes` is absent for directories. */
export interface TreeEntry {
  readonly path: string;
  readonly type: 'blob' | 'tree' | 'commit';
  readonly sizeBytes: number | null;
}

/**
 * The repository file tree.
 *
 * `truncated` is load-bearing. Phase 0 measured `torvalds/linux` returning 71,474 entries
 * with `truncated: true`. When the tree is truncated, a path that is absent from the list
 * may still exist in the repository, so checks must degrade to `Unknown` rather than
 * reporting `Not detected`.
 */
export interface RepositoryTree {
  readonly entries: readonly TreeEntry[];
  readonly truncated: boolean;
}

/**
 * A GitHub Actions workflow, as listed by the API.
 *
 * `isRepositoryDefined` distinguishes workflows the repository actually committed from
 * ones GitHub injects. Live testing against `expressjs/express` returned entries with
 * paths like `dynamic/copilot-pull-request-reviewer`, which exist in the API listing but
 * not in the repository. Counting those as evidence that a project has configured CI
 * would be a false claim of the exact kind §5.3 prohibits, so only workflows under
 * `.github/workflows/` are treated as repository-authored.
 */
export interface WorkflowSummary {
  readonly name: string;
  readonly path: string;
  readonly state: string;
  readonly isRepositoryDefined: boolean;
}

/** Latest release, where one exists. A 404 means "no releases", not an error (§8.1). */
export interface ReleaseInfo {
  readonly tagName: string;
  readonly name: string | null;
  readonly publishedAt: string | null;
  readonly isPrerelease: boolean;
}

/**
 * Everything retrieved about a repository before analysis begins.
 *
 * Every optional source is `null` when unavailable, so the engine can tell "we looked and
 * it is not there" from "we could not look".
 */
/**
 * Why a data source produced no data.
 *
 * These are not interchangeable, and conflating them is how a report comes to assert a
 * fact it has no evidence for: a rate limit reported as "GitHub has no dependency graph
 * for this repository" is a claim about GitHub's state derived from an absence of
 * evidence (P1-2). `pending` matters for the same reason — GitHub answers `202 Accepted`
 * while it computes repository statistics, which is "not yet", not "none" (P1-6).
 */
export type SourceUnavailableReason =
  /** 404 — the resource genuinely does not exist for this repository. */
  | 'not-found'
  /** 202 — GitHub accepted the request and is still computing the answer. */
  | 'pending'
  /** 403 without an exhausted quota — forbidden, disabled or blocked. */
  | 'access-denied'
  | 'rate-limited'
  | 'network'
  | 'timeout'
  | 'cancelled'
  /** Retrieved, but the content could not be read. */
  | 'invalid'
  /** Retrieved and recognised, but in a form this release does not handle. */
  | 'unsupported'
  /** Rejected by a size, depth or count bound rather than read. */
  | 'limit-exceeded'
  /** Anything else, including an unexpected status. */
  | 'error';

/** An optional data source: either it produced data, or it says precisely why not. */
export type SourceState =
  | { readonly kind: 'available' }
  | {
      readonly kind: 'unavailable';
      readonly reason: SourceUnavailableReason;
      /** User-facing, already safe to render. Never a stack trace or raw API body. */
      readonly detail: string;
    };

/** The optional sources whose availability is tracked. */
export type SourceId =
  | 'tree'
  | 'workflows'
  | 'latest-release'
  | 'contributors'
  | 'languages'
  | 'commit-activity'
  | 'dependency-graph';

export interface RepositorySnapshot {
  readonly metadata: RepositoryMetadata;
  readonly tree: RepositoryTree | null;
  readonly workflows: readonly WorkflowSummary[] | null;
  readonly latestRelease: ReleaseInfo | null;
  readonly contributorCount: number | null;
  readonly languages: Readonly<Record<string, number>> | null;
  /** 52 weeks of commit totals, most recent last. Null if GitHub was still computing. */
  readonly weeklyCommits: readonly number[] | null;
  /** Contents of specific allowlisted files, fetched from raw.githubusercontent.com. */
  readonly fileContents: Readonly<Record<string, string>>;
  /**
   * Why each optional source is absent, for the sources that are.
   *
   * Carried alongside the nullable fields rather than replacing them: every existing
   * consumer keeps working, and the ones that need to explain an absence can.
   */
  readonly sourceStates: Readonly<Partial<Record<SourceId, SourceState>>>;
  /** When this snapshot was taken (ISO 8601). */
  readonly retrievedAt: string;
}

/**
 * 52 weeks of commit totals.
 *
 * Three-way rather than nullable because `202 Accepted` is a distinct answer: GitHub is
 * computing the statistics and has not failed. Reporting that as "no commit activity"
 * would turn a young repository's missing data into a finding (P1-6).
 */
export type WeeklyCommits =
  | { readonly kind: 'available'; readonly weeks: readonly number[] }
  | { readonly kind: 'pending' }
  | { readonly kind: 'unavailable' };
