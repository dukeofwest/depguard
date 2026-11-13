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
  /** When this snapshot was taken (ISO 8601). */
  readonly retrievedAt: string;
}
