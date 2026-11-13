import type {
  ReleaseInfo,
  RepositoryMetadata,
  RepositoryRef,
  RepositoryTree,
  TreeEntry,
  WorkflowSummary,
} from '../models/repository.model';

/**
 * Validation and normalisation of GitHub REST responses.
 *
 * Every response is untrusted input (§9.2, §14). These functions never assume a field is
 * present or of the expected type; anything unusable becomes `null` so the analysis can
 * record "not available" rather than crashing or inventing a value.
 *
 * Raw API shapes are kept here and converted to domain models immediately, so API
 * vocabulary does not leak into the rest of the application (§10.1).
 */

type Json = Record<string, unknown>;

function isObject(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function str(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function num(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function bool(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

/** Non-negative integer, else null. Guards against negative or fractional counts. */
function count(value: unknown): number | null {
  const n = num(value);
  return n !== null && n >= 0 ? Math.floor(n) : null;
}

/** An ISO 8601 timestamp that actually parses, else null. */
function isoDate(value: unknown): string | null {
  const s = str(value);
  if (s === null || Number.isNaN(Date.parse(s))) {
    return null;
  }
  return s;
}

function stringArray(value: unknown): readonly string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === 'string');
}

/**
 * Normalises `GET /repos/{owner}/{repo}`.
 *
 * Returns null only when the payload lacks the fields that make it a repository at all —
 * there is no point analysing a response we cannot identify.
 */
export function toRepositoryMetadata(body: unknown, ref: RepositoryRef): RepositoryMetadata | null {
  if (!isObject(body)) {
    return null;
  }

  const defaultBranch = str(body['default_branch']);
  const htmlUrl = str(body['html_url']);
  if (defaultBranch === null || htmlUrl === null) {
    return null;
  }

  // Only trust the API's html_url if it really is a github.com address; it is
  // rendered as a link, so a hostile value must not become an open redirect.
  let safeHtmlUrl = `https://github.com/${ref.owner}/${ref.repo}`;
  try {
    const parsed = new URL(htmlUrl);
    if (parsed.protocol === 'https:' && parsed.hostname === 'github.com') {
      safeHtmlUrl = parsed.toString();
    }
  } catch {
    // Keep the constructed fallback.
  }

  const license = isObject(body['license']) ? body['license'] : null;

  return {
    ref,
    fullName: str(body['full_name']) ?? `${ref.owner}/${ref.repo}`,
    description: str(body['description']),
    htmlUrl: safeHtmlUrl,
    defaultBranch,
    isArchived: bool(body['archived'], false),
    isDisabled: bool(body['disabled'], false),
    isFork: bool(body['fork'], false),
    visibility: str(body['visibility']) ?? 'unknown',
    stars: count(body['stargazers_count']) ?? 0,
    forks: count(body['forks_count']) ?? 0,
    openIssues: count(body['open_issues_count']) ?? 0,
    sizeKb: count(body['size']) ?? 0,
    primaryLanguage: str(body['language']),
    licenseSpdxId: license === null ? null : str(license['spdx_id']),
    licenseName: license === null ? null : str(license['name']),
    topics: stringArray(body['topics']),
    createdAt: isoDate(body['created_at']),
    updatedAt: isoDate(body['updated_at']),
    pushedAt: isoDate(body['pushed_at']),
  };
}

/**
 * Normalises `GET /repos/{owner}/{repo}/git/trees/{ref}?recursive=1`.
 *
 * `truncated` is carried through deliberately. Phase 0 measured `torvalds/linux`
 * returning 71,474 entries with `truncated: true`; when that happens, an absent path
 * means "we could not see it", not "it is not there", and checks must degrade to
 * `Unknown` rather than `Not detected`.
 */
export function toRepositoryTree(body: unknown, maxEntries: number): RepositoryTree | null {
  if (!isObject(body) || !Array.isArray(body['tree'])) {
    return null;
  }

  const raw = body['tree'];
  const entries: TreeEntry[] = [];

  for (const item of raw) {
    if (entries.length >= maxEntries) {
      break;
    }
    if (!isObject(item)) {
      continue;
    }
    const path = str(item['path']);
    const type = str(item['type']);
    if (path === null || (type !== 'blob' && type !== 'tree' && type !== 'commit')) {
      continue;
    }
    entries.push({ path, type, sizeBytes: count(item['size']) });
  }

  // A tree we had to clip is just as incomplete as one GitHub clipped.
  const truncated = bool(body['truncated'], false) || raw.length > maxEntries;

  return { entries, truncated };
}

/** Normalises `GET /repos/{owner}/{repo}/actions/workflows`. */
export function toWorkflowSummaries(body: unknown): readonly WorkflowSummary[] | null {
  if (!isObject(body) || !Array.isArray(body['workflows'])) {
    return null;
  }

  const workflows: WorkflowSummary[] = [];
  for (const item of body['workflows']) {
    if (!isObject(item)) {
      continue;
    }
    const path = str(item['path']);
    if (path === null) {
      continue;
    }
    workflows.push({
      name: str(item['name']) ?? path,
      path,
      state: str(item['state']) ?? 'unknown',
      // Only a workflow file committed under .github/workflows/ is evidence that the
      // repository configured CI. GitHub also lists workflows it injects itself, under
      // paths such as `dynamic/...`, which the repository never authored.
      isRepositoryDefined: path.startsWith('.github/workflows/'),
    });
  }
  return workflows;
}

/** Normalises `GET /repos/{owner}/{repo}/releases/latest`. A 404 is handled by the caller. */
export function toReleaseInfo(body: unknown): ReleaseInfo | null {
  if (!isObject(body)) {
    return null;
  }
  const tagName = str(body['tag_name']);
  if (tagName === null) {
    return null;
  }
  return {
    tagName,
    name: str(body['name']),
    publishedAt: isoDate(body['published_at']),
    isPrerelease: bool(body['prerelease'], false),
  };
}

/** Normalises `GET /repos/{owner}/{repo}/languages` — a map of language to byte count. */
export function toLanguages(body: unknown): Readonly<Record<string, number>> | null {
  if (!isObject(body)) {
    return null;
  }
  const languages: Record<string, number> = {};
  for (const [name, value] of Object.entries(body)) {
    const bytes = count(value);
    if (bytes !== null) {
      languages[name] = bytes;
    }
  }
  return languages;
}

/**
 * Normalises `GET /repos/{owner}/{repo}/stats/commit_activity`.
 *
 * Returns null for a `202` (GitHub still computing the statistics), which the caller
 * reports as `Unknown` rather than as zero activity.
 */
export function toWeeklyCommits(body: unknown): readonly number[] | null {
  if (!Array.isArray(body) || body.length === 0) {
    return null;
  }
  const weeks: number[] = [];
  for (const item of body) {
    if (!isObject(item)) {
      continue;
    }
    const total = count(item['total']);
    weeks.push(total ?? 0);
  }
  return weeks.length > 0 ? weeks : null;
}

/**
 * Reads the contributor count from a `Link` header.
 *
 * Requesting `per_page=1` makes the last page number equal the contributor count, which
 * avoids paging through thousands of contributors to count them. Returns null when the
 * header is absent — which legitimately happens when there is only one page.
 */
export function contributorCountFromLink(linkHeader: string | null): number | null {
  if (linkHeader === null) {
    return null;
  }
  const match = /[?&]page=(\d+)[^>]*>;\s*rel="last"/.exec(linkHeader);
  if (match === null) {
    return null;
  }
  const parsed = Number.parseInt(match[1] ?? '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}
