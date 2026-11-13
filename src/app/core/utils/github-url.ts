import { createAppError, type AppError } from '../models/api-error.model';
import type { RepositoryRef } from '../models/repository.model';

/**
 * Repository URL parsing and validation.
 *
 * This is a security boundary, not a convenience. The parsed owner and repo are
 * interpolated into API URLs, so anything that reaches the network must first be proven
 * to be a plausible GitHub identifier (§14: "Validate repository URL input", "No
 * arbitrary URL fetching"). Pure and synchronous so it can be exhaustively tested.
 */

export type ParseResult =
  | { readonly ok: true; readonly ref: RepositoryRef }
  | { readonly ok: false; readonly error: AppError };

/** Hosts recognised as GitHub. Anything else is rejected outright. */
const GITHUB_HOSTS: readonly string[] = ['github.com', 'www.github.com'] as const;

/**
 * GitHub account names: alphanumeric with internal hyphens, max 39 characters.
 * Deliberately stricter than "whatever GitHub might accept" — over-permissiveness here
 * is what turns a URL field into an SSRF primitive.
 */
const OWNER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;

/** Repository names: alphanumerics plus `.`, `-`, `_`, max 100 characters. */
const REPO_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;

/**
 * Path segments that are GitHub features rather than account names, so
 * `github.com/settings/foo` is never read as the repository `settings/foo`.
 */
const RESERVED_OWNERS: ReadonlySet<string> = new Set([
  'about',
  'account',
  'admin',
  'apps',
  'blog',
  'collections',
  'contact',
  'dashboard',
  'enterprise',
  'events',
  'explore',
  'features',
  'gist',
  'issues',
  'login',
  'logout',
  'marketplace',
  'new',
  'notifications',
  'organizations',
  'orgs',
  'pricing',
  'pulls',
  'search',
  'security',
  'sessions',
  'settings',
  'signup',
  'sponsors',
  'stars',
  'topics',
  'trending',
  'users',
]);

function invalid(message: string, remedy?: string): ParseResult {
  return {
    ok: false,
    error: createAppError('invalid-url', message, remedy ? { remedy } : undefined),
  };
}

function unsupported(message: string, remedy?: string): ParseResult {
  return {
    ok: false,
    error: createAppError('unsupported-url', message, remedy ? { remedy } : undefined),
  };
}

/** Strips a trailing `.git`, which appears on clone URLs. */
function stripGitSuffix(repo: string): string {
  return repo.endsWith('.git') ? repo.slice(0, -4) : repo;
}

/**
 * Parses user input into a validated `owner/repo`.
 *
 * Accepts the forms people actually paste:
 * `https://github.com/owner/repo`, with or without scheme, `www.`, a trailing slash,
 * a `.git` suffix, or deep paths such as `/tree/main/src`. Also accepts bare
 * `owner/repo`.
 *
 * Rejects anything else, including other hosts, gists and GitHub feature pages.
 */
export function parseRepositoryUrl(input: string): ParseResult {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    return invalid(
      'Enter a GitHub repository URL.',
      'For example: https://github.com/expressjs/express',
    );
  }
  if (trimmed.length > 500) {
    return invalid('That URL is too long to be a GitHub repository.');
  }

  // Reject relative path segments before any parsing.
  //
  // `new URL()` silently resolves them away: `https://github.com/../../etc/passwd`
  // normalises to the path `/etc/passwd`, which would then parse as the repository
  // `etc/passwd`. That particular result is harmless, but no legitimate repository URL
  // contains a `.` or `..` segment, so rejecting outright is both clearer to the user and
  // one less thing depending on URL-normalisation behaviour staying the same.
  // Note this matches whole segments only, so names like `angular.js` are unaffected.
  if (trimmed.split(/[/\\]/).some((segment) => segment === '.' || segment === '..')) {
    return invalid('That URL contains a relative path segment.');
  }

  let pathname: string;

  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(trimmed)) {
    // Has an explicit scheme — it must be http(s) on a GitHub host.
    let url: URL;
    try {
      url = new URL(trimmed);
    } catch {
      return invalid('That does not look like a valid URL.');
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      return unsupported(
        'Only https:// GitHub URLs are supported.',
        'Paste the repository address from your browser.',
      );
    }
    // Reject embedded credentials.
    //
    // `https://user:token@github.com/owner/repo` parses with hostname github.com, so the
    // host check below passes and the credential is silently discarded. No bad request
    // results - DepGuard sends no credentials anywhere - but accepting it quietly is the
    // wrong behaviour: a visitor who pasted a URL containing a real token deserves to be
    // told it was there, not to have it swallowed. It also removes any chance of a future
    // change carrying userinfo into a request URL.
    if (url.username.length > 0 || url.password.length > 0) {
      return invalid(
        'That URL contains embedded credentials.',
        'Remove the username and password from the address. DepGuard never uses credentials.',
      );
    }

    // Reject a non-default port. github.com serves HTTPS on 443 and nothing else, so a
    // port is either a mistake or an attempt to redirect the request somewhere unexpected.
    if (url.port.length > 0 && url.port !== '443') {
      return unsupported(
        `DepGuard only analyses repositories on github.com, not port ${url.port}.`,
      );
    }

    if (!GITHUB_HOSTS.includes(url.hostname.toLowerCase())) {
      return unsupported(
        `DepGuard only analyses repositories on github.com, not ${url.hostname}.`,
        'GitHub Enterprise and other hosts are not supported.',
      );
    }
    pathname = url.pathname;
  } else if (
    trimmed.toLowerCase().startsWith('github.com/') ||
    trimmed.toLowerCase().startsWith('www.github.com/')
  ) {
    pathname = trimmed.slice(trimmed.indexOf('/'));
  } else if (trimmed.includes('://')) {
    return invalid('That does not look like a valid URL.');
  } else {
    // Bare `owner/repo`.
    pathname = `/${trimmed}`;
  }

  const segments = pathname.split('/').filter((segment) => segment.length > 0);
  const rawOwner = segments[0];
  const rawRepo = segments[1];

  if (rawOwner === undefined || rawRepo === undefined) {
    return invalid(
      'That URL does not point to a repository.',
      'A repository URL looks like https://github.com/owner/repository.',
    );
  }

  if (RESERVED_OWNERS.has(rawOwner.toLowerCase())) {
    return unsupported(
      `"${rawOwner}" is a GitHub feature page, not a user or organisation.`,
      'Paste the address of a repository instead.',
    );
  }

  const owner = rawOwner;
  const repo = stripGitSuffix(rawRepo);

  if (!OWNER_PATTERN.test(owner)) {
    return invalid(`"${owner}" is not a valid GitHub owner name.`);
  }
  if (!REPO_PATTERN.test(repo) || repo === '.' || repo === '..') {
    return invalid(`"${repo}" is not a valid GitHub repository name.`);
  }

  return { ok: true, ref: { owner, repo } };
}

/**
 * Encodes a ref for use in an API path.
 *
 * Defence in depth: the patterns above already exclude `/`, `?`, `#` and `..`, so this
 * cannot currently change anything — but it means a future relaxation of those patterns
 * cannot silently become a path-traversal bug.
 */
export function encodeRef(ref: RepositoryRef): { owner: string; repo: string } {
  return { owner: encodeURIComponent(ref.owner), repo: encodeURIComponent(ref.repo) };
}

/** `owner/repo`, for display and cache keys. */
export function formatRef(ref: RepositoryRef): string {
  return `${ref.owner}/${ref.repo}`;
}
