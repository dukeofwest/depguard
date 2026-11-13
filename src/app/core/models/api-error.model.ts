/**
 * Typed application errors (§10.5).
 *
 * Raw errors never reach the UI. Each variant carries what the interface needs to explain
 * the situation and, where possible, what the user can do about it. Stack traces and raw
 * API bodies are deliberately excluded (§10.5, §14).
 */
export type AppErrorKind =
  | 'invalid-url'
  | 'unsupported-url'
  | 'repository-not-found'
  | 'repository-inaccessible'
  | 'rate-limited'
  | 'github-unavailable'
  | 'sbom-unavailable'
  | 'sbom-invalid'
  | 'osv-unavailable'
  | 'response-too-large'
  | 'network'
  | 'cancelled'
  | 'internal';

export interface AppError {
  readonly kind: AppErrorKind;
  /** Short, user-facing message. Safe to render directly. */
  readonly message: string;
  /** What the user can do, where there is something. */
  readonly remedy?: string;
  /**
   * When the GitHub rate limit resets (ISO 8601). Only set for `rate-limited`, where
   * retrying before this time cannot succeed.
   */
  readonly retryAt?: string;
  /** Non-sensitive diagnostic context for development; never rendered verbatim. */
  readonly context?: string;
}

export function createAppError(
  kind: AppErrorKind,
  message: string,
  extra?: Omit<AppError, 'kind' | 'message'>,
): AppError {
  return { kind, message, ...extra };
}

/** Narrows an unknown caught value to an AppError. */
export function isAppError(value: unknown): value is AppError {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const candidate = value as { kind?: unknown; message?: unknown };
  return typeof candidate.kind === 'string' && typeof candidate.message === 'string';
}
