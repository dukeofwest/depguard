import { Injectable, computed, inject, signal } from '@angular/core';
import { Subscription } from 'rxjs';

import {
  RepositoryAnalysisService,
  type AnalysisStage,
} from '../services/repository-analysis.service';
import { RateLimitService } from '../services/rate-limit.service';
import { isAppError, createAppError, type AppError } from '../models/api-error.model';
import type { HealthReport } from '../models/health-report.model';
import type { RepositoryRef } from '../models/repository.model';
import { parseRepositoryUrl } from '../utils/github-url';

/**
 * Scan state (§10.4).
 *
 * A signal-based state machine. The invariant that matters: starting a new scan
 * invalidates the previous one, so a slow response from an abandoned scan can never
 * overwrite a current result. Enforced two ways — the previous subscription is
 * unsubscribed, and every emission is checked against a run token before being accepted.
 * The second guard exists because unsubscribing stops delivery but an already-queued
 * emission could still be in flight.
 */

export type ScanState =
  | { readonly kind: 'idle' }
  | {
      readonly kind: 'running';
      readonly ref: RepositoryRef;
      readonly stage: AnalysisStage;
      readonly detail: string | null;
    }
  | { readonly kind: 'completed'; readonly ref: RepositoryRef; readonly report: HealthReport }
  | { readonly kind: 'failed'; readonly ref: RepositoryRef | null; readonly error: AppError }
  | { readonly kind: 'cancelled'; readonly ref: RepositoryRef };

@Injectable({ providedIn: 'root' })
export class ScanStore {
  private readonly analysis = inject(RepositoryAnalysisService);
  private readonly rateLimit = inject(RateLimitService);

  private readonly state = signal<ScanState>({ kind: 'idle' });
  private subscription: Subscription | null = null;

  /** Incremented per scan; emissions carrying a stale token are discarded. */
  private runToken = 0;

  readonly current = this.state.asReadonly();

  readonly isRunning = computed(() => this.state().kind === 'running');

  readonly report = computed(() => {
    const state = this.state();
    return state.kind === 'completed' ? state.report : null;
  });

  readonly error = computed(() => {
    const state = this.state();
    return state.kind === 'failed' ? state.error : null;
  });

  readonly stage = computed(() => {
    const state = this.state();
    return state.kind === 'running' ? state.stage : null;
  });

  /**
   * Validates a URL and starts an analysis.
   *
   * Refuses to start when the remaining GitHub budget cannot cover a whole scan, so the
   * user is told up front rather than discovering it halfway through (ADR-0004).
   */
  start(url: string): void {
    const parsed = parseRepositoryUrl(url);
    if (!parsed.ok) {
      this.state.set({ kind: 'failed', ref: null, error: parsed.error });
      return;
    }

    if (!this.rateLimit.canStartScan()) {
      const resetAt = this.rateLimit.resetDate();
      this.state.set({
        kind: 'failed',
        ref: parsed.ref,
        error: createAppError(
          'rate-limited',
          'GitHub’s hourly limit for anonymous requests has been used up.',
          {
            remedy:
              'DepGuard analyses public repositories without an account, which GitHub limits to 60 requests per hour per IP address.',
            ...(resetAt === null ? {} : { retryAt: resetAt.toISOString() }),
          },
        ),
      });
      return;
    }

    this.runScan(parsed.ref);
  }

  /** Re-runs the current repository. Cached responses make this cheap within a session. */
  retry(): void {
    const state = this.state();
    const ref = state.kind === 'failed' || state.kind === 'cancelled' ? state.ref : null;
    if (ref !== null) {
      this.runScan(ref);
    }
  }

  cancel(): void {
    const state = this.state();
    this.invalidate();
    if (state.kind === 'running') {
      this.state.set({ kind: 'cancelled', ref: state.ref });
    }
  }

  reset(): void {
    this.invalidate();
    this.state.set({ kind: 'idle' });
  }

  private runScan(ref: RepositoryRef): void {
    this.invalidate();

    const token = ++this.runToken;
    this.state.set({ kind: 'running', ref, stage: 'validating', detail: null });

    this.subscription = this.analysis.analyse(ref).subscribe({
      next: (progress) => {
        // Discard anything from a scan the user has moved on from.
        if (token !== this.runToken) {
          return;
        }
        if (progress.kind === 'progress') {
          this.state.set({
            kind: 'running',
            ref,
            stage: progress.stage,
            detail: progress.detail ?? null,
          });
        } else {
          this.state.set({ kind: 'completed', ref, report: progress.report });
        }
      },
      error: (error: unknown) => {
        if (token !== this.runToken) {
          return;
        }
        this.state.set({
          kind: 'failed',
          ref,
          error: isAppError(error)
            ? error
            : createAppError('internal', 'Something went wrong while analysing this repository.'),
        });
      },
    });
  }

  /** Stops the in-flight scan and makes its remaining emissions unacceptable. */
  private invalidate(): void {
    this.runToken++;
    this.subscription?.unsubscribe();
    this.subscription = null;
  }
}
