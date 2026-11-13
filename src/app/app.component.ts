import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

import { AnalysisProgressComponent } from './features/analysis/analysis-progress.component';
import { DashboardComponent } from './features/dashboard/dashboard.component';
import { LandingComponent } from './features/landing/landing.component';
import { GithubApiService } from './core/api/github-api.service';
import { RateLimitService } from './core/services/rate-limit.service';
import { ScanStore } from './core/state/scan.store';

/**
 * Application shell.
 *
 * View selection is driven by the scan store's state rather than by a router: DepGuard has
 * two views and the report lives in memory for the session, so a deep link could not
 * restore one without re-running the scan at a cost of 8 of the 60 hourly requests
 * (ADR-0005).
 */
@Component({
  selector: 'dg-root',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LandingComponent, AnalysisProgressComponent, DashboardComponent],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css',
})
export class App {
  private readonly rateLimit = inject(RateLimitService);
  private readonly github = inject(GithubApiService);
  protected readonly store = inject(ScanStore);

  constructor() {
    // Populate the remaining-requests indicator before the first scan. This costs no
    // quota (verified in Phase 0), and it is how a visitor on a shared IP learns their
    // budget is already spent before typing a repository rather than after.
    this.github.primeRateLimit().pipe(takeUntilDestroyed()).subscribe();
  }

  protected readonly repositoryUrl = 'https://github.com/dukeofwest/depguard';

  protected readonly state = this.store.current;

  /**
   * Narrowed views of the scan state.
   *
   * Angular's template type checker does not narrow a discriminated union through
   * `@switch (state().kind)`, and `$any()` would silence the error by disabling type
   * checking for that expression entirely — the template equivalent of a type assertion,
   * which §4.2 forbids. Narrowing here instead keeps the templates fully type-checked.
   */
  protected readonly running = computed(() => {
    const state = this.state();
    return state.kind === 'running' ? state : null;
  });

  protected readonly completed = computed(() => {
    const state = this.state();
    return state.kind === 'completed' ? state : null;
  });

  protected readonly failed = computed(() => {
    const state = this.state();
    return state.kind === 'failed' ? state : null;
  });

  protected readonly cancelled = computed(() => {
    const state = this.state();
    return state.kind === 'cancelled' ? state : null;
  });

  protected readonly remaining = this.rateLimit.remaining;
  protected readonly limit = this.rateLimit.limit;

  protected readonly resetLabel = computed(() => {
    const reset = this.rateLimit.resetDate();
    if (reset === null) {
      return null;
    }
    return reset.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  });

  protected readonly budgetIsLow = computed(() => {
    const remaining = this.remaining();
    return remaining !== null && remaining < 10;
  });

  protected retry(): void {
    this.store.retry();
  }

  protected reset(): void {
    this.store.reset();
  }

  /** A failed scan can only be retried when we know which repository to retry. */
  protected canRetry(): boolean {
    const state = this.state();
    return (
      (state.kind === 'failed' && state.ref !== null && state.error.kind !== 'rate-limited') ||
      state.kind === 'cancelled'
    );
  }

  protected retryTime(): string | null {
    const state = this.state();
    if (state.kind !== 'failed' || state.error.retryAt === undefined) {
      return null;
    }
    return new Date(state.error.retryAt).toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
    });
  }
}
