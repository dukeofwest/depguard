import { Injectable, computed, signal } from '@angular/core';
import type { HttpHeaders } from '@angular/common/http';
import { RATE_LIMIT } from '../config/api.config';

/**
 * Tracks the GitHub API rate limit (ADR-0004).
 *
 * Anonymous GitHub REST allows 60 requests per hour per IP — the binding constraint on
 * the whole product. Rather than discovering exhaustion by failing mid-scan, the budget
 * is read from every response and surfaced in the UI.
 *
 * Phase 0 verified in a real browser that `x-ratelimit-remaining` is readable from
 * JavaScript (it depends on `Access-Control-Expose-Headers`, which curl cannot test).
 * See docs/phase-0/BROWSER-CORS-PROOF.md — without that, this service is impossible.
 */
export interface RateLimitState {
  readonly limit: number;
  readonly remaining: number;
  /** Unix epoch seconds when the window resets. */
  readonly resetAt: number;
  /** When this reading was taken, so staleness is visible. */
  readonly observedAt: number;
}

@Injectable({ providedIn: 'root' })
export class RateLimitService {
  private readonly state = signal<RateLimitState | null>(null);

  /** Latest known rate-limit state, or null before the first response. */
  readonly current = this.state.asReadonly();

  readonly remaining = computed(() => this.state()?.remaining ?? null);
  readonly limit = computed(() => this.state()?.limit ?? null);

  /** Reset time as a Date, for display. */
  readonly resetDate = computed(() => {
    const resetAt = this.state()?.resetAt;
    return resetAt === undefined ? null : new Date(resetAt * 1000);
  });

  /**
   * Whether a scan can start.
   *
   * Unknown budget is permissive: before the first request there is nothing to go on, and
   * blocking the user on absent information would be worse than letting the attempt
   * proceed and reporting a real 403.
   */
  readonly canStartScan = computed(() => {
    const remaining = this.remaining();
    return remaining === null || remaining >= RATE_LIMIT.minimumRemainingToStart;
  });

  /** Approximate scans left in this window, for the UI. */
  readonly scansRemaining = computed(() => {
    const remaining = this.remaining();
    return remaining === null ? null : Math.floor(remaining / RATE_LIMIT.requestsPerScan);
  });

  /**
   * Updates from response headers.
   *
   * Called for every GitHub response including errors, because a 403 carries the headers
   * that explain why. Malformed or absent headers leave the previous state untouched
   * rather than zeroing it — a missing header is not a budget of zero.
   */
  updateFromHeaders(headers: HttpHeaders): void {
    const limit = this.parseHeader(headers, 'x-ratelimit-limit');
    const remaining = this.parseHeader(headers, 'x-ratelimit-remaining');
    const reset = this.parseHeader(headers, 'x-ratelimit-reset');

    if (limit === null || remaining === null || reset === null) {
      return;
    }

    this.state.set({ limit, remaining, resetAt: reset, observedAt: Date.now() });
  }

  /**
   * Records a known-exhausted budget when GitHub returns 403 without usable headers.
   *
   * `resetAt` is only overwritten when a fresh value is supplied, so an existing reset
   * time is not lost.
   */
  markExhausted(resetAt: number | null): void {
    const previous = this.state();
    this.state.set({
      limit: previous?.limit ?? 60,
      remaining: 0,
      resetAt: resetAt ?? previous?.resetAt ?? Math.floor(Date.now() / 1000) + 3600,
      observedAt: Date.now(),
    });
  }

  private parseHeader(headers: HttpHeaders, name: string): number | null {
    const raw = headers.get(name);
    if (raw === null) {
      return null;
    }
    const value = Number.parseInt(raw, 10);
    return Number.isFinite(value) && value >= 0 ? value : null;
  }
}
