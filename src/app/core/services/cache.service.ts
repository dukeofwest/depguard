import { Injectable } from '@angular/core';
import { Observable, shareReplay } from 'rxjs';

/**
 * In-memory response cache with in-flight request deduplication (§8.4).
 *
 * Two distinct jobs, both required by the 60 requests/hour budget:
 *
 * 1. **Caching** — re-analysing a repository in the same session costs no quota.
 * 2. **Deduplication** — concurrent callers asking for the same URL share one request,
 *    so a scan cannot accidentally spend two of its nine requests on the same endpoint.
 *
 * Session-scoped by design. Nothing is written to `localStorage`: the spec forbids
 * unnecessary storage (§14), and a stale cached report surviving a page reload would be
 * worse than spending the quota again.
 */

interface CacheEntry<T> {
  readonly value: T;
  readonly expiresAt: number;
}

/** Default lifetime. Long enough for one working session, short enough to stay current. */
const DEFAULT_TTL_MS = 15 * 60 * 1000;

@Injectable({ providedIn: 'root' })
export class CacheService {
  private readonly entries = new Map<string, CacheEntry<unknown>>();
  private readonly inFlight = new Map<string, Observable<unknown>>();

  /**
   * Returns a cached value, or runs `factory` and caches its result.
   *
   * An in-flight request is shared rather than duplicated. If the request fails, the
   * in-flight entry is cleared so a retry is possible — caching a failure would make the
   * error permanent for the session.
   */
  getOrCreate<T>(key: string, factory: () => Observable<T>, ttlMs = DEFAULT_TTL_MS): Observable<T> {
    const cached = this.entries.get(key);
    if (cached !== undefined && cached.expiresAt > Date.now()) {
      return new Observable<T>((subscriber) => {
        subscriber.next(cached.value as T);
        subscriber.complete();
      });
    }
    if (cached !== undefined) {
      this.entries.delete(key);
    }

    const existing = this.inFlight.get(key);
    if (existing !== undefined) {
      return existing as Observable<T>;
    }

    const request = new Observable<T>((subscriber) => {
      const subscription = factory().subscribe({
        next: (value) => {
          this.entries.set(key, { value, expiresAt: Date.now() + ttlMs });
          subscriber.next(value);
        },
        error: (error: unknown) => {
          this.inFlight.delete(key);
          subscriber.error(error);
        },
        complete: () => {
          this.inFlight.delete(key);
          subscriber.complete();
        },
      });
      return () => {
        // Also clear the in-flight entry when the request is torn down without
        // completing — i.e. cancelled. Otherwise a cancelled scan would leave a dead
        // entry behind and every later request for the same URL would wait on an
        // observable that never emits.
        this.inFlight.delete(key);
        subscription.unsubscribe();
      };
    }).pipe(
      // refCount:true tears the request down only when the LAST subscriber leaves, so
      // concurrent callers still share one request while a genuinely abandoned request
      // is aborted rather than running on. Cancellation is a stated requirement (§10.4),
      // and an un-cancellable request would keep writing to a cache the user has moved on
      // from.
      shareReplay({ bufferSize: 1, refCount: true }),
    );

    this.inFlight.set(key, request);
    return request;
  }

  /** True when a live, unexpired entry exists. */
  has(key: string): boolean {
    const entry = this.entries.get(key);
    return entry !== undefined && entry.expiresAt > Date.now();
  }

  /** Drops everything. Used when the user explicitly asks for a fresh analysis. */
  clear(): void {
    this.entries.clear();
    this.inFlight.clear();
  }

  /** Number of live entries, for diagnostics and tests. */
  get size(): number {
    const now = Date.now();
    let live = 0;
    for (const entry of this.entries.values()) {
      if (entry.expiresAt > now) {
        live++;
      }
    }
    return live;
  }
}
