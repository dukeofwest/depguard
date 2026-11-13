import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';

import { ScanStore } from '../../core/state/scan.store';
import { RateLimitService } from '../../core/services/rate-limit.service';
import { parseRepositoryUrl } from '../../core/utils/github-url';

/**
 * Landing page (§11.2).
 *
 * Validates the URL before any request is made, so an obvious mistake costs nothing from
 * a budget of 60 requests per hour.
 */
@Component({
  selector: 'dg-landing',
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './landing.component.html',
  styleUrl: './landing.component.css',
})
export class LandingComponent {
  private readonly store = inject(ScanStore);
  private readonly rateLimit = inject(RateLimitService);

  protected readonly url = signal('');
  /** Validation messages appear only after a submit attempt, not while typing. */
  protected readonly submitted = signal(false);

  protected readonly examples: readonly string[] = [
    'expressjs/express',
    'npm/cli',
    'psf/requests',
  ] as const;

  protected readonly validationError = computed(() => {
    if (!this.submitted() || this.url().trim().length === 0) {
      return null;
    }
    const parsed = parseRepositoryUrl(this.url());
    return parsed.ok ? null : parsed.error;
  });

  protected readonly scansRemaining = this.rateLimit.scansRemaining;
  protected readonly canScan = this.rateLimit.canStartScan;

  protected readonly categories: readonly { title: string; detail: string }[] = [
    {
      title: 'Dependency security',
      detail:
        'Known advisories affecting dependencies, matched against resolved versions via OSV.dev.',
    },
    {
      title: 'Dependency health',
      detail: 'Inventory size, ecosystems, and how much of it carries usable version metadata.',
    },
    {
      title: 'Security configuration',
      detail: 'Security policy, Dependabot configuration, CodeQL and dependency review workflows.',
    },
    {
      title: 'Maintenance and activity',
      detail: 'Commit and release recency, contributors, and whether the repository is archived.',
    },
    {
      title: 'Engineering quality',
      detail: 'Documentation, test configuration, CI/CD and licensing signals.',
    },
  ] as const;

  protected onInput(event: Event): void {
    const target = event.target;
    if (target instanceof HTMLInputElement) {
      this.url.set(target.value);
    }
  }

  protected submit(event: Event): void {
    event.preventDefault();
    this.submitted.set(true);
    const value = this.url().trim();
    if (value.length === 0) {
      return;
    }
    this.store.start(value);
  }

  protected useExample(example: string): void {
    this.url.set(example);
    this.submitted.set(false);
    this.store.start(example);
  }
}
