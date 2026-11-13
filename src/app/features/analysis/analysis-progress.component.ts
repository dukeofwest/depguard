import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';

import { ScanStore } from '../../core/state/scan.store';
import { STAGE_LABELS, type AnalysisStage } from '../../core/services/repository-analysis.service';
import type { RepositoryRef } from '../../core/models/repository.model';

/**
 * Analysis progress (§11.3).
 *
 * Shows which stages have actually completed. There is no percentage and no timer —
 * §11.3 forbids artificial progress, and a fake bar would imply knowledge of a duration
 * that depends on network latency and repository size.
 */
@Component({
  selector: 'dg-analysis-progress',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="progress" aria-labelledby="progress-heading">
      <h1 class="progress__heading" id="progress-heading">
        Analysing <span class="progress__repo">{{ ref().owner }}/{{ ref().repo }}</span>
      </h1>

      <ol class="progress__stages" aria-live="polite">
        @for (item of stages(); track item.stage) {
          <li
            class="stage"
            [class.stage--done]="item.state === 'done'"
            [class.stage--active]="item.state === 'active'"
          >
            <span class="stage__marker" aria-hidden="true">
              @switch (item.state) {
                @case ('done') {
                  &#10003;
                }
                @case ('active') {
                  <span class="stage__pulse"></span>
                }
                @default {
                  &#183;
                }
              }
            </span>
            <span class="stage__label">
              {{ item.label }}
              @if (item.state === 'active' && detail()) {
                <span class="stage__detail">({{ detail() }})</span>
              }
            </span>
            @if (item.state === 'active') {
              <span class="dg-visually-hidden">in progress</span>
            }
            @if (item.state === 'done') {
              <span class="dg-visually-hidden">complete</span>
            }
          </li>
        }
      </ol>

      <button class="progress__cancel" type="button" (click)="cancel()">Cancel analysis</button>
    </section>
  `,
  styles: `
    .progress {
      max-width: 36rem;
      padding-block: var(--space-7);
    }

    .progress__heading {
      font-size: var(--text-2xl);
      margin-bottom: var(--space-6);
    }

    .progress__repo {
      font-family: var(--font-mono);
      color: var(--color-accent);
      font-size: 0.9em;
    }

    .progress__stages {
      display: grid;
      gap: var(--space-3);
      margin-bottom: var(--space-6);
      list-style: none;
      padding: 0;
    }

    .stage {
      display: flex;
      align-items: baseline;
      gap: var(--space-3);
      color: var(--color-text-muted);
      font-size: var(--text-sm);
    }

    .stage--done {
      color: var(--color-text-secondary);
    }

    .stage--active {
      color: var(--color-text-primary);
      font-weight: var(--weight-medium);
    }

    .stage__marker {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      flex: none;
      color: var(--color-text-muted);
    }

    .stage--done .stage__marker {
      color: var(--color-success);
    }

    .stage--active .stage__marker {
      color: var(--color-accent);
    }

    .stage__pulse {
      width: 8px;
      height: 8px;
      border-radius: var(--radius-pill);
      background: currentColor;
      animation: pulse 1.4s ease-in-out infinite;
    }

    @keyframes pulse {
      0%,
      100% {
        opacity: 0.35;
      }
      50% {
        opacity: 1;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      .stage__pulse {
        animation: none;
        opacity: 1;
      }
    }

    .stage__detail {
      color: var(--color-text-muted);
      font-weight: var(--weight-normal);
    }

    .progress__cancel {
      padding: var(--space-2) var(--space-4);
      background: transparent;
      border: 1px solid var(--color-border-strong);
      border-radius: var(--radius-md);
      color: var(--color-text-secondary);
      font-size: var(--text-sm);
      cursor: pointer;
    }

    .progress__cancel:hover {
      border-color: var(--color-danger);
      color: var(--color-text-primary);
    }
  `,
})
export class AnalysisProgressComponent {
  private readonly store = inject(ScanStore);

  readonly ref = input.required<RepositoryRef>();
  readonly stage = input.required<AnalysisStage>();
  readonly detail = input<string | null>(null);

  /** Stages shown to the user. `validating` is too brief to be worth a line. */
  private readonly visibleStages: readonly AnalysisStage[] = [
    'fetching-repository',
    'fetching-sbom',
    'analysing-dependencies',
    'querying-vulnerabilities',
    'evaluating',
  ] as const;

  protected readonly stages = computed(() => {
    const currentIndex = this.visibleStages.indexOf(this.stage());
    // `fetching-advisories` is a sub-step of querying; `validating` precedes everything.
    const effectiveIndex =
      currentIndex >= 0
        ? currentIndex
        : this.stage() === 'fetching-advisories'
          ? this.visibleStages.indexOf('querying-vulnerabilities')
          : 0;

    return this.visibleStages.map((stage, index) => ({
      stage,
      label: STAGE_LABELS[stage],
      state: index < effectiveIndex ? 'done' : index === effectiveIndex ? 'active' : 'pending',
    }));
  });

  protected cancel(): void {
    this.store.cancel();
  }
}
