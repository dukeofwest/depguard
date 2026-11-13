import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

import type { Priority } from '../../core/models/analysis.model';
import type { Recommendation } from '../../core/models/health-report.model';

/**
 * Prioritised recommendations (§7.1, §7.2).
 *
 * Each item shows the evidence that produced it, so a reader can check the reasoning
 * rather than take it on trust. Priority is shown as a word, not only a colour (§11.6).
 */
@Component({
  selector: 'dg-recommendation-list',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (recommendations().length === 0) {
      <p class="empty">
        DepGuard found nothing it would recommend changing, within what it was able to check.
      </p>
    } @else {
      <ol class="recommendations">
        @for (item of visible(); track item.id) {
          <li class="recommendation">
            <div class="recommendation__header">
              <span class="priority" [class]="'priority--' + modifier(item.priority)">
                {{ item.priority }}
              </span>
              <h3 class="recommendation__title">{{ item.title }}</h3>
            </div>
            <p class="recommendation__detail">{{ item.detail }}</p>

            <details class="recommendation__evidence">
              <summary>Why this is recommended</summary>
              <dl>
                <dt>Checked</dt>
                <dd>{{ item.evidence.checked }}</dd>
                <dt>Found</dt>
                <dd>{{ item.evidence.found }}</dd>
                <dt>Explanation</dt>
                <dd>{{ item.evidence.explanation }}</dd>
                @if (item.evidence.limitation) {
                  <dt>Limitation</dt>
                  <dd>{{ item.evidence.limitation }}</dd>
                }
              </dl>
            </details>
          </li>
        }
      </ol>

      @if (hiddenCount() > 0) {
        <p class="empty">
          {{ hiddenCount() }} further
          {{ hiddenCount() === 1 ? 'recommendation' : 'recommendations' }}
          of lower priority are included in the JSON export.
        </p>
      }
    }
  `,
  styles: `
    .recommendations {
      display: grid;
      gap: var(--space-3);
      list-style: none;
      padding: 0;
      counter-reset: recommendation;
    }

    .recommendation {
      padding: var(--space-4);
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-md);
    }

    .recommendation__header {
      display: flex;
      align-items: baseline;
      gap: var(--space-3);
      margin-bottom: var(--space-2);
      flex-wrap: wrap;
    }

    .recommendation__title {
      font-size: var(--text-base);
      font-weight: var(--weight-medium);
      flex: 1 1 260px;
      min-width: 0;
    }

    .recommendation__detail {
      font-size: var(--text-sm);
      color: var(--color-text-secondary);
      max-width: 72ch;
    }

    .priority {
      flex: none;
      padding: 2px var(--space-2);
      border-radius: var(--radius-pill);
      border: 1px solid currentColor;
      font-size: var(--text-xs);
      font-weight: var(--weight-semibold);
      white-space: nowrap;
    }

    .priority--critical {
      color: var(--color-severity-critical);
    }
    .priority--high {
      color: var(--color-severity-high);
    }
    .priority--medium {
      color: var(--color-severity-medium);
    }
    .priority--low {
      color: var(--color-severity-low);
    }
    .priority--informational {
      color: var(--color-text-muted);
    }

    .recommendation__evidence {
      margin-top: var(--space-3);
      font-size: var(--text-xs);
    }

    .recommendation__evidence summary {
      cursor: pointer;
      color: var(--color-accent);
      padding: var(--space-1) 0;
    }

    .recommendation__evidence dl {
      margin-top: var(--space-2);
      padding: var(--space-3);
      background: var(--color-surface-raised);
      border-radius: var(--radius-sm);
    }

    .recommendation__evidence dt {
      color: var(--color-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-top: var(--space-2);
    }

    .recommendation__evidence dt:first-child {
      margin-top: 0;
    }

    .recommendation__evidence dd {
      margin: 2px 0 0;
      color: var(--color-text-secondary);
      max-width: 72ch;
    }

    .empty {
      font-size: var(--text-sm);
      color: var(--color-text-muted);
      margin-top: var(--space-3);
    }
  `,
})
export class RecommendationListComponent {
  readonly recommendations = input.required<readonly Recommendation[]>();
  readonly limit = input(8);

  protected readonly visible = computed(() => this.recommendations().slice(0, this.limit()));
  protected readonly hiddenCount = computed(() =>
    Math.max(0, this.recommendations().length - this.limit()),
  );

  protected modifier(priority: Priority): string {
    return priority.toLowerCase();
  }
}
