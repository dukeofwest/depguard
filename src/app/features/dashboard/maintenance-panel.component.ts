import { ChangeDetectionStrategy, Component, input } from '@angular/core';

import type { MaintenanceSignals } from '../../core/models/health-report.model';
import { describeMaintenance } from '../../engine/health/maintenance-analyzer';

/**
 * Maintenance and activity panel (§5.4).
 *
 * Reports observable activity without inferring quality from it. The closing note is not
 * decoration: §5.4 explicitly warns that a low commit count is not evidence of poor
 * quality, because a mature project may legitimately need very few changes.
 *
 * Unknown values are shown as "Unknown", never as zero — a repository whose commit
 * statistics GitHub has not computed has not had zero commits.
 */
@Component({
  selector: 'dg-maintenance-panel',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p class="summary">{{ summary() }}</p>

    <dl class="signals">
      <div>
        <dt>Activity</dt>
        <dd>{{ signals().classification }}</dd>
      </div>
      <div>
        <dt>Days since last push</dt>
        <dd>{{ signals().daysSinceLastPush ?? 'Unknown' }}</dd>
      </div>
      <div>
        <dt>Days since last release</dt>
        <dd>{{ signals().daysSinceLastRelease ?? 'No releases found' }}</dd>
      </div>
      <div>
        <dt>Commits in last 52 weeks</dt>
        <dd>{{ signals().commitsLast52Weeks ?? 'Unknown' }}</dd>
      </div>
      <div>
        <dt>Contributors</dt>
        <dd>{{ signals().contributorCount ?? 'Unknown' }}</dd>
      </div>
    </dl>

    <p class="footnote">
      Commit recency is an activity signal, not a measure of quality. A mature project may
      legitimately need very few changes.
    </p>
  `,
  styles: `
    .summary {
      font-size: var(--text-sm);
      color: var(--color-text-secondary);
      margin-bottom: var(--space-5);
      max-width: 72ch;
    }

    .signals {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: var(--space-4);
    }

    .signals dt {
      font-size: var(--text-xs);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--color-text-muted);
      margin-bottom: var(--space-1);
    }

    .signals dd {
      margin: 0;
      font-size: var(--text-lg);
      color: var(--color-text-primary);
      font-variant-numeric: tabular-nums;
    }

    .footnote {
      margin-top: var(--space-5);
      font-size: var(--text-xs);
      color: var(--color-text-muted);
      max-width: 72ch;
    }
  `,
})
export class MaintenancePanelComponent {
  readonly signals = input.required<MaintenanceSignals>();

  protected summary(): string {
    return describeMaintenance(this.signals());
  }
}
