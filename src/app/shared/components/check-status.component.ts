import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

import type { CheckStatus } from '../../core/models/analysis.model';

/**
 * Check status indicator.
 *
 * Four states, never a tick/cross binary, because the evidence often does not justify one
 * (§5.3). "Unknown" is visually distinct from "Not detected": the first means DepGuard
 * could not look, the second means it looked and found nothing — a difference users must
 * be able to see at a glance.
 */
@Component({
  selector: 'dg-check-status',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <span class="status" [class]="'status--' + modifier()">
      <span class="status__glyph" aria-hidden="true">{{ glyph() }}</span>
      <span>{{ status() }}</span>
    </span>
  `,
  styles: `
    .status {
      display: inline-flex;
      align-items: center;
      gap: var(--space-2);
      font-size: var(--text-sm);
      font-weight: var(--weight-medium);
      white-space: nowrap;
    }

    .status__glyph {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      height: 18px;
      border-radius: var(--radius-pill);
      border: 1px solid currentColor;
      font-size: 11px;
      line-height: 1;
      flex: none;
    }

    .status--configured {
      color: var(--color-status-configured);
    }
    .status--not-detected {
      color: var(--color-status-not-detected);
    }
    .status--unknown {
      color: var(--color-status-unknown);
    }
    .status--not-applicable {
      color: var(--color-status-not-applicable);
    }
  `,
})
export class CheckStatusComponent {
  readonly status = input.required<CheckStatus>();

  protected readonly modifier = computed(() => this.status().toLowerCase().replace(/\s+/g, '-'));

  protected readonly glyph = computed(() => {
    switch (this.status()) {
      case 'Configured':
        return '✓'; // tick
      case 'Not detected':
        return '–'; // en dash — looked, found nothing
      case 'Unknown':
        return '?'; // could not look
      default:
        return '·'; // middle dot — not applicable
    }
  });
}
