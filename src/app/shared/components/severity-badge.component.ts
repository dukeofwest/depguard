import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

import type { Severity } from '../../core/models/analysis.model';

/**
 * Severity indicator.
 *
 * §11.6 forbids communicating severity by colour alone, so every badge carries the
 * severity word as text and a distinct glyph shape. The colour is reinforcement, not the
 * message — the badge remains fully readable in greyscale and to screen readers.
 */
@Component({
  selector: 'dg-severity-badge',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <span class="badge" [class]="'badge--' + modifier()">
      <span class="badge__glyph" aria-hidden="true">{{ glyph() }}</span>
      <span class="badge__label">{{ severity() }}</span>
      @if (severity() === 'Unknown') {
        <span class="dg-visually-hidden"> — the advisory source published no severity rating </span>
      }
    </span>
  `,
  styles: `
    .badge {
      display: inline-flex;
      align-items: center;
      gap: var(--space-1);
      padding: 2px var(--space-2);
      border-radius: var(--radius-pill);
      border: 1px solid currentColor;
      font-size: var(--text-xs);
      font-weight: var(--weight-semibold);
      white-space: nowrap;
      line-height: 1.6;
    }

    .badge__glyph {
      font-size: 0.85em;
    }

    .badge--critical {
      color: var(--color-severity-critical);
      background: color-mix(in srgb, var(--color-severity-critical) 12%, transparent);
    }
    .badge--high {
      color: var(--color-severity-high);
      background: color-mix(in srgb, var(--color-severity-high) 12%, transparent);
    }
    .badge--medium {
      color: var(--color-severity-medium);
      background: color-mix(in srgb, var(--color-severity-medium) 12%, transparent);
    }
    .badge--low {
      color: var(--color-severity-low);
      background: color-mix(in srgb, var(--color-severity-low) 12%, transparent);
    }
    .badge--unknown {
      color: var(--color-severity-unknown);
      background: color-mix(in srgb, var(--color-severity-unknown) 12%, transparent);
    }
  `,
})
export class SeverityBadgeComponent {
  readonly severity = input.required<Severity>();

  protected readonly modifier = computed(() => this.severity().toLowerCase());

  /** Distinct shapes so severity survives greyscale printing and colour blindness. */
  protected readonly glyph = computed(() => {
    switch (this.severity()) {
      case 'Critical':
        return '◆'; // filled diamond
      case 'High':
        return '▲'; // filled triangle
      case 'Medium':
        return '●'; // filled circle
      case 'Low':
        return '○'; // hollow circle
      default:
        return '?';
    }
  });
}
