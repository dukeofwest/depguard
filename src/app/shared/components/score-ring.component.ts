import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

import type { ScoreBand } from '../../core/models/health-report.model';

/**
 * Circular score indicator.
 *
 * Renders the number as text first and the ring as decoration, so the value is available
 * to screen readers and in greyscale. The band word always accompanies the number, since
 * the colour alone must not carry the verdict (§11.6).
 */
@Component({
  selector: 'dg-score-ring',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="ring" [class]="'ring--' + modifier()" [style.--dg-progress]="progress()">
      <svg class="ring__svg" viewBox="0 0 120 120" aria-hidden="true" focusable="false">
        <circle class="ring__track" cx="60" cy="60" r="52" />
        <circle
          class="ring__value"
          cx="60"
          cy="60"
          r="52"
          [attr.stroke-dasharray]="circumference()"
          [attr.stroke-dashoffset]="offset()"
        />
      </svg>
      <div class="ring__content">
        <span class="ring__score">{{ score() }}</span>
        <span class="ring__total">/ 100</span>
      </div>
    </div>
  `,
  styles: `
    .ring {
      position: relative;
      display: grid;
      place-items: center;
      width: var(--dg-ring-size, 140px);
      height: var(--dg-ring-size, 140px);
    }

    .ring__svg {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      transform: rotate(-90deg);
    }

    .ring__track {
      fill: none;
      stroke: var(--color-border);
      stroke-width: 8;
    }

    .ring__value {
      fill: none;
      stroke: currentColor;
      stroke-width: 8;
      stroke-linecap: round;
      transition: stroke-dashoffset var(--duration-base) var(--ease-standard);
    }

    .ring__content {
      position: relative;
      display: flex;
      align-items: baseline;
      gap: 2px;
    }

    .ring__score {
      font-size: 2.25rem;
      font-weight: var(--weight-bold);
      letter-spacing: -0.03em;
      color: var(--color-text-primary);
      font-variant-numeric: tabular-nums;
    }

    .ring__total {
      font-size: var(--text-sm);
      color: var(--color-text-muted);
    }

    .ring--excellent {
      color: var(--color-success);
    }
    .ring--good {
      color: #84cc16;
    }
    .ring--fair {
      color: var(--color-warning);
    }
    .ring--needs-attention {
      color: #fb923c;
    }
    .ring--poor {
      color: var(--color-danger);
    }
  `,
})
export class ScoreRingComponent {
  readonly score = input.required<number>();
  readonly band = input.required<ScoreBand>();

  protected readonly modifier = computed(() => this.band().toLowerCase().replace(/\s+/g, '-'));
  protected readonly circumference = computed(() => 2 * Math.PI * 52);
  protected readonly progress = computed(() => Math.max(0, Math.min(100, this.score())) / 100);
  protected readonly offset = computed(() => this.circumference() * (1 - this.progress()));
}
