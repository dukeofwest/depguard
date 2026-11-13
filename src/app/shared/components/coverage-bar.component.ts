import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

/**
 * Coverage indicator.
 *
 * §6.3 requires coverage to be displayed with equal prominence to the score: "A score of
 * 92 with 45% coverage must not look equivalent to a score of 92 with 100% coverage."
 *
 * Low coverage is therefore shown in a cautionary colour rather than a reassuring one —
 * but coverage is not a score, so it is never coloured green. Green would imply approval
 * of a figure that only describes how much was examined.
 */
@Component({
  selector: 'dg-coverage-bar',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="coverage">
      <div class="coverage__header">
        <span class="coverage__label">{{ label() }}</span>
        <span class="coverage__value">{{ percentage() }}%</span>
      </div>
      <div
        class="coverage__track"
        role="meter"
        [attr.aria-valuenow]="percentage()"
        aria-valuemin="0"
        aria-valuemax="100"
        [attr.aria-label]="label() + ': ' + percentage() + ' per cent of the intended analysis'"
      >
        <div
          class="coverage__fill"
          [class.coverage__fill--low]="isLow()"
          [style.width.%]="percentage()"
        ></div>
      </div>
    </div>
  `,
  styles: `
    .coverage__header {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: var(--space-3);
      margin-bottom: var(--space-2);
    }

    .coverage__label {
      font-size: var(--text-sm);
      color: var(--color-text-secondary);
    }

    .coverage__value {
      font-size: var(--text-sm);
      font-weight: var(--weight-semibold);
      font-variant-numeric: tabular-nums;
    }

    .coverage__track {
      height: 6px;
      border-radius: var(--radius-pill);
      background: var(--color-border);
      overflow: hidden;
    }

    .coverage__fill {
      height: 100%;
      border-radius: var(--radius-pill);
      background: var(--color-accent);
      transition: width var(--duration-base) var(--ease-standard);
    }

    .coverage__fill--low {
      background: var(--color-warning);
    }
  `,
})
export class CoverageBarComponent {
  /** 0–1. */
  readonly coverage = input.required<number>();
  readonly label = input('Analysis coverage');

  protected readonly percentage = computed(() =>
    Math.round(Math.max(0, Math.min(1, this.coverage())) * 100),
  );

  protected readonly isLow = computed(() => this.percentage() < 70);
}
