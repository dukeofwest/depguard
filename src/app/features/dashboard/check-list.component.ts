import { ChangeDetectionStrategy, Component, input } from '@angular/core';

import { CheckStatusComponent } from '../../shared/components/check-status.component';
import type { SecurityCheck } from '../../core/models/health-report.model';

/**
 * Check results with their evidence (§5.3).
 *
 * Every check shows what was examined, what was found, the source, and the explanation —
 * including what the finding does *not* prove. The evidence is shown inline rather than
 * hidden behind a disclosure, because a status without its caveat is exactly the kind of
 * overclaim the specification is written to prevent.
 */
@Component({
  selector: 'dg-check-list',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CheckStatusComponent],
  template: `
    <ul class="checks">
      @for (check of checks(); track check.id) {
        <li class="check">
          <div class="check__header">
            <h3 class="check__label">{{ check.label }}</h3>
            <dg-check-status [status]="check.status" />
          </div>

          <p class="check__found">{{ check.evidence.found }}</p>
          <p class="check__explanation">{{ check.evidence.explanation }}</p>

          @if (check.evidence.limitation) {
            <p class="check__limitation">
              <span class="check__limitation-label">Limitation:</span>
              {{ check.evidence.limitation }}
            </p>
          }

          <p class="check__source">
            <span class="check__source-label">Checked:</span>
            <code>{{ check.evidence.checked }}</code>
          </p>
        </li>
      }
    </ul>
  `,
  styles: `
    .checks {
      display: grid;
      gap: var(--space-3);
      list-style: none;
      padding: 0;
    }

    .check {
      padding: var(--space-4);
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-md);
    }

    .check__header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: var(--space-4);
      margin-bottom: var(--space-3);
      flex-wrap: wrap;
    }

    .check__label {
      font-size: var(--text-base);
      font-weight: var(--weight-medium);
    }

    .check__found {
      font-size: var(--text-sm);
      color: var(--color-text-primary);
      margin-bottom: var(--space-2);
    }

    .check__explanation {
      font-size: var(--text-sm);
      color: var(--color-text-secondary);
      max-width: 72ch;
    }

    .check__limitation {
      margin-top: var(--space-3);
      padding: var(--space-2) var(--space-3);
      background: var(--color-surface-raised);
      border-left: 2px solid var(--color-status-unknown);
      border-radius: var(--radius-sm);
      font-size: var(--text-xs);
      color: var(--color-text-secondary);
      max-width: 72ch;
    }

    .check__limitation-label {
      color: var(--color-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-right: var(--space-1);
    }

    .check__source {
      margin-top: var(--space-3);
      font-size: var(--text-xs);
      color: var(--color-text-muted);
    }

    .check__source-label {
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-right: var(--space-1);
    }

    .check__source code {
      word-break: break-word;
    }
  `,
})
export class CheckListComponent {
  readonly checks = input.required<readonly SecurityCheck[]>();
}
