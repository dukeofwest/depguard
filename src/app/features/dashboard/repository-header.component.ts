import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';

import type { RepositoryMetadata } from '../../core/models/repository.model';

/**
 * Repository identity header (§11.4 A).
 *
 * Split out of the dashboard because it is a self-contained region with its own data and
 * actions — which also keeps each component's stylesheet within budget.
 */
@Component({
  selector: 'dg-repository-header',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header class="repo">
      <div class="repo__main">
        <h1 class="repo__name">
          <a [href]="repository().htmlUrl" target="_blank" rel="noopener noreferrer">
            {{ repository().fullName }}
            <span class="dg-visually-hidden">(opens on GitHub in a new tab)</span>
          </a>
        </h1>

        @if (repository().description; as description) {
          <p class="repo__description">{{ description }}</p>
        }

        <dl class="repo__stats">
          <div>
            <dt>Stars</dt>
            <dd>{{ repository().stars.toLocaleString() }}</dd>
          </div>
          <div>
            <dt>Forks</dt>
            <dd>{{ repository().forks.toLocaleString() }}</dd>
          </div>
          <div>
            <dt>Open issues</dt>
            <dd>{{ repository().openIssues.toLocaleString() }}</dd>
          </div>
          <div>
            <dt>Branch</dt>
            <dd>{{ repository().defaultBranch }}</dd>
          </div>
          <div>
            <dt>Last push</dt>
            <dd>{{ pushedAt() }}</dd>
          </div>
          @if (repository().licenseSpdxId; as license) {
            <div>
              <dt>Licence</dt>
              <dd>{{ license }}</dd>
            </div>
          }
        </dl>

        @if (repository().isArchived) {
          <p class="repo__archived">Archived — no longer maintained by its owner</p>
        }
      </div>

      <div class="repo__actions">
        <button class="button button--ghost" type="button" (click)="newScan.emit()">
          New analysis
        </button>
        <button class="button" type="button" (click)="exportJson.emit()">Export JSON</button>
      </div>
    </header>
  `,
  styles: `
    .repo {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: var(--space-5);
      flex-wrap: wrap;
      padding-bottom: var(--space-5);
      border-bottom: 1px solid var(--color-border);
    }

    .repo__name {
      font-size: var(--text-2xl);
      letter-spacing: -0.01em;
      margin-bottom: var(--space-2);
      word-break: break-word;
    }

    .repo__name a {
      color: var(--color-text-primary);
      text-decoration: none;
    }

    .repo__name a:hover {
      color: var(--color-accent);
    }

    .repo__description {
      color: var(--color-text-secondary);
      max-width: 60ch;
      margin-bottom: var(--space-4);
    }

    .repo__stats {
      display: flex;
      flex-wrap: wrap;
      gap: var(--space-2) var(--space-5);
    }

    .repo__stats dt {
      font-size: var(--text-xs);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--color-text-muted);
    }

    .repo__stats dd {
      margin: 2px 0 0;
      font-size: var(--text-sm);
      color: var(--color-text-primary);
      font-variant-numeric: tabular-nums;
    }

    .repo__archived {
      margin-top: var(--space-3);
      display: inline-block;
      padding: var(--space-1) var(--space-3);
      border: 1px solid var(--color-warning);
      border-radius: var(--radius-pill);
      color: var(--color-warning);
      font-size: var(--text-xs);
    }

    .repo__actions {
      display: flex;
      gap: var(--space-2);
      flex-wrap: wrap;
    }

    .button {
      padding: var(--space-2) var(--space-4);
      background: var(--color-accent-strong);
      border: 1px solid var(--color-accent-strong);
      border-radius: var(--radius-md);
      color: #fff;
      font-size: var(--text-sm);
      font-weight: var(--weight-medium);
      cursor: pointer;
    }

    .button:hover {
      background: var(--color-accent-hover);
      border-color: var(--color-accent-hover);
    }

    .button--ghost {
      background: transparent;
      border-color: var(--color-border-strong);
      color: var(--color-text-secondary);
    }

    .button--ghost:hover {
      background: var(--color-surface-hover);
      border-color: var(--color-accent);
      color: var(--color-text-primary);
    }

    @media (max-width: 640px) {
      .repo__actions {
        width: 100%;
      }

      .button {
        flex: 1 1 auto;
      }
    }
  `,
})
export class RepositoryHeaderComponent {
  readonly repository = input.required<RepositoryMetadata>();

  readonly newScan = output<void>();
  readonly exportJson = output<void>();

  protected pushedAt(): string {
    const value = this.repository().pushedAt;
    return value === null ? 'Unknown' : value.slice(0, 10);
  }
}
