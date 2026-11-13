import { ChangeDetectionStrategy, Component, input } from '@angular/core';

import type { AnalysisLimitation, DataSourceInfo } from '../../core/models/health-report.model';

/**
 * Overview panel: what the report cannot tell you, and where its data came from.
 *
 * Limitations are shown as the first tab rather than buried in a footer, because §2.4
 * treats transparency as taking precedence over impressive-looking scores. A reader who
 * sees a clean report should find out here what that result does and does not cover.
 */
@Component({
  selector: 'dg-analysis-overview',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h3 class="heading">Analysis limitations</h3>
    <p class="intro">
      What this report does not and cannot tell you. These apply to every DepGuard report, not only
      this one.
    </p>
    <ul class="limitations">
      @for (limitation of limitations(); track limitation.scope) {
        <li>
          <strong>{{ limitation.scope }}:</strong>
          {{ limitation.detail }}
        </li>
      }
    </ul>

    <h3 class="heading">Data sources</h3>
    <ul class="sources">
      @for (source of dataSources(); track source.name) {
        <li>
          <span class="sources__name">{{ source.name }}</span>
          <code class="sources__endpoint">{{ source.endpoint }}</code>
          <span class="sources__status" [class]="'sources__status--' + source.status">
            {{ source.status }}
          </span>
        </li>
      }
    </ul>

    <p class="footnote">Report schema {{ schemaVersion() }} · generated {{ generatedAt() }} UTC</p>
  `,
  styles: `
    .heading {
      font-size: var(--text-base);
      margin-block: var(--space-5) var(--space-3);
    }

    .heading:first-child {
      margin-top: 0;
    }

    .intro {
      font-size: var(--text-sm);
      color: var(--color-text-secondary);
      margin-bottom: var(--space-4);
      max-width: 72ch;
    }

    .limitations {
      display: grid;
      gap: var(--space-2);
      list-style: none;
      padding: 0;
    }

    .limitations li {
      position: relative;
      padding-left: var(--space-4);
      font-size: var(--text-sm);
      color: var(--color-text-secondary);
      max-width: 78ch;
    }

    .limitations li::before {
      content: '\\2014';
      position: absolute;
      left: 0;
      color: var(--color-text-muted);
    }

    .limitations strong {
      color: var(--color-text-primary);
    }

    .sources {
      display: grid;
      gap: var(--space-2);
      list-style: none;
      padding: 0;
    }

    .sources li {
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      gap: var(--space-3);
      font-size: var(--text-xs);
    }

    .sources__name {
      color: var(--color-text-primary);
      min-width: 14rem;
    }

    .sources__endpoint {
      color: var(--color-text-muted);
      word-break: break-all;
    }

    .sources__status {
      padding: 1px var(--space-2);
      border-radius: var(--radius-pill);
      border: 1px solid currentColor;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .sources__status--ok {
      color: var(--color-success);
    }

    .sources__status--partial {
      color: var(--color-warning);
    }

    .sources__status--unavailable {
      color: var(--color-status-unknown);
    }

    .footnote {
      margin-top: var(--space-4);
      font-size: var(--text-xs);
      color: var(--color-text-muted);
    }
  `,
})
export class AnalysisOverviewComponent {
  readonly limitations = input.required<readonly AnalysisLimitation[]>();
  readonly dataSources = input.required<readonly DataSourceInfo[]>();
  readonly schemaVersion = input.required<string>();
  readonly generatedAt = input.required<string>();
}
