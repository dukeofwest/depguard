import { ChangeDetectionStrategy, Component, computed, input, signal } from '@angular/core';

import { SeverityBadgeComponent } from '../../shared/components/severity-badge.component';
import type { Severity } from '../../core/models/analysis.model';
import type { DependencyRow, SkipReason } from '../../core/models/dependency.model';

/**
 * Searchable, filterable dependency inventory (§5.2).
 *
 * The important column is "Checked". A package with no vulnerabilities and `wasChecked:
 * false` was never examined — a different statement from "examined and clean" — so the two
 * render differently and can be filtered apart.
 *
 * On narrow screens the table becomes a card list rather than a horizontally scrolling
 * table (§11.5: do not simply shrink desktop content).
 */
@Component({
  selector: 'dg-dependency-table',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SeverityBadgeComponent],
  templateUrl: './dependency-table.component.html',
  styleUrl: './dependency-table.component.css',
})
export class DependencyTableComponent {
  readonly rows = input.required<readonly DependencyRow[]>();

  protected readonly search = signal('');
  protected readonly ecosystemFilter = signal<string>('all');
  protected readonly statusFilter = signal<'all' | 'vulnerable' | 'clean' | 'unchecked'>('all');

  /** Rows are capped for rendering; large inventories would otherwise stall the page. */
  private readonly renderLimit = 250;

  protected readonly ecosystems = computed(() => {
    const seen = new Set<string>();
    for (const row of this.rows()) {
      seen.add(row.package.ecosystem ?? row.package.purlType ?? 'unknown');
    }
    return [...seen].sort();
  });

  protected readonly filtered = computed(() => {
    const term = this.search().trim().toLowerCase();
    const ecosystem = this.ecosystemFilter();
    const status = this.statusFilter();

    return this.rows().filter((row) => {
      if (term.length > 0 && !row.package.name.toLowerCase().includes(term)) {
        return false;
      }
      if (ecosystem !== 'all') {
        const rowEcosystem = row.package.ecosystem ?? row.package.purlType ?? 'unknown';
        if (rowEcosystem !== ecosystem) {
          return false;
        }
      }
      switch (status) {
        case 'vulnerable':
          return row.vulnerabilityCount > 0;
        case 'clean':
          return row.wasChecked && row.vulnerabilityCount === 0;
        case 'unchecked':
          return !row.wasChecked;
        default:
          return true;
      }
    });
  });

  protected readonly visible = computed(() => this.filtered().slice(0, this.renderLimit));
  protected readonly hiddenCount = computed(() =>
    Math.max(0, this.filtered().length - this.renderLimit),
  );

  protected readonly counts = computed(() => {
    const rows = this.rows();
    return {
      total: rows.length,
      vulnerable: rows.filter((row) => row.vulnerabilityCount > 0).length,
      unchecked: rows.filter((row) => !row.wasChecked).length,
    };
  });

  protected onSearch(event: Event): void {
    const target = event.target;
    if (target instanceof HTMLInputElement) {
      this.search.set(target.value);
    }
  }

  protected onEcosystem(event: Event): void {
    const target = event.target;
    if (target instanceof HTMLSelectElement) {
      this.ecosystemFilter.set(target.value);
    }
  }

  protected onStatus(event: Event): void {
    const target = event.target;
    if (target instanceof HTMLSelectElement) {
      const value = target.value;
      if (value === 'all' || value === 'vulnerable' || value === 'clean' || value === 'unchecked') {
        this.statusFilter.set(value);
      }
    }
  }

  protected severityOf(row: DependencyRow): Severity | null {
    return row.highestSeverity;
  }

  /** Plain-language reason a package was not checked. */
  protected skipLabel(reason: SkipReason | null): string {
    switch (reason) {
      case 'version-not-exact':
        return 'Version is a range';
      case 'no-version':
        return 'No version recorded';
      case 'unsupported-ecosystem':
        return 'Ecosystem not supported';
      case 'no-purl':
        return 'Incomplete metadata';
      default:
        return 'Not checked';
    }
  }
}
