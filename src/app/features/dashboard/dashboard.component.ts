import { ChangeDetectionStrategy, Component, computed, inject, input, signal } from '@angular/core';

import { AnalysisOverviewComponent } from './analysis-overview.component';
import { CheckListComponent } from './check-list.component';
import { DependencyTableComponent } from './dependency-table.component';
import { MaintenancePanelComponent } from './maintenance-panel.component';
import { RecommendationListComponent } from './recommendation-list.component';
import { RepositoryHeaderComponent } from './repository-header.component';
import { VulnerabilityListComponent } from './vulnerability-list.component';
import { CoverageBarComponent } from '../../shared/components/coverage-bar.component';
import { ScoreRingComponent } from '../../shared/components/score-ring.component';
import { CATEGORY_LABELS, type CategoryId } from '../../core/models/analysis.model';
import type { CategoryResult, HealthReport } from '../../core/models/health-report.model';
import { ReportExportService } from '../../core/services/report-export.service';
import { ScanStore } from '../../core/state/scan.store';

type TabId =
  'overview' | 'dependencies' | 'vulnerabilities' | 'security' | 'maintenance' | 'engineering';

/**
 * The analysis dashboard (§11.4).
 *
 * Every value comes from the report; nothing is recomputed here. Coverage is displayed
 * beside the score at equal prominence, because §6.3 requires that a score of 92 at 45%
 * coverage cannot look equivalent to a score of 92 at 100%.
 */
@Component({
  selector: 'dg-dashboard',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    AnalysisOverviewComponent,
    MaintenancePanelComponent,
    RepositoryHeaderComponent,
    ScoreRingComponent,
    CoverageBarComponent,
    DependencyTableComponent,
    VulnerabilityListComponent,
    CheckListComponent,
    RecommendationListComponent,
  ],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.css',
})
export class DashboardComponent {
  private readonly store = inject(ScanStore);
  private readonly exporter = inject(ReportExportService);

  readonly report = input.required<HealthReport>();

  protected readonly activeTab = signal<TabId>('overview');

  protected readonly tabs: readonly { id: TabId; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'dependencies', label: 'Dependencies' },
    { id: 'vulnerabilities', label: 'Vulnerabilities' },
    { id: 'security', label: 'Security' },
    { id: 'maintenance', label: 'Maintenance' },
    { id: 'engineering', label: 'Engineering' },
  ] as const;

  /** Narrowed overall result, so the template stays type-checked (see app.component.ts). */
  protected readonly scoredOverall = computed(() => {
    const overall = this.report().overall;
    return overall.kind === 'scored' ? overall : null;
  });

  protected readonly unavailableOverall = computed(() => {
    const overall = this.report().overall;
    return overall.kind === 'unavailable' ? overall : null;
  });

  protected readonly categoryCards = computed(() =>
    this.report().categories.map((category) => ({
      category,
      label: CATEGORY_LABELS[category.id],
    })),
  );

  /**
   * Findings that warrant attention first.
   *
   * Deliberately includes unscorable categories: "we could not check this" is itself a
   * critical finding for a security tool, and burying it would defeat the point.
   */
  protected readonly criticalFindings = computed(() => {
    const report = this.report();
    const findings: { title: string; detail: string }[] = [];

    for (const category of report.categories) {
      if (category.kind === 'insufficient-data') {
        findings.push({
          title: `${CATEGORY_LABELS[category.id]}: could not be assessed`,
          detail: category.reason,
        });
      }
    }

    const vulnerabilities = report.vulnerabilities;
    if (vulnerabilities.kind === 'completed' || vulnerabilities.kind === 'partial') {
      const serious = vulnerabilities.findings.filter(
        (finding) => finding.severity === 'Critical' || finding.severity === 'High',
      );
      if (serious.length > 0) {
        findings.push({
          title: `${serious.length} critical or high severity ${serious.length === 1 ? 'advisory' : 'advisories'}`,
          detail: serious
            .slice(0, 3)
            .map((finding) => finding.summary ?? finding.key)
            .join('; '),
        });
      }
    }

    if (report.maintenance.isArchived) {
      findings.push({
        title: 'Repository is archived',
        detail: 'The owner has archived this repository, so it will not receive security fixes.',
      });
    }

    return findings;
  });

  protected readonly tally = computed(() => {
    const result = this.report().vulnerabilities;
    if (result.kind !== 'completed' && result.kind !== 'partial') {
      return null;
    }
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 };
    for (const finding of result.findings) {
      counts[finding.severity]++;
    }
    return counts;
  });

  protected setTab(tab: TabId): void {
    this.activeTab.set(tab);
  }

  protected labelFor(id: CategoryId): string {
    return CATEGORY_LABELS[id];
  }

  protected isScored(
    category: CategoryResult,
  ): category is Extract<CategoryResult, { kind: 'scored' }> {
    return category.kind === 'scored';
  }

  protected exportJson(): void {
    this.exporter.download(this.report());
  }

  protected newScan(): void {
    this.store.reset();
  }

  /** Formatted for display; the raw ISO value stays in the export. */
  protected readonly generatedAtLabel = computed(() =>
    this.report().generatedAt.slice(0, 16).replace('T', ' '),
  );

  protected formatDate(iso: string | null): string {
    return iso === null ? 'Unknown' : iso.slice(0, 10);
  }
}
