import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DashboardComponent } from './dashboard.component';
import { buildReport } from '../../engine/report/report-builder';
import { parseSbom } from '../../engine/sbom/spdx-parser';
import { ReportExportService } from '../../core/services/report-export.service';
import expressSbom from '../../engine/__fixtures__/sbom-express.json';
import requestRequestSbom from '../../engine/__fixtures__/sbom-request-request.json';
import type { HealthReport } from '../../core/models/health-report.model';
import type { RepositorySnapshot } from '../../core/models/repository.model';
import type { VulnerabilityResult } from '../../core/models/vulnerability.model';

/**
 * Dashboard rendering tests (§13.3).
 *
 * These run the real engine over real SBOM fixtures and render the result, so they verify
 * what a user is actually shown — in particular that an unassessable category is never
 * displayed as a clean or zero result.
 */

const NOW = new Date('2026-11-13T12:00:00.000Z');

function snapshot(overrides: Partial<RepositorySnapshot> = {}): RepositorySnapshot {
  return {
    metadata: {
      ref: { owner: 'expressjs', repo: 'express' },
      fullName: 'expressjs/express',
      description: 'Fast, unopinionated, minimalist web framework for node.',
      htmlUrl: 'https://github.com/expressjs/express',
      defaultBranch: 'master',
      isArchived: false,
      isDisabled: false,
      isFork: false,
      visibility: 'public',
      stars: 69675,
      forks: 25439,
      openIssues: 262,
      sizeKb: 10074,
      primaryLanguage: 'JavaScript',
      licenseSpdxId: 'MIT',
      licenseName: 'MIT License',
      topics: ['express'],
      createdAt: '2009-06-26T18:56:01Z',
      updatedAt: '2026-11-13T03:15:13Z',
      pushedAt: '2026-11-02T20:15:26Z',
      ...overrides.metadata,
    },
    tree: {
      entries: [
        { path: 'Readme.md', type: 'blob', sizeBytes: 10375 },
        { path: 'LICENSE', type: 'blob', sizeBytes: 1249 },
        { path: 'SECURITY.md', type: 'blob', sizeBytes: 500 },
        { path: '.github/dependabot.yml', type: 'blob', sizeBytes: 442 },
        { path: 'test/app.js', type: 'blob', sizeBytes: 100 },
      ],
      truncated: false,
    },
    workflows: [
      { name: 'CI', path: '.github/workflows/ci.yml', state: 'active', isRepositoryDefined: true },
    ],
    latestRelease: {
      tagName: 'v5.3.0',
      name: null,
      publishedAt: '2026-10-09T12:50:31Z',
      isPrerelease: false,
    },
    contributorCount: 372,
    languages: { JavaScript: 1000 },
    weeklyCommits: [1, 2, 3],
    fileContents: {
      '.github/dependabot.yml': 'version: 2\nupdates:\n  - package-ecosystem: npm\n',
    },
    retrievedAt: NOW.toISOString(),
    ...overrides,
  };
}

function reportFor(
  sbomFixture: unknown,
  vulnerabilities: VulnerabilityResult,
  overrides: Partial<RepositorySnapshot> = {},
): HealthReport {
  const parsed = parseSbom(sbomFixture, 20000);
  if (parsed.kind !== 'parsed') {
    throw new Error('fixture failed to parse');
  }
  return buildReport({
    snapshot: snapshot(overrides),
    packages: parsed.packages,
    dependencyCoverage: parsed.coverage,
    vulnerabilities,
    sbomUnavailableReason: null,
    now: NOW,
  });
}

describe('DashboardComponent', () => {
  let fixture: ComponentFixture<DashboardComponent>;

  function render(report: HealthReport): HTMLElement {
    fixture = TestBed.createComponent(DashboardComponent);
    fixture.componentRef.setInput('report', report);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  function text(element: HTMLElement): string {
    return element.textContent ?? '';
  }

  beforeEach(() => {
    TestBed.configureTestingModule({ imports: [DashboardComponent] });
  });

  afterEach(() => {
    TestBed.resetTestingModule();
  });

  describe('a scored report', () => {
    it('renders the repository, score, band and coverage together', () => {
      const report = reportFor(expressSbom, {
        kind: 'completed',
        findings: [],
        packagesChecked: 8,
      });
      const element = render(report);

      expect(text(element)).toContain('expressjs/express');

      // §6.3: coverage must appear alongside the score, never the score alone.
      expect(element.querySelector('.coverage__value')).not.toBeNull();
      expect(element.querySelector('.overall__disclaimer')).not.toBeNull();
      expect(text(element)).toContain('not a security certification');
    });

    it('formats counts for an English page regardless of machine locale', () => {
      // Caught by looking at a screenshot: toLocaleString() with no locale rendered
      // 69,679 as "69.679" on a German system, which reads as a decimal.
      const report = reportFor(expressSbom, {
        kind: 'completed',
        findings: [],
        packagesChecked: 8,
      });
      const element = render(report);
      expect(element.textContent ?? '').toContain('69,675');
      expect(element.textContent ?? '').not.toContain('69.675');
    });

    it('renders all five category cards', () => {
      const report = reportFor(expressSbom, {
        kind: 'completed',
        findings: [],
        packagesChecked: 8,
      });
      const element = render(report);

      expect(element.querySelectorAll('.category')).toHaveLength(5);
      expect(text(element)).toContain('Dependency Security');
      expect(text(element)).toContain('Maintenance and Activity');
    });
  });

  describe('an unassessable category', () => {
    // expressjs/express has only 8 of 53 packages checkable — below the coverage floor.
    const report = reportFor(expressSbom, { kind: 'completed', findings: [], packagesChecked: 8 });

    it('renders "Insufficient data" rather than a score or a zero', () => {
      const element = render(report);
      const unscored = [...element.querySelectorAll('.category--unscored')];

      expect(unscored.length).toBeGreaterThan(0);

      // Asserted per card, not over the page text: a page-wide search for "0/100" also
      // matches "100/100" from a category that legitimately scored full marks.
      for (const card of unscored) {
        expect(
          card.querySelector('.category__score'),
          'unscored card must have no score',
        ).toBeNull();
        expect(card.querySelector('.category__insufficient')?.textContent?.trim()).toBe(
          'Insufficient data',
        );
      }
    });

    it('surfaces it under "Needs attention first"', () => {
      const element = render(report);
      const titles = [...element.querySelectorAll('.findings__title')].map(
        (n) => n.textContent ?? '',
      );
      expect(titles.some((title) => title.includes('could not be assessed'))).toBe(true);
    });

    it('states in the explanation how much of the analysis completed', () => {
      const element = render(report);
      const explanation = element.querySelector('.overall__explanation')?.textContent ?? '';
      expect(explanation).toContain('could not be assessed');
      expect(explanation).toMatch(/\d+% of the intended analysis/);
    });
  });

  describe('a repository where nothing could be checked', () => {
    const report = reportFor(
      requestRequestSbom,
      {
        kind: 'not-applicable',
        reason: 'No dependency had an exact version that could be checked.',
      },
      {
        metadata: {
          ...snapshot().metadata,
          ref: { owner: 'request', repo: 'request' },
          fullName: 'request/request',
          pushedAt: '2024-08-14T00:09:41Z',
        },
      },
    );

    it('never presents the absence of findings as a clean result', () => {
      const element = render(report);
      // Switch to the vulnerabilities tab.
      const tabs = [...element.querySelectorAll('.tabs__tab')] as HTMLButtonElement[];
      const vulnTab = tabs.find((tab) => (tab.textContent ?? '').includes('Vulnerabilities'));
      vulnTab?.click();
      fixture.detectChanges();

      const panel = text(element);
      expect(panel).toContain('No dependency could be checked');
      expect(panel).toContain('not evidence that the dependencies are free of vulnerabilities');
      expect(panel).not.toContain('No known vulnerabilities found');
    });

    it('recommends committing a lockfile', () => {
      const element = render(report);
      expect(text(element)).toContain('Commit a lockfile');
    });
  });

  describe('tabs', () => {
    const report = reportFor(expressSbom, { kind: 'completed', findings: [], packagesChecked: 8 });

    it('renders content for every tab', () => {
      const element = render(report);
      const tabs = [...element.querySelectorAll('.tabs__tab')] as HTMLButtonElement[];
      expect(tabs).toHaveLength(6);

      for (const tab of tabs) {
        tab.click();
        fixture.detectChanges();
        const panel = element.querySelector('.panel');
        expect(
          (panel?.textContent ?? '').trim().length,
          `${tab.textContent} panel`,
        ).toBeGreaterThan(40);
      }
    });

    it('marks exactly one tab as selected', () => {
      const element = render(report);
      const selected = element.querySelectorAll('[role="tab"][aria-selected="true"]');
      expect(selected).toHaveLength(1);
    });

    it('always shows the standing limitations on the overview tab', () => {
      const element = render(report);
      expect(text(element)).toContain('Version freshness analysis is not available');
      expect(text(element)).toContain('does not read or execute source code');
    });
  });

  describe('export', () => {
    it('exports the report as JSON', () => {
      const report = reportFor(expressSbom, {
        kind: 'completed',
        findings: [],
        packagesChecked: 8,
      });
      const exporter = TestBed.inject(ReportExportService);
      const download = vi.spyOn(exporter, 'download').mockImplementation(() => undefined);

      const element = render(report);
      const buttons = [...element.querySelectorAll('button')] as HTMLButtonElement[];
      buttons.find((button) => (button.textContent ?? '').includes('Export JSON'))?.click();

      expect(download).toHaveBeenCalledWith(report);
      download.mockRestore();
    });
  });

  describe('untrusted content', () => {
    it('renders a hostile repository description as text, not markup', () => {
      const report = reportFor(
        expressSbom,
        { kind: 'completed', findings: [], packagesChecked: 8 },
        {
          metadata: {
            ...snapshot().metadata,
            description: '<img src=x onerror="alert(1)"><script>alert(2)</script>',
          },
        },
      );
      const element = render(report);

      // Repository metadata is attacker-controllable (§14). Angular interpolation must
      // escape it; no element may be created from it.
      expect(element.querySelector('img')).toBeNull();
      expect(element.querySelector('script')).toBeNull();
      expect(text(element)).toContain('<img src=x onerror=');
    });
  });
});
