import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { VulnerabilityListComponent } from './vulnerability-list.component';
import { DependencyTableComponent } from './dependency-table.component';
import { processVulnerabilities } from '../../engine/security/vulnerability-processor';
import { parseSbom } from '../../engine/sbom/spdx-parser';
import type { DependencyRow } from '../../core/models/dependency.model';
import type { VulnerabilityResult } from '../../core/models/vulnerability.model';

/**
 * Adversarial rendering tests (§14).
 *
 * Package names, advisory summaries and advisory descriptions all originate from third
 * parties and are treated as untrusted input. These tests push hostile values through the
 * real engine and into the real components, and assert that nothing becomes markup, a
 * script, or a dangerous link.
 */

const XSS_PAYLOADS: readonly string[] = [
  '<script>alert(1)</script>',
  '<img src=x onerror="alert(1)">',
  '"><svg onload=alert(1)>',
  "javascript:alert('x')",
  '<iframe src="javascript:alert(1)"></iframe>',
  '{{ constructor.constructor("alert(1)")() }}',
  '<style>body{display:none}</style>',
  '\u0000<script>alert(1)</script>',
] as const;

describe('untrusted content rendering', () => {
  afterEach(() => {
    TestBed.resetTestingModule();
  });

  describe('vulnerability findings', () => {
    let fixture: ComponentFixture<VulnerabilityListComponent>;

    beforeEach(() => {
      TestBed.configureTestingModule({ imports: [VulnerabilityListComponent] });
    });

    function renderWith(result: VulnerabilityResult): HTMLElement {
      fixture = TestBed.createComponent(VulnerabilityListComponent);
      fixture.componentRef.setInput('result', result);
      fixture.detectChanges();
      return fixture.nativeElement as HTMLElement;
    }

    it('escapes hostile advisory text rather than executing it', () => {
      for (const payload of XSS_PAYLOADS) {
        const findings = processVulnerabilities(
          [
            {
              id: 'GHSA-test',
              summary: payload,
              details: payload,
              database_specific: { severity: 'HIGH' },
            },
          ],
          [],
        );

        const element = renderWith({ kind: 'completed', findings, packagesChecked: 1 });

        expect(element.querySelector('script'), payload).toBeNull();
        expect(element.querySelector('img'), payload).toBeNull();
        expect(element.querySelector('svg[onload]'), payload).toBeNull();
        expect(element.querySelector('iframe'), payload).toBeNull();
        expect(element.querySelector('style'), payload).toBeNull();
        // No element may carry an inline event handler derived from the payload.
        for (const node of element.querySelectorAll('*')) {
          expect(node.getAttribute('onerror')).toBeNull();
          expect(node.getAttribute('onload')).toBeNull();
        }

        TestBed.resetTestingModule();
        TestBed.configureTestingModule({ imports: [VulnerabilityListComponent] });
      }
    });

    it('drops advisory references that are not http(s) links', () => {
      // The engine filters these; this asserts nothing dangerous survives to the DOM.
      const findings = processVulnerabilities(
        [
          {
            id: 'GHSA-test',
            summary: 'test',
            database_specific: { severity: 'HIGH' },
            references: [
              { type: 'WEB', url: 'javascript:alert(1)' },
              { type: 'WEB', url: 'data:text/html;base64,PHNjcmlwdD4=' },
              { type: 'WEB', url: 'vbscript:msgbox(1)' },
              { type: 'ADVISORY', url: 'https://example.com/safe' },
            ],
          },
        ],
        [],
      );

      const element = renderWith({ kind: 'completed', findings, packagesChecked: 1 });

      // Expand the details so references render.
      const toggle = element.querySelector('.finding__toggle') as HTMLButtonElement | null;
      toggle?.click();
      fixture.detectChanges();

      const hrefs = [...element.querySelectorAll('a')].map((anchor) => anchor.getAttribute('href'));
      for (const href of hrefs) {
        expect(href).toMatch(/^https?:\/\//);
      }
      expect(hrefs).toContain('https://example.com/safe');
    });

    it('opens external links without granting access to the opener', () => {
      const findings = processVulnerabilities(
        [
          {
            id: 'GHSA-test',
            summary: 'test',
            database_specific: { severity: 'HIGH' },
            references: [{ type: 'ADVISORY', url: 'https://example.com/advisory' }],
          },
        ],
        [],
      );

      const element = renderWith({ kind: 'completed', findings, packagesChecked: 1 });
      (element.querySelector('.finding__toggle') as HTMLButtonElement | null)?.click();
      fixture.detectChanges();

      for (const anchor of element.querySelectorAll('a[target="_blank"]')) {
        const rel = anchor.getAttribute('rel') ?? '';
        expect(rel).toContain('noopener');
        expect(rel).toContain('noreferrer');
      }
    });
  });

  describe('dependency inventory', () => {
    beforeEach(() => {
      TestBed.configureTestingModule({ imports: [DependencyTableComponent] });
    });

    it('escapes hostile package names from a real SBOM parse', () => {
      // Hostile names arrive via the SBOM, so they go through the real parser first.
      const sbom = {
        sbom: {
          packages: XSS_PAYLOADS.map((payload, index) => ({
            name: payload,
            SPDXID: `SPDXRef-${index}`,
            versionInfo: '1.0.0',
            externalRefs: [
              {
                referenceType: 'purl',
                referenceLocator: `pkg:npm/${encodeURIComponent(payload)}@1.0.0`,
              },
            ],
          })),
        },
      };

      const parsed = parseSbom(sbom, 20000);
      if (parsed.kind !== 'parsed') {
        throw new Error('expected the SBOM to parse');
      }

      const rows: DependencyRow[] = parsed.packages.map((pkg) => ({
        package: pkg,
        vulnerabilityCount: 0,
        highestSeverity: null,
        wasChecked: true,
      }));

      const fixture = TestBed.createComponent(DependencyTableComponent);
      fixture.componentRef.setInput('rows', rows);
      fixture.detectChanges();
      const element = fixture.nativeElement as HTMLElement;

      expect(element.querySelector('script')).toBeNull();
      expect(element.querySelector('img')).toBeNull();
      expect(element.querySelector('iframe')).toBeNull();
      expect(element.querySelector('style')).toBeNull();

      // The names must still be present as visible text — sanitising them away would
      // hide real dependencies.
      expect(element.textContent ?? '').toContain('<script>alert(1)</script>');
    });

    it('does not execute Angular template syntax embedded in data', () => {
      const rows: DependencyRow[] = [
        {
          package: {
            key: 'npm|{{1+1}}|1.0.0',
            name: '{{1+1}}',
            purlType: 'npm',
            ecosystem: 'npm',
            declaredVersion: '1.0.0',
            versionKind: 'exact',
            relationship: 'unknown',
            licenseConcluded: null,
            skipReason: null,
          },
          vulnerabilityCount: 0,
          highestSeverity: null,
          wasChecked: true,
        },
      ];

      const fixture = TestBed.createComponent(DependencyTableComponent);
      fixture.componentRef.setInput('rows', rows);
      fixture.detectChanges();
      const element = fixture.nativeElement as HTMLElement;

      // Interpolation is compile-time in Angular, so data is never evaluated. Asserted
      // because this is a classic failure mode in template systems that interpolate at
      // runtime.
      expect(element.textContent ?? '').toContain('{{1+1}}');
      expect(element.textContent ?? '').not.toContain('>2<');
    });
  });
});
