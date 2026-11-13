import { describe, expect, it } from 'vitest';

import { parseSbom, queryablePackages } from './spdx-parser';
import expressSbom from '../__fixtures__/sbom-express.json';
import npmCliSbom from '../__fixtures__/sbom-npm-cli.json';
import requestsSbom from '../__fixtures__/sbom-requests.json';
import requestRequestSbom from '../__fixtures__/sbom-request-request.json';

/**
 * These fixtures are real SBOM responses captured from the GitHub API during Phase 0,
 * not hand-written approximations. They are what makes the coverage numbers below
 * meaningful rather than circular.
 */

const MAX = 20000;

function parsed(body: unknown) {
  const result = parseSbom(body, MAX);
  if (result.kind !== 'parsed') {
    throw new Error(`expected a parsed SBOM, got ${result.kind}`);
  }
  return result;
}

describe('parseSbom', () => {
  describe('real GitHub SBOM documents', () => {
    it('parses expressjs/express — a repository with no committed lockfile', () => {
      const result = parsed(expressSbom);

      expect(result.spdxVersion).toBe('SPDX-2.3');
      // 54 packages in the document, one of which is the repository itself.
      expect(result.coverage.totalPackages).toBe(53);

      // The headline Phase 0 finding: without a lockfile, most versions are ranges and
      // cannot be checked. Measured at 8 queryable.
      expect(result.coverage.queryablePackages).toBe(8);
      expect(result.coverage.queryableRatio).toBeCloseTo(8 / 53, 3);
      expect(result.coverage.rangeVersionsDominant).toBe(true);

      // GitHub Actions appear in real SBOMs but are not an OSV package ecosystem.
      expect(result.coverage.skippedByReason['unsupported-ecosystem']).toBe(9);
      expect(result.coverage.skippedByReason['version-not-exact']).toBe(36);
    });

    it('parses npm/cli — a repository that commits a lockfile', () => {
      const result = parsed(npmCliSbom);

      // The full, unmodified document. Phase 0 measured 1,026 of 1,208 packages as
      // queryable — 84.9%, against 14.8% for express. The lockfile is the whole
      // difference, and these exact numbers are the evidence behind ADR-0002.
      expect(result.coverage.totalPackages).toBe(1207);
      expect(result.coverage.queryablePackages).toBe(1026);
      expect(result.coverage.queryableRatio).toBeGreaterThan(0.84);
      expect(result.coverage.rangeVersionsDominant).toBe(false);

      // A lockfile yields a real dependency graph, so direct/transitive is derivable.
      const classified = result.packages.filter((p) => p.relationship !== 'unknown');
      expect(classified.length).toBeGreaterThan(0);
    });

    it('parses psf/requests — packages with no version at all', () => {
      const result = parsed(requestsSbom);

      // 12 of 30 packages carried no version whatsoever.
      expect(result.coverage.skippedByReason['no-version']).toBe(12);
      expect(result.packages.some((p) => p.ecosystem === 'PyPI')).toBe(true);
    });

    it('parses request/request — the case that must never read as "no vulnerabilities"', () => {
      const result = parsed(requestRequestSbom);

      // Zero packages can be checked. An abandoned, widely-depended-upon repository.
      expect(result.coverage.queryablePackages).toBe(0);
      expect(result.coverage.queryableRatio).toBe(0);
      expect(queryablePackages(result.packages)).toHaveLength(0);
      expect(result.coverage.totalPackages).toBeGreaterThan(0);
      expect(result.coverage.rangeVersionsDominant).toBe(true);
    });
  });

  describe('package normalisation', () => {
    it('decodes percent-encoded scoped names and versions', () => {
      const result = parsed({
        sbom: {
          packages: [
            {
              name: '@npmcli/git',
              SPDXID: 'SPDXRef-a',
              versionInfo: '^8.0.0',
              externalRefs: [
                { referenceType: 'purl', referenceLocator: 'pkg:npm/%40npmcli/git@%5E8.0.0' },
              ],
            },
          ],
        },
      });

      const pkg = result.packages[0];
      expect(pkg?.name).toBe('@npmcli/git');
      expect(pkg?.ecosystem).toBe('npm');
      // The caret survives decoding and is correctly refused.
      expect(pkg?.versionKind).toBe('range');
      expect(pkg?.skipReason).toBe('version-not-exact');
    });

    it('never marks a non-exact version as queryable', () => {
      // The core safety property of ADR-0002, asserted across every fixture at once.
      for (const fixture of [expressSbom, npmCliSbom, requestsSbom, requestRequestSbom]) {
        for (const pkg of queryablePackages(parsed(fixture).packages)) {
          expect(pkg.versionKind).toBe('exact');
          expect(pkg.ecosystem).not.toBeNull();
          expect(pkg.declaredVersion).toBeTruthy();
          expect(pkg.skipReason).toBeNull();
        }
      }
    });

    it('reads licences but treats NOASSERTION as absence', () => {
      const result = parsed({
        sbom: {
          packages: [
            { name: 'a', SPDXID: '1', licenseConcluded: 'MIT' },
            { name: 'b', SPDXID: '2', licenseConcluded: 'NOASSERTION' },
            { name: 'c', SPDXID: '3', licenseConcluded: 'NONE' },
          ],
        },
      });

      expect(result.packages[0]?.licenseConcluded).toBe('MIT');
      expect(result.packages[1]?.licenseConcluded).toBeNull();
      expect(result.packages[2]?.licenseConcluded).toBeNull();
    });

    it('reports relationship as unknown when the graph is flat', () => {
      // express's SBOM has every edge originating from the root, so "direct" would be
      // true of everything and therefore meaningless.
      const result = parsed(expressSbom);
      expect(result.packages.every((p) => p.relationship === 'unknown')).toBe(true);
    });
  });

  describe('malformed and hostile input', () => {
    it('reports an absent SBOM as unavailable, not as an error', () => {
      expect(parseSbom(null, MAX).kind).toBe('unavailable');
      expect(parseSbom(undefined, MAX).kind).toBe('unavailable');
    });

    const malformed: readonly [string, unknown][] = [
      ['a string', 'not an sbom'],
      ['a number', 42],
      ['an array', []],
      ['an empty object', {}],
      ['packages of the wrong type', { sbom: { packages: 'nope' } }],
    ];

    for (const [label, input] of malformed) {
      it(`does not throw on ${label}`, () => {
        const result = parseSbom(input, MAX);
        expect(['invalid', 'unavailable']).toContain(result.kind);
      });
    }

    it('skips unusable package entries without discarding the rest', () => {
      const result = parsed({
        sbom: {
          packages: [
            null,
            'string',
            { SPDXID: 'no-name' },
            {
              name: 'good',
              SPDXID: '1',
              versionInfo: '1.0.0',
              externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/good@1.0.0' }],
            },
            {
              name: 'bad-purl',
              SPDXID: '2',
              externalRefs: [{ referenceType: 'purl', referenceLocator: 'not-a-purl' }],
            },
            { name: 'bad-refs', SPDXID: '3', externalRefs: 'nope' },
          ],
        },
      });

      expect(result.packages).toHaveLength(3);
      expect(result.packages[0]?.skipReason).toBeNull();
      expect(result.packages[1]?.skipReason).toBe('no-purl');
      expect(result.packages[2]?.skipReason).toBe('no-purl');
    });

    it('enforces the package cap', () => {
      const packages = Array.from({ length: 500 }, (_, i) => ({
        name: `pkg-${i}`,
        SPDXID: `SPDXRef-${i}`,
        versionInfo: '1.0.0',
      }));
      const result = parseSbom({ sbom: { packages } }, 50);
      if (result.kind !== 'parsed') throw new Error(result.kind);
      expect(result.coverage.totalPackages).toBe(50);
    });

    it('does not let a hostile package name escape as structure', () => {
      const result = parsed({
        sbom: {
          packages: [
            {
              name: '<script>alert(1)</script>',
              SPDXID: '1',
              versionInfo: '1.0.0',
              externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/evil@1.0.0' }],
            },
          ],
        },
      });
      // The name is carried as data. Angular interpolation escapes it at render time;
      // the engine's job is simply not to transform or trust it.
      expect(result.packages[0]?.name).toBe('evil');
      expect(typeof result.packages[0]?.name).toBe('string');
    });
  });

  it('is deterministic', () => {
    const first = parseSbom(expressSbom, MAX);
    const second = parseSbom(expressSbom, MAX);
    expect(first).toEqual(second);
  });
});
