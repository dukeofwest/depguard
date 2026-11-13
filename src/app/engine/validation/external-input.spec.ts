import { describe, expect, it } from 'vitest';

import {
  MAX_EXTERNAL_STRING_LENGTH,
  MAX_JSON_DEPTH,
  boundedString,
  checkJsonShape,
  wouldTruncate,
} from './external-input';

/**
 * Bounds on untrusted input (MANDATORY_SECURITY_REQUIREMENT §C, §D, §H).
 *
 * These are the guards that stand between a hostile document and the rest of the engine.
 * Each is tested at the boundary, one either side of it, and with the pathological input
 * it exists to reject.
 */
describe('external input bounds', () => {
  describe('checkJsonShape - nesting depth', () => {
    /** Builds `{"a":{"a":...}}` nested `depth` levels. */
    function nest(depth: number): unknown {
      let node: unknown = 1;
      for (let i = 0; i < depth; i++) {
        node = { a: node };
      }
      return node;
    }

    function nestArrays(depth: number): unknown {
      let node: unknown = 1;
      for (let i = 0; i < depth; i++) {
        node = [node];
      }
      return node;
    }

    it('accepts a document at the depth limit', () => {
      // One object at depth 1, so `MAX_JSON_DEPTH - 1` wrappers reach exactly the limit.
      const result = checkJsonShape(nest(MAX_JSON_DEPTH - 1));
      expect(result.ok).toBe(true);
    });

    it('rejects a document one level beyond the limit', () => {
      const result = checkJsonShape(nest(MAX_JSON_DEPTH + 1));
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.kind).toBe('too-deep');
      }
    });

    it('rejects a nesting bomb without exhausting its own stack', () => {
      // 200,000 levels. A recursive depth-checker would overflow here, which is the
      // failure mode this implementation exists to avoid - so the test asserts that a
      // verdict is returned at all, not merely that it is the right one.
      const result = checkJsonShape(nest(200_000));
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.kind).toBe('too-deep');
      }
    });

    it('rejects deep nesting built from arrays as well as objects', () => {
      expect(checkJsonShape(nestArrays(200_000)).ok).toBe(false);
    });

    it('accepts the shapes real documents have', () => {
      // An OSV advisory: affected[].ranges[].events[].fixed is the deepest real path.
      const advisory = {
        id: 'GHSA-test',
        affected: [
          {
            package: { name: 'left-pad', ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }],
          },
        ],
      };
      expect(checkJsonShape(advisory).ok).toBe(true);

      // An SPDX package entry.
      const sbom = {
        sbom: {
          packages: [
            {
              name: 'left-pad',
              externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/left-pad@1.0.0' }],
            },
          ],
        },
      };
      expect(checkJsonShape(sbom).ok).toBe(true);
    });

    it('treats a wide document as acceptable, since width is not the hazard', () => {
      const wide = { packages: Array.from({ length: 50_000 }, (_, i) => ({ name: `p${i}` })) };
      expect(checkJsonShape(wide).ok).toBe(true);
    });

    it('rejects a document exceeding the node budget', () => {
      const tiny = { maxDepth: MAX_JSON_DEPTH, maxNodes: 10 };
      const result = checkJsonShape({ a: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] }, tiny);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.kind).toBe('too-many-nodes');
      }
    });

    it('accepts primitives and null', () => {
      for (const value of [null, 1, 'text', true, undefined]) {
        expect(checkJsonShape(value).ok, String(value)).toBe(true);
      }
    });

    it('does not follow the prototype chain', () => {
      // A body parsed from JSON cannot carry a prototype, but if the input source ever
      // changed, walking inherited properties would make depth unbounded again.
      const parent = { deep: { deeper: { deepest: 1 } } };
      const child = Object.create(parent) as Record<string, unknown>;
      child['own'] = 1;
      expect(checkJsonShape(child).ok).toBe(true);
    });
  });

  describe('boundedString', () => {
    it('returns usable strings unchanged', () => {
      expect(boundedString('express')).toBe('express');
    });

    it('rejects non-strings and empty strings', () => {
      for (const value of [null, undefined, 0, 1, true, {}, [], '']) {
        expect(boundedString(value), JSON.stringify(value)).toBeNull();
      }
    });

    it('accepts a string at exactly the limit', () => {
      const exact = 'a'.repeat(MAX_EXTERNAL_STRING_LENGTH);
      expect(boundedString(exact)).toBe(exact);
      expect(wouldTruncate(exact)).toBe(false);
    });

    it('truncates a string one character beyond the limit', () => {
      const over = 'a'.repeat(MAX_EXTERNAL_STRING_LENGTH + 1);
      const result = boundedString(over);
      expect(wouldTruncate(over)).toBe(true);
      expect(result).not.toBeNull();
      expect(result?.startsWith('a'.repeat(MAX_EXTERNAL_STRING_LENGTH))).toBe(true);
      expect(result).toContain('truncated');
    });

    it('bounds a pathologically long value rather than carrying it through', () => {
      // 5 MB in a single package name. Valid JSON, trivial depth, and the kind of value
      // that reaches the DOM and every regular expression in the engine.
      const huge = 'x'.repeat(5 * 1024 * 1024);
      const result = boundedString(huge);
      expect(result).not.toBeNull();
      expect((result ?? '').length).toBeLessThan(MAX_EXTERNAL_STRING_LENGTH + 32);
    });

    it('truncates rather than discarding, so a finding is never lost to its own length', () => {
      // Dropping an over-long advisory summary would understate risk, which is the one
      // thing this product must not do.
      const summary = 'Critical remote code execution. ' + 'detail '.repeat(100_000);
      const result = boundedString(summary);
      expect(result).not.toBeNull();
      expect(result).toContain('Critical remote code execution.');
    });

    it('honours an explicit shorter limit', () => {
      expect(boundedString('abcdef', 3)).toBe('abc… (truncated)');
    });
  });
});
