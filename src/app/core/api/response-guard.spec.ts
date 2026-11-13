import { describe, expect, it } from 'vitest';

import {
  DEFAULT_JSON_BOUNDS,
  SBOM_BOUNDS,
  boundedHeader,
  parseBoundedJson,
  type JsonBounds,
} from './response-guard';
import { RESPONSE_LIMITS } from '../config/api.config';

/**
 * HTTP-level response bounds (MANDATORY_SECURITY_REQUIREMENT §C5-C9, §D, §H).
 *
 * The guarantee under test is that no response body, whatever its size or shape, can
 * cause an exception to escape or an unbounded amount of work to happen. Every rejection
 * must be a value the caller can act on.
 */
describe('parseBoundedJson', () => {
  const small: JsonBounds = { maxLength: 1024, maxDepth: 8, maxNodes: 1000 };

  it('parses a well-formed body', () => {
    const result = parseBoundedJson('{"a":1}', small);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toEqual({ a: 1 });
    }
  });

  describe('malformed JSON', () => {
    const malformed = [
      '',
      '   ',
      '{',
      '}',
      '{"a":}',
      "{'a':1}",
      '[1,2,',
      'undefined',
      'NaN',
      '{"a":1}{"b":2}',
      '<html>429 Too Many Requests</html>',
      'null bytes \u0000 everywhere',
      '￿￾',
    ];

    for (const text of malformed) {
      it(`rejects ${JSON.stringify(text.slice(0, 32))} as a value, not an exception`, () => {
        // The point of the test: no throw. A parser that threw here would turn a bad
        // response from a third party into an unhandled error in the browser.
        const result = parseBoundedJson(text, small);
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.kind).toBe('malformed');
          expect(result.reason.length).toBeGreaterThan(0);
        }
      });
    }

    it('reports a reason fit to show a person, with no parser internals', () => {
      const result = parseBoundedJson('{oops', small);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).not.toContain('JSON.parse');
        expect(result.reason).not.toContain('position');
      }
    });
  });

  describe('size', () => {
    it('accepts a body at exactly the limit', () => {
      // A JSON string of total length exactly maxLength.
      const padding = 'a'.repeat(small.maxLength - 8);
      const text = `{"a":"${padding}"}`;
      expect(text.length).toBe(small.maxLength);
      expect(parseBoundedJson(text, small).ok).toBe(true);
    });

    it('rejects a body one character beyond the limit', () => {
      const text = `{"a":"${'a'.repeat(small.maxLength - 7)}"}`;
      expect(text.length).toBe(small.maxLength + 1);
      const result = parseBoundedJson(text, small);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.kind).toBe('too-large');
      }
    });

    it('rejects an oversized body without parsing it', () => {
      // 4 MB of valid JSON against a 1 kB budget. If this were parsed first, the object
      // graph would already exist by the time it was rejected.
      const huge = JSON.stringify({ packages: Array.from({ length: 80_000 }, (_, i) => i) });
      expect(huge.length).toBeGreaterThan(small.maxLength);
      const started = performance.now();
      const result = parseBoundedJson(huge, small);
      const elapsed = performance.now() - started;
      expect(result.ok).toBe(false);
      // Rejection is a length comparison, so it is effectively instant. A generous
      // ceiling, since this asserts the shape of the algorithm rather than a benchmark.
      expect(elapsed).toBeLessThan(50);
    });

    it('states the limit in the reason, so the message is actionable', () => {
      const result = parseBoundedJson('x'.repeat(2048), small);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toMatch(/MB/);
      }
    });
  });

  describe('nesting', () => {
    it('rejects a body nested beyond the limit', () => {
      const deep = '['.repeat(20) + '1' + ']'.repeat(20);
      const result = parseBoundedJson(deep, small);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.kind).toBe('too-deep');
      }
    });

    it('survives a nesting bomb, whether the parser or the guard rejects it', () => {
      // 100,000 levels. V8's own parser raises a RangeError well before this, which is
      // caught and reported as malformed; if a future engine parses it, the depth guard
      // rejects it instead. Either is correct; a thrown error is not.
      const bomb = '['.repeat(100_000) + '1' + ']'.repeat(100_000);
      const bounds: JsonBounds = { maxLength: 10_000_000, maxDepth: 32, maxNodes: 2_000_000 };
      const result = parseBoundedJson(bomb, bounds);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(['too-deep', 'malformed']).toContain(result.kind);
      }
    });

    it('survives an object-shaped nesting bomb', () => {
      let text = '1';
      for (let i = 0; i < 50_000; i++) {
        text = `{"a":${text}}`;
      }
      const bounds: JsonBounds = { maxLength: 10_000_000, maxDepth: 32, maxNodes: 2_000_000 };
      const result = parseBoundedJson(text, bounds);
      expect(result.ok).toBe(false);
    });
  });

  describe('configured bounds', () => {
    it('gives the SBOM a larger budget than other responses', () => {
      expect(SBOM_BOUNDS.maxLength).toBeGreaterThan(DEFAULT_JSON_BOUNDS.maxLength);
      expect(SBOM_BOUNDS.maxLength).toBe(RESPONSE_LIMITS.maxSbomBytes);
    });

    it('accepts the largest SBOM measured in Phase 0', () => {
      // npm/cli was 1.1 MB; the budget is 16 MB.
      expect(SBOM_BOUNDS.maxLength).toBeGreaterThan(1.1 * 1024 * 1024);
    });

    it('applies the same depth and node limits to every response', () => {
      expect(SBOM_BOUNDS.maxDepth).toBe(DEFAULT_JSON_BOUNDS.maxDepth);
      expect(SBOM_BOUNDS.maxNodes).toBe(DEFAULT_JSON_BOUNDS.maxNodes);
    });
  });
});

describe('boundedHeader', () => {
  it('passes a normal header through unchanged', () => {
    const link = '<https://api.github.com/x?page=2>; rel="last"';
    expect(boundedHeader(link)).toBe(link);
  });

  it('returns null for an absent header', () => {
    expect(boundedHeader(null)).toBeNull();
  });

  it('caps a header long enough to matter to a regular expression', () => {
    const absurd = 'a'.repeat(RESPONSE_LIMITS.maxHeaderLength * 4);
    const result = boundedHeader(absurd);
    expect(result).not.toBeNull();
    expect((result ?? '').length).toBe(RESPONSE_LIMITS.maxHeaderLength);
  });

  it('keeps header matching linear on a hostile value', () => {
    // The Link header is the only one parsed with a regular expression. This asserts the
    // combination - cap then match - completes promptly on input designed to backtrack.
    const hostile = 'a'.repeat(200_000) + '?page=';
    const started = performance.now();
    const bounded = boundedHeader(hostile) ?? '';
    const pattern = /[?&]page=(\d+)[^>]*>;\s*rel="last"/;
    pattern.exec(bounded);
    expect(performance.now() - started).toBeLessThan(100);
  });
});
