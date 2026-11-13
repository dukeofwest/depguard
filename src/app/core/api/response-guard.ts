import { RESPONSE_LIMITS } from '../config/api.config';
import {
  DEFAULT_SHAPE_BOUNDS,
  checkJsonShape,
  type ShapeBounds,
} from '../../engine/validation/external-input';

/**
 * HTTP-level bounded parsing of untrusted response bodies.
 *
 * The shape and string guards live in `engine/validation/external-input.ts`, because the
 * SPDX parser and vulnerability processor need them and the engine may not import values
 * from `core/`. This module adds what is specific to a network response: a size bound
 * applied *before* the body is turned into an object graph, and a cap on header values
 * that are matched with a regular expression.
 */

export type JsonRejection = 'too-large' | 'malformed' | 'too-deep' | 'too-many-nodes';

export type BoundedJsonResult =
  | { readonly ok: true; readonly value: unknown }
  | { readonly ok: false; readonly kind: JsonRejection; readonly reason: string };

export interface JsonBounds extends ShapeBounds {
  /**
   * Maximum size of the raw response text.
   *
   * Compared in UTF-16 code units. That is what determines the memory a JavaScript
   * string actually occupies, and it equals the byte count for the ASCII-dominant JSON
   * these two APIs return. The true byte count is checked separately against
   * `Content-Length` wherever the server declares one, so a multi-byte body cannot
   * exceed the intended budget unnoticed.
   */
  readonly maxLength: number;
}

/** Bounds for the SBOM, legitimately the largest document DepGuard handles. */
export const SBOM_BOUNDS: JsonBounds = {
  ...DEFAULT_SHAPE_BOUNDS,
  maxLength: RESPONSE_LIMITS.maxSbomBytes,
};

/** Bounds for every other JSON response. */
export const DEFAULT_JSON_BOUNDS: JsonBounds = {
  ...DEFAULT_SHAPE_BOUNDS,
  maxLength: RESPONSE_LIMITS.maxJsonBytes,
};

/**
 * Parses response text within explicit bounds.
 *
 * Never throws. A malformed body is a result, not an exception, because "GitHub returned
 * something unparseable" is a condition the report must describe rather than crash on.
 */
export function parseBoundedJson(text: string, bounds: JsonBounds): BoundedJsonResult {
  if (text.length > bounds.maxLength) {
    return {
      ok: false,
      kind: 'too-large',
      reason: `The response was larger than the ${formatLimit(bounds.maxLength)} DepGuard will process.`,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    // Includes the RangeError V8 raises on deeply nested input, which is why this catch
    // cannot be narrowed to a syntax error.
    return { ok: false, kind: 'malformed', reason: 'The response was not valid JSON.' };
  }

  const shape = checkJsonShape(parsed, bounds);
  if (!shape.ok) {
    return { ok: false, kind: shape.kind, reason: shape.reason };
  }

  return { ok: true, value: parsed };
}

/**
 * Caps a header value before it is matched with a regular expression.
 *
 * None of DepGuard's patterns backtrack catastrophically, but bounding the input makes
 * that a property of the data rather than a property of every pattern staying careful
 * forever.
 */
export function boundedHeader(value: string | null): string | null {
  if (value === null) {
    return null;
  }
  return value.length > RESPONSE_LIMITS.maxHeaderLength
    ? value.slice(0, RESPONSE_LIMITS.maxHeaderLength)
    : value;
}

function formatLimit(characters: number): string {
  const megabytes = characters / (1024 * 1024);
  return `${Number.isInteger(megabytes) ? megabytes : megabytes.toFixed(1)} MB`;
}
