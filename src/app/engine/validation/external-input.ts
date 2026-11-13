/**
 * Bounds on untrusted external input.
 *
 * Pure, dependency-free, and deliberately inside the engine: the SPDX parser and the
 * vulnerability processor need these guards, and the engine may not import values from
 * `core/` (enforced by `engine-purity.spec.ts`). `core/api/response-guard.ts` builds the
 * HTTP-level checks on top of these.
 *
 * Three hazards, each with its own limit:
 *
 * 1. **Depth.** `{"a":{"a":{"a": ...` 100,000 deep overflows the stack of any recursive
 *    consumer. `JSON.parse` throws rather than crashing, which is survivable, but the
 *    `JSON.stringify` used for report export would not be - so depth is bounded
 *    explicitly rather than by relying on a parser's internals.
 * 2. **String length.** A single 50 MB package name is valid JSON of trivial depth. It
 *    reaches the DOM, the table layout and every regular expression in the engine.
 * 3. **Node count.** Bounds the validator itself, so checking a hostile document cannot
 *    become the denial of service.
 */

/**
 * Maximum nesting depth accepted in an external document.
 *
 * The deepest legitimate structure measured is an OSV advisory's
 * `affected[].ranges[].events[]` at depth 7, and an SPDX document at depth 6. 32 accepts
 * every real document with a wide margin while rejecting a nesting bomb.
 */
export const MAX_JSON_DEPTH = 32;

/**
 * Maximum number of nodes visited while shape-checking a document.
 *
 * The check is linear, but a legitimate document can be large: `npm/cli` yields about
 * 25,000 nodes. A document exceeding this budget is rejected rather than walked.
 */
export const MAX_JSON_NODES = 2_000_000;

/**
 * Maximum length of any single string retained from an external document.
 *
 * Far above any real value - the longest advisory summary measured in Phase 0 was 186
 * characters.
 */
export const MAX_EXTERNAL_STRING_LENGTH = 4096;

export interface ShapeBounds {
  readonly maxDepth: number;
  readonly maxNodes: number;
}

export const DEFAULT_SHAPE_BOUNDS: ShapeBounds = {
  maxDepth: MAX_JSON_DEPTH,
  maxNodes: MAX_JSON_NODES,
};

export type ShapeRejection = 'too-deep' | 'too-many-nodes';

export type ShapeResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly kind: ShapeRejection; readonly reason: string };

/**
 * Verifies nesting depth and node count without recursing.
 *
 * Deliberately iterative. A recursive depth-checker would itself overflow the stack on
 * exactly the input it exists to reject, which is the classic way this defence is
 * written wrong.
 */
export function checkJsonShape(
  value: unknown,
  bounds: ShapeBounds = DEFAULT_SHAPE_BOUNDS,
): ShapeResult {
  const stack: { node: unknown; depth: number }[] = [{ node: value, depth: 1 }];
  let nodes = 0;

  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) {
      break;
    }

    nodes++;
    if (nodes > bounds.maxNodes) {
      return {
        ok: false,
        kind: 'too-many-nodes',
        reason: 'The response contained more elements than DepGuard will process.',
      };
    }

    const { node, depth } = current;
    if (node === null || typeof node !== 'object') {
      continue;
    }

    if (depth > bounds.maxDepth) {
      return {
        ok: false,
        kind: 'too-deep',
        reason: `The response was nested more than ${bounds.maxDepth} levels deep.`,
      };
    }

    if (Array.isArray(node)) {
      for (const child of node) {
        stack.push({ node: child, depth: depth + 1 });
      }
    } else {
      // Own enumerable properties only. A hostile body cannot reach the prototype chain
      // through `JSON.parse`, but being explicit keeps that true if the input source
      // ever changes.
      for (const child of Object.values(node as Record<string, unknown>)) {
        stack.push({ node: child, depth: depth + 1 });
      }
    }
  }

  return { ok: true };
}

/**
 * A non-empty string, truncated to a safe length, or null.
 *
 * The single place string length is bounded. Truncation rather than rejection is
 * deliberate: an advisory with an absurdly long summary is still a real advisory, and
 * dropping it would understate the risk - the one thing this product must never do.
 *
 * The marker is visible, so a reader can tell the value was cut rather than finding it
 * mysteriously ending mid-sentence.
 */
export function boundedString(
  value: unknown,
  maxLength: number = MAX_EXTERNAL_STRING_LENGTH,
): string | null {
  if (typeof value !== 'string' || value.length === 0) {
    return null;
  }
  if (value.length <= maxLength) {
    return value;
  }
  return `${value.slice(0, maxLength)}… (truncated)`;
}

/** True when `boundedString` would truncate. Used to report that it happened. */
export function wouldTruncate(
  value: unknown,
  maxLength: number = MAX_EXTERNAL_STRING_LENGTH,
): boolean {
  return typeof value === 'string' && value.length > maxLength;
}
