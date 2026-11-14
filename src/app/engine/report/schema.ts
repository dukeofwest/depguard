/**
 * Report schema version (§7.3).
 *
 * Lives in the engine, not in `core/models`, because the engine may import only *types*
 * from the application layers (§4.4) — a value import would give it a runtime dependency
 * on the application. The report builder owns the schema, so the version belongs with it.
 *
 * Bump on any breaking change to the exported JSON structure. Consumers of an exported
 * report read this field to know what shape to expect.
 *
 * ## 1.1.0 — November 2026 audit remediation
 *
 * Additive, so a 1.0.0 consumer keeps working; every field below is new, and no existing
 * field changed shape or meaning.
 *
 * - `overall.assessedWeight` — the share of the intended analysis that could be scored,
 *   previously computed only inside the explanation sentence where it sat beside
 *   `overall.coverage` with nothing naming either (P1-3).
 * - `vulnerabilities.advisoriesUnretrieved` — advisory ids OSV confirmed whose details
 *   could not be retrieved. Present on `partial` results (P0-1).
 * - `vulnerabilities.advisoriesOmitted` — advisories confirmed but not requested, because
 *   the request cap was reached. Previously reachable only as prose (P2-4).
 * - `sourceStates` — why each optional data source is absent, where it is (P1-2, P1-6).
 *
 * Values that changed without changing shape, and which a consumer comparing reports
 * across versions should expect: `maintenance` coverage (no longer counts signals that
 * cannot affect its score), `dependency-health` coverage (no longer a hardcoded 1), and
 * `dependency-security` scores at partial coverage (the ceiling now applies whether or
 * not findings exist).
 */
export const REPORT_SCHEMA_VERSION = '1.1.0' as const;
