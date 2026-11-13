/**
 * Report schema version (§7.3).
 *
 * Lives in the engine, not in `core/models`, because the engine may import only *types*
 * from the application layers (§4.4) — a value import would give it a runtime dependency
 * on the application. The report builder owns the schema, so the version belongs with it.
 *
 * Bump on any breaking change to the exported JSON structure. Consumers of an exported
 * report read this field to know what shape to expect.
 */
export const REPORT_SCHEMA_VERSION = '1.0.0' as const;
