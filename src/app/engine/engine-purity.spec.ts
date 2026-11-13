import { describe, expect, it } from 'vitest';

/**
 * Enforces the engine purity rule from PROJECT_SPECIFICATION.md §4.4 and §10.3.
 *
 * This is a stated acceptance criterion for Phase 3 ("Engine has zero Angular imports",
 * "Engine has zero DOM dependencies"). ESLint already forbids these imports, but lint and
 * tests are run separately and a developer can disable a rule inline — so the rule is
 * also asserted here, where it fails the test suite and therefore CI.
 *
 * The check reads the engine's own source files via Vite's `import.meta.glob`, which
 * resolves at build time and needs no Node filesystem access (keeping this runnable in
 * the browser-like test environment).
 */

const engineSources = import.meta.glob('./**/*.ts', {
  eager: true,
  query: '?raw',
  import: 'default',
}) as Record<string, string>;

/** Strips comments so a rule named in prose is not mistaken for a violation. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/** Source files under test, excluding the spec files themselves. */
function productionSources(): [string, string][] {
  return Object.entries(engineSources)
    .filter(([path]) => !path.endsWith('.spec.ts'))
    .map(([path, source]) => [path, stripComments(source)]);
}

describe('analysis engine purity (spec §4.4)', () => {
  it('finds engine source files to check', () => {
    // Guards against the glob silently matching nothing, which would make every
    // assertion below vacuously true.
    expect(productionSources().length).toBeGreaterThan(0);
  });

  it('imports nothing from @angular/*', () => {
    const offenders = productionSources()
      .filter(([, source]) => /from\s+['"]@angular\//.test(source))
      .map(([path]) => path);

    expect(offenders, 'engine files importing Angular').toEqual([]);
  });

  it('contains no value imports from application layers', () => {
    // Type-only imports are erased at compile time and are permitted, so the engine can
    // share domain vocabulary without acquiring a runtime dependency. A value import
    // would couple the engine to Angular services and is rejected.
    const offenders = productionSources()
      .filter(([, source]) => {
        const appImports = source.match(
          /^\s*import\s+(?!type\s)[^;]*?from\s+['"][^'"]*(core|features)\/[^'"]*['"]/gm,
        );
        return appImports !== null;
      })
      .map(([path]) => path);

    expect(offenders, 'engine files with runtime imports from core/ or features/').toEqual([]);
  });

  it('touches no browser or DOM globals', () => {
    const forbidden = [
      /\bwindow\./,
      /\bdocument\./,
      /\blocalStorage\b/,
      /\bsessionStorage\b/,
      /\bnavigator\./,
      /\bfetch\s*\(/,
      /\bXMLHttpRequest\b/,
    ];

    const offenders: string[] = [];
    for (const [path, source] of productionSources()) {
      for (const pattern of forbidden) {
        if (pattern.test(source)) {
          offenders.push(`${path} matched ${pattern}`);
        }
      }
    }

    expect(offenders, 'engine files touching browser APIs').toEqual([]);
  });

  it('uses no non-deterministic time or randomness', () => {
    // Identical input must produce identical output (§6.5, Phase 3 acceptance criteria).
    // Reading the clock or RNG inside the engine would break that, so timestamps are
    // passed in as arguments instead.
    const offenders: string[] = [];
    for (const [path, source] of productionSources()) {
      if (/\bDate\.now\s*\(/.test(source) || /\bnew\s+Date\s*\(\s*\)/.test(source)) {
        offenders.push(`${path} reads the current time`);
      }
      if (/\bMath\.random\s*\(/.test(source)) {
        offenders.push(`${path} uses Math.random`);
      }
    }

    expect(offenders, 'engine files with non-deterministic behaviour').toEqual([]);
  });
});
