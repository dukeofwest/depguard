import { describe, expect, it } from 'vitest';

import { parseSbom, queryablePackages } from './sbom/spdx-parser';
import { parseNpmLockfile } from './dependencies/npm-lockfile';
import { parseXml } from './dependencies/xml';
import {
  declaredResolution,
  parseCentralVersions,
  parseNuGetLockfile,
  parsePackagesConfig,
  parseProjectFile,
} from './dependencies/nuget';
import { classifyVersion, normalizeVersionForQuery, parsePurl } from './dependencies/purl';
import { processVulnerabilities } from './security/vulnerability-processor';
import { checkJsonShape } from './validation/external-input';
import type { OsvEcosystem } from '../core/models/dependency.model';

/**
 * Fuzz tests for the parsers (MANDATORY_SECURITY_REQUIREMENT §C, §D, §H).
 *
 * The parsers consume documents written by third parties. The contract every one of them
 * holds is **totality**: for any input at all, a result is returned describing what could
 * be read. Never an exception, never a hang.
 *
 * This is not a replacement for the targeted tests in each parser's own spec, which
 * assert what the result should *be*. It is the complement: a wide, randomised sweep whose
 * only claim is that nothing throws and nothing takes unbounded time. It is deterministic
 * despite being randomised, because the generator is seeded — a failure here can be
 * reproduced exactly, which a `Math.random` fuzzer could not promise.
 */

/** A small xorshift PRNG. Seeded, so a failure is reproducible and CI is not flaky. */
function makeRandom(seed: number): () => number {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state / 0x100000000;
  };
}

/** Values chosen because each one has broken a parser somewhere, in some codebase. */
const NASTY_SCALARS: readonly unknown[] = [
  null,
  undefined,
  0,
  -1,
  1.5,
  NaN,
  Infinity,
  -Infinity,
  Number.MAX_SAFE_INTEGER,
  Number.MIN_SAFE_INTEGER,
  true,
  false,
  '',
  ' ',
  '0',
  'null',
  'undefined',
  '[]',
  '{}',
  '__proto__',
  'constructor',
  'prototype',
  'toString',
  'valueOf',
  '\u0000',
  '�',
  '\uD800',
  '‮',
  'ï¿½',
  '../../etc/passwd',
  '<script>alert(1)</script>',
  '{{constructor.constructor("alert(1)")()}}',
  "'; DROP TABLE packages; --",
  'pkg:npm/',
  'pkg:',
  'pkg:npm/@scope/name@',
  '@'.repeat(100),
  'x'.repeat(10_000),
  '^'.repeat(1000),
  '.'.repeat(1000),
  '\n\r\t',
  [],
  {},
  [[[[[]]]]],
  { a: { b: { c: {} } } },
];

function pick<T>(random: () => number, items: readonly T[]): T {
  const value = items[Math.floor(random() * items.length)];
  return value as T;
}

/** Builds a value shaped loosely like an SPDX package, with fields randomly corrupted. */
function fuzzPackage(random: () => number): unknown {
  const shape = random();
  if (shape < 0.1) {
    return pick(random, NASTY_SCALARS);
  }

  const pkg: Record<string, unknown> = {};
  const fields = ['name', 'SPDXID', 'versionInfo', 'licenseConcluded', 'externalRefs'];
  for (const field of fields) {
    if (random() < 0.75) {
      pkg[field] = pick(random, NASTY_SCALARS);
    }
  }
  // Sometimes a plausible purl, so the happy path is exercised alongside the broken one.
  if (random() < 0.4) {
    pkg['externalRefs'] = [
      {
        referenceType: random() < 0.8 ? 'purl' : pick(random, NASTY_SCALARS),
        referenceLocator: random() < 0.5 ? 'pkg:npm/left-pad@1.0.0' : pick(random, NASTY_SCALARS),
      },
    ];
  }
  if (random() < 0.3) {
    pkg['name'] = 'left-pad';
    pkg['versionInfo'] = '1.0.0';
  }
  return pkg;
}

function fuzzRelationship(random: () => number): unknown {
  if (random() < 0.2) {
    return pick(random, NASTY_SCALARS);
  }
  return {
    spdxElementId: random() < 0.7 ? 'SPDXRef-DOCUMENT' : pick(random, NASTY_SCALARS),
    relatedSpdxElement: random() < 0.7 ? 'SPDXRef-1' : pick(random, NASTY_SCALARS),
    relationshipType: pick(random, ['DESCRIBES', 'DEPENDS_ON', 'CONTAINS', ...NASTY_SCALARS]),
  };
}

function fuzzSbom(random: () => number): unknown {
  const shape = random();
  if (shape < 0.08) {
    return pick(random, NASTY_SCALARS);
  }

  const document: Record<string, unknown> = {};
  if (random() < 0.85) {
    document['packages'] = Array.from({ length: Math.floor(random() * 12) }, () =>
      fuzzPackage(random),
    );
  } else {
    document['packages'] = pick(random, NASTY_SCALARS);
  }
  if (random() < 0.6) {
    document['relationships'] = Array.from({ length: Math.floor(random() * 8) }, () =>
      fuzzRelationship(random),
    );
  }
  if (random() < 0.5) {
    document['spdxVersion'] = pick(random, NASTY_SCALARS);
  }
  if (random() < 0.5) {
    document['name'] = pick(random, NASTY_SCALARS);
  }

  // GitHub wraps the document; sometimes it is unwrapped, sometimes wrapped in rubbish.
  const wrap = random();
  if (wrap < 0.5) return { sbom: document };
  if (wrap < 0.6) return { sbom: pick(random, NASTY_SCALARS) };
  return document;
}

function fuzzAdvisory(random: () => number): unknown {
  if (random() < 0.1) {
    return pick(random, NASTY_SCALARS);
  }
  const record: Record<string, unknown> = {};
  for (const field of ['id', 'summary', 'details', 'modified', 'published', 'withdrawn']) {
    if (random() < 0.7) {
      record[field] = pick(random, NASTY_SCALARS);
    }
  }
  if (random() < 0.6) record['id'] = 'GHSA-xxxx-yyyy-zzzz';
  if (random() < 0.5) {
    record['aliases'] = random() < 0.7 ? ['CVE-2021-44420'] : pick(random, NASTY_SCALARS);
  }
  if (random() < 0.5) {
    record['severity'] =
      random() < 0.6
        ? [{ type: 'CVSS_V3', score: pick(random, NASTY_SCALARS) }]
        : pick(random, NASTY_SCALARS);
  }
  if (random() < 0.5) {
    record['database_specific'] = {
      severity: pick(random, ['HIGH', 'CRITICAL', ...NASTY_SCALARS]),
    };
  }
  if (random() < 0.5) {
    record['references'] = [
      { type: pick(random, NASTY_SCALARS), url: pick(random, NASTY_SCALARS) },
      { type: 'WEB', url: 'https://example.com/a' },
    ];
  }
  if (random() < 0.5) {
    record['affected'] = [
      {
        package: { name: pick(random, NASTY_SCALARS), ecosystem: pick(random, NASTY_SCALARS) },
        ranges:
          random() < 0.7
            ? [{ type: 'SEMVER', events: [{ fixed: '1.0.0' }] }]
            : pick(random, NASTY_SCALARS),
      },
    ];
  }
  return record;
}

/**
 * A structurally-plausible-but-corrupted `package-lock.json`.
 *
 * Mixes the three lockfile versions, the flat map and the nested tree, and sprays nasty
 * scalars through the fields a parser reads.
 */
function fuzzNpmLockfile(random: () => number): unknown {
  if (random() < 0.1) {
    return pick(random, NASTY_SCALARS);
  }

  const lock: Record<string, unknown> = {};

  lock['lockfileVersion'] = pick(random, [1, 2, 3, 0, 4, 99, -1, ...NASTY_SCALARS]);

  if (random() < 0.8) {
    const packages: Record<string, unknown> = {};
    if (random() < 0.7) {
      packages[''] = {
        dependencies: random() < 0.7 ? { a: '^1.0.0' } : pick(random, NASTY_SCALARS),
        devDependencies: random() < 0.5 ? { b: '~2' } : pick(random, NASTY_SCALARS),
      };
    }
    const count = Math.floor(random() * 6);
    for (let index = 0; index < count; index += 1) {
      const key = pick(random, [
        `node_modules/pkg-${index}`,
        `node_modules/@scope/pkg-${index}`,
        `packages/app/node_modules/pkg-${index}`,
        `node_modules/a/node_modules/pkg-${index}`,
        'node_modules/',
        'node_modules/@scope',
        '',
        '__proto__',
        'constructor',
      ]);
      packages[key] =
        random() < 0.8
          ? {
              version: pick(random, ['1.0.0', '^1.0.0', 'latest', 'npm:x@1.0.0', ...NASTY_SCALARS]),
              dev: pick(random, [true, false, ...NASTY_SCALARS]),
              link: random() < 0.2 ? true : undefined,
            }
          : pick(random, NASTY_SCALARS);
    }
    lock['packages'] = random() < 0.9 ? packages : pick(random, NASTY_SCALARS);
  }

  if (random() < 0.5) {
    lock['dependencies'] =
      random() < 0.8
        ? {
            express: {
              version: pick(random, ['4.18.2', ...NASTY_SCALARS]),
              dependencies:
                random() < 0.5 ? { ms: { version: '2.1.3' } } : pick(random, NASTY_SCALARS),
            },
          }
        : pick(random, NASTY_SCALARS);
  }

  return lock;
}

/** XML fragments, from well-formed MSBuild through to hostile and malformed. */
function fuzzXml(random: () => number): string {
  const pieces: readonly string[] = [
    '<Project Sdk="Microsoft.NET.Sdk">',
    '<ItemGroup>',
    '<PackageReference Include="A" Version="1.0.0" />',
    '<PackageReference Include="B"><Version>2.0.0</Version></PackageReference>',
    '<PackageReference Include="C" Version="$(Undefined)" />',
    '<PackageReference Include="D" Version="[1.0.0]" />',
    '<PackageReference Version="1.0.0" />',
    '<PackageVersion Include="E" Version="3.0.0" />',
    '<package id="F" version="1.2.3" />',
    '<PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>',
    '</ItemGroup>',
    '</Project>',
    '<!-- comment -->',
    '<![CDATA[ raw ]]>',
    '<?xml version="1.0"?>',
    '<!DOCTYPE p>',
    '<!ENTITY e "x">',
    '&custom;',
    '&lt;&amp;',
    '&#65;',
    '&#xD800;',
    '<a attr=unquoted />',
    '<a attr />',
    '<unclosed>',
    '</mismatched>',
    '<>',
    '<a/>'.repeat(5),
    `<deep>${'<n>'.repeat(10)}`,
    'plain text',
    '',
    `<a b="${'x'.repeat(100)}" />`,
  ];

  const count = 1 + Math.floor(random() * 8);
  let xml = '';
  for (let index = 0; index < count; index += 1) {
    xml += pick(random, pieces);
  }
  return xml;
}

/** A corrupted `packages.lock.json`. */
function fuzzNuGetLock(random: () => number): unknown {
  if (random() < 0.15) {
    return pick(random, NASTY_SCALARS);
  }

  const dependencies: Record<string, unknown> = {};
  const frameworks = ['.NETCoreApp,Version=v8.0', 'net48', '', '__proto__'];
  const count = 1 + Math.floor(random() * 3);

  for (let index = 0; index < count; index += 1) {
    const framework = pick(random, frameworks);
    if (random() < 0.85) {
      dependencies[framework] = {
        [`Pkg.${index}`]:
          random() < 0.85
            ? {
                type: pick(random, ['Direct', 'Transitive', 'Project', ...NASTY_SCALARS]),
                requested: pick(random, ['[1.0.0, )', ...NASTY_SCALARS]),
                resolved: pick(random, ['1.0.0', '1.0', '1.0.0.0', ...NASTY_SCALARS]),
              }
            : pick(random, NASTY_SCALARS),
      };
    } else {
      dependencies[framework] = pick(random, NASTY_SCALARS);
    }
  }

  return {
    version: pick(random, [1, 2, ...NASTY_SCALARS]),
    dependencies: random() < 0.9 ? dependencies : pick(random, NASTY_SCALARS),
  };
}

const ITERATIONS = 400;

describe('parser fuzzing', () => {
  it('parseSbom returns a result for every input, and never throws', () => {
    const random = makeRandom(0x5eed);
    for (let i = 0; i < ITERATIONS; i++) {
      const input = fuzzSbom(random);
      let result;
      try {
        result = parseSbom(input, 20_000);
      } catch (error) {
        throw new Error(
          `parseSbom threw on iteration ${i}: ${String(error)}\ninput: ${safeStringify(input)}`,
          // Keep the original stack: the message says which input broke it, the cause
          // says where.
          { cause: error },
        );
      }
      expect(['parsed', 'unavailable', 'invalid'], `iteration ${i}`).toContain(result.kind);

      if (result.kind === 'parsed') {
        // Invariants that must hold for any parse, however broken the input.
        const { coverage, packages } = result;
        expect(coverage.totalPackages).toBe(packages.length);
        expect(coverage.queryablePackages).toBeLessThanOrEqual(coverage.totalPackages);
        expect(coverage.queryableRatio).toBeGreaterThanOrEqual(0);
        expect(coverage.queryableRatio).toBeLessThanOrEqual(1);
        expect(coverage.duplicateEntries).toBeGreaterThanOrEqual(0);
        expect(Number.isFinite(coverage.queryableRatio)).toBe(true);

        for (const pkg of packages) {
          expect(typeof pkg.name).toBe('string');
          expect(pkg.name.length).toBeGreaterThan(0);
          expect(['exact', 'range', 'missing']).toContain(pkg.versionKind);
          expect(['direct', 'transitive', 'unknown']).toContain(pkg.relationship);
        }

        // Nothing without an exact version may ever be queryable (ADR-0002).
        for (const pkg of queryablePackages(packages)) {
          expect(pkg.versionKind, `iteration ${i}`).toBe('exact');
          expect(pkg.ecosystem).not.toBeNull();
          expect(pkg.declaredVersion).not.toBeNull();
        }
      }
    }
  });

  it('processVulnerabilities returns findings for every input, and never throws', () => {
    const random = makeRandom(0xc0ffee);
    for (let i = 0; i < ITERATIONS; i++) {
      const records = Array.from({ length: Math.floor(random() * 5) }, () => fuzzAdvisory(random));
      let findings;
      try {
        findings = processVulnerabilities(records, []);
      } catch (error) {
        throw new Error(
          `processVulnerabilities threw on iteration ${i}: ${String(error)}\ninput: ${safeStringify(records)}`,
          { cause: error },
        );
      }
      expect(Array.isArray(findings)).toBe(true);

      for (const finding of findings) {
        expect(['Critical', 'High', 'Medium', 'Low', 'Unknown']).toContain(finding.severity);
        expect(typeof finding.key).toBe('string');
        expect(finding.key.length).toBeGreaterThan(0);
        expect(Array.isArray(finding.advisoryIds)).toBe(true);
        // Every rendered reference must be an https URL, whatever the advisory claimed.
        for (const reference of finding.references) {
          expect(reference.url.startsWith('https://'), reference.url).toBe(true);
        }
      }
    }
  });

  it('parsePurl and version classification never throw', () => {
    const random = makeRandom(0xbeef);
    for (let i = 0; i < ITERATIONS * 4; i++) {
      const value = pick(random, NASTY_SCALARS);
      const text = typeof value === 'string' ? value : String(value);

      expect(() => parsePurl(text), text.slice(0, 40)).not.toThrow();
      expect(() => classifyVersion(text), text.slice(0, 40)).not.toThrow();
      expect(['exact', 'range', 'missing']).toContain(classifyVersion(text));

      const ecosystems: readonly OsvEcosystem[] = ['npm', 'Go', 'PyPI', 'Maven'];
      for (const ecosystem of ecosystems) {
        expect(() => normalizeVersionForQuery(ecosystem, text)).not.toThrow();
      }
    }
  });

  it('classifies pathological version strings in linear time', () => {
    // Guards against catastrophic backtracking (§D). A quadratic or exponential pattern
    // would not return at all on these.
    const pathological = [
      '1' + '.1'.repeat(5000),
      '1' + '.1'.repeat(5000) + '!',
      '1.0.0-' + 'a'.repeat(20_000),
      '^'.repeat(20_000),
      '~'.repeat(20_000) + '1.0.0',
      '='.repeat(20_000),
      'v' + '0'.repeat(20_000),
    ];

    for (const version of pathological) {
      const started = performance.now();
      classifyVersion(version);
      const elapsed = performance.now() - started;
      expect(elapsed, `${version.slice(0, 20)}… took ${elapsed.toFixed(1)}ms`).toBeLessThan(100);
    }
  });

  it('shape-checks every fuzzed document without throwing', () => {
    const random = makeRandom(0xd00d);
    for (let i = 0; i < ITERATIONS; i++) {
      const input = fuzzSbom(random);
      expect(() => checkJsonShape(input), `iteration ${i}`).not.toThrow();
    }
  });

  // ---- npm lockfiles (Phase C) -------------------------------------------

  it('parseNpmLockfile returns a result for every input, and never throws', () => {
    const random = makeRandom(0x10cc);
    for (let i = 0; i < ITERATIONS; i++) {
      const input = fuzzNpmLockfile(random);
      let result;
      try {
        result = parseNpmLockfile(input, 'package-lock.json', 'package-lock.json');
      } catch (error) {
        throw new Error(
          `parseNpmLockfile threw on iteration ${i}: ${String(error)}\ninput: ${safeStringify(input)}`,
          { cause: error },
        );
      }
      expect(['parsed', 'invalid', 'unsupported'], `iteration ${i}`).toContain(result.kind);

      if (result.kind === 'parsed') {
        // The invariant that protects every downstream consumer: nothing non-resolved is
        // ever queryable, whatever the lockfile said.
        for (const pkg of queryablePackages(result.packages)) {
          expect(pkg.resolution, `iteration ${i}`).toBe('resolved');
          expect(pkg.versionKind, `iteration ${i}`).toBe('exact');
        }
        expect(result.coverage.totalPackages).toBe(result.packages.length);
        expect(result.coverage.queryableRatio).toBeGreaterThanOrEqual(0);
        expect(result.coverage.queryableRatio).toBeLessThanOrEqual(1);
      }
    }
  });

  // ---- NuGet (Phase D) ---------------------------------------------------

  it('parseXml returns a result for every input, and never throws', () => {
    const random = makeRandom(0x5bee);
    for (let i = 0; i < ITERATIONS; i++) {
      const input = fuzzXml(random);
      let result;
      try {
        result = parseXml(input);
      } catch (error) {
        throw new Error(
          `parseXml threw on iteration ${i}: ${String(error)}\ninput: ${input.slice(0, 300)}`,
          { cause: error },
        );
      }
      expect(['parsed', 'rejected'], `iteration ${i}`).toContain(result.kind);
    }
  });

  it('parseXml terminates quickly on pathological input', () => {
    // Shapes chosen to provoke quadratic scanning or runaway entity handling.
    const pathological = [
      '<a '.repeat(20_000),
      `<a attr="${'&'.repeat(20_000)}" />`,
      `<a>${'&lt;'.repeat(20_000)}</a>`,
      `<a>${'x'.repeat(200_000)}</a>`,
      '<'.repeat(50_000),
      `<a ${'b="c" '.repeat(5_000)}/>`,
      `${'<!-- '.repeat(10_000)}<a />`,
    ];

    for (const input of pathological) {
      const started = performance.now();
      parseXml(input);
      const elapsed = performance.now() - started;
      expect(elapsed, `${input.slice(0, 20)}… took ${elapsed.toFixed(1)}ms`).toBeLessThan(500);
    }
  });

  it('NuGet parsers return a result for every input, and never throw', () => {
    const random = makeRandom(0xd0d);
    for (let i = 0; i < ITERATIONS; i++) {
      const xml = fuzzXml(random);
      const json = fuzzNuGetLock(random);

      expect(
        () => parseProjectFile(xml, 'A.csproj', 'csproj', null),
        `iteration ${i}`,
      ).not.toThrow();
      expect(() => parsePackagesConfig(xml, 'packages.config'), `iteration ${i}`).not.toThrow();
      expect(
        () => parseCentralVersions(xml, 'Directory.Packages.props'),
        `iteration ${i}`,
      ).not.toThrow();
      expect(() => parseNuGetLockfile(json, 'packages.lock.json'), `iteration ${i}`).not.toThrow();

      // The rule the whole .NET implementation turns on, asserted against random input:
      // a declared version must never become queryable.
      const project = parseProjectFile(xml, 'A.csproj', 'csproj', null);
      if (project.kind === 'parsed') {
        for (const pkg of queryablePackages(project.packages)) {
          expect(pkg.resolution, `iteration ${i}: ${pkg.declaredVersion}`).toBe('resolved');
        }
      }
    }
  });

  it('never classifies a bare NuGet version as resolved, for any version string', () => {
    // Exhaustive over the forms a version attribute can take. A bare version is a
    // minimum; only the bracketed single value pins.
    const bare = ['1', '1.0', '1.0.0', '1.0.0.0', '1.0.0-beta', '13.0.1', 'v1.0.0'];
    for (const version of bare) {
      expect(declaredResolution(version), version).not.toBe('resolved');
    }
    for (const version of bare) {
      const exact = `[${version}]`;
      // Bracketed forms are resolved only when the inner value is a concrete version.
      const expected = classifyVersion(version) === 'exact' ? 'resolved' : 'declared-range';
      expect(declaredResolution(exact), exact).toBe(expected);
    }
  });

  it('is reproducible, so a fuzz failure can be investigated', () => {
    const first = makeRandom(42);
    const second = makeRandom(42);
    const a = Array.from({ length: 20 }, () => first());
    const b = Array.from({ length: 20 }, () => second());
    expect(a).toEqual(b);
  });
});

/** Stringifies fuzz input for a failure message, surviving circular or exotic values. */
function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value)?.slice(0, 600) ?? String(value);
  } catch {
    return '[unstringifiable]';
  }
}
