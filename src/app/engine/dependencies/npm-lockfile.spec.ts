import { describe, expect, it } from 'vitest';

import { packageNameFromPath, parseNpmLockfile } from './npm-lockfile';
import { queryablePackages } from '../sbom/spdx-parser';
import { mergeInventories } from './inventory';
import depguardLock from '../__fixtures__/package-lock-depguard.json';
import type { NormalizedPackage } from '../../core/models/dependency.model';

/** Parses and narrows to the success case, failing loudly otherwise. */
function parsed(body: unknown, path = 'package-lock.json') {
  const result = parseNpmLockfile(body, 'package-lock.json', path);
  if (result.kind !== 'parsed') {
    throw new Error(`expected a parsed result, got ${result.kind}: ${result.reason}`);
  }
  return result;
}

function byName(packages: readonly NormalizedPackage[], name: string): NormalizedPackage {
  const found = packages.find((pkg) => pkg.name === name);
  if (found === undefined) {
    throw new Error(`expected to find ${name}`);
  }
  return found;
}

describe('parseNpmLockfile', () => {
  // ---- The measured regression case (P1-1) -------------------------------

  describe("DepGuard's own lockfile", () => {
    // The repository the audit was performed on. GitHub returns 404 from the SBOM
    // endpoint for it even with an authenticated token, so before this parser existed
    // DepGuard reported "no dependency inventory was available" for a repository
    // carrying a complete, fully-resolved one.
    const result = parsed(depguardLock);

    it('finds every entry in the lockfile', () => {
      expect(result.lockfileVersion).toBe(3);
      expect(result.packages).toHaveLength(587);
    });

    it('resolves every version exactly', () => {
      // The measurement that makes this worth doing: 587 of 587 at exact versions, so
      // the whole inventory is checkable against OSV.
      expect(result.coverage.queryablePackages).toBe(587);
      expect(result.coverage.queryableRatio).toBe(1);
      expect(result.packages.every((pkg) => pkg.resolution === 'resolved')).toBe(true);
    });

    it('separates development from production dependencies', () => {
      const dev = result.packages.filter((pkg) => pkg.scope === 'development');
      const prod = result.packages.filter((pkg) => pkg.scope === 'production');
      expect(dev).toHaveLength(581);
      expect(prod).toHaveLength(6);
    });

    it('separates direct from transitive dependencies', () => {
      const direct = result.packages.filter((pkg) => pkg.relationship === 'direct');
      expect(direct).toHaveLength(17);
      expect(
        direct.length + result.packages.filter((p) => p.relationship === 'transitive').length,
      ).toBe(587);
    });

    it('records provenance on every package', () => {
      expect(result.coverage.inventorySource).toBe('package-lock.json');
      expect(result.coverage.transitiveCoverage).toBe('full');
      for (const pkg of result.packages) {
        expect(pkg.source).toBe('package-lock.json');
        expect(pkg.sourcePath).toBe('package-lock.json');
      }
    });

    it('handles scoped package names', () => {
      const scoped = byName(result.packages, '@angular/core');
      expect(scoped.ecosystem).toBe('npm');
      expect(scoped.versionKind).toBe('exact');
    });
  });

  // ---- Lockfile versions -------------------------------------------------

  it('reads a v3 lockfile from the flat packages map', () => {
    const result = parsed({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { lodash: '^4.17.21' } },
        'node_modules/lodash': { version: '4.17.21' },
        'node_modules/ms': { version: '2.1.3', dev: true },
      },
    });

    expect(result.packages).toHaveLength(2);
    expect(byName(result.packages, 'lodash').relationship).toBe('direct');
    expect(byName(result.packages, 'ms').relationship).toBe('transitive');
    expect(byName(result.packages, 'ms').scope).toBe('development');
  });

  it('reads a v2 lockfile from the flat map, not its legacy tree', () => {
    // v2 carries both. The flat map states each entry's resolved version and dev flag
    // directly, so it is preferred; reading the legacy tree would lose the dev flags.
    const result = parsed({
      lockfileVersion: 2,
      packages: {
        '': { dependencies: { lodash: '^4.17.21' } },
        'node_modules/lodash': { version: '4.17.21' },
      },
      dependencies: { lodash: { version: '0.0.1-WRONG' } },
    });

    expect(result.packages).toHaveLength(1);
    expect(byName(result.packages, 'lodash').declaredVersion).toBe('4.17.21');
  });

  it('reads a v1 lockfile from the nested dependencies tree', () => {
    const result = parseNpmLockfile(
      {
        lockfileVersion: 1,
        dependencies: {
          express: {
            version: '4.18.2',
            dependencies: { ms: { version: '2.1.3' } },
          },
        },
      },
      'package-lock.json',
      'package-lock.json',
    );
    if (result.kind !== 'parsed') throw new Error('expected parsed');

    expect(result.packages).toHaveLength(2);
    // Nesting is how v1 expresses the install tree: top level is direct.
    expect(byName(result.packages, 'express').relationship).toBe('direct');
    expect(byName(result.packages, 'ms').relationship).toBe('transitive');
  });

  it('reports an unsupported future lockfile version by number', () => {
    const result = parseNpmLockfile({ lockfileVersion: 99 }, 'package-lock.json', 'x.json');
    expect(result.kind).toBe('unsupported');
    if (result.kind !== 'unsupported') throw new Error('expected unsupported');
    expect(result.reason).toContain('99');
    // Guessing a future format's shape is how a parser silently produces a wrong
    // inventory, so it is named rather than attempted.
    expect(result.reason).toContain('1, 2 and 3');
  });

  // ---- Malformed and hostile input ---------------------------------------

  it('rejects input that is not an object', () => {
    for (const body of [null, undefined, 42, 'text', [], true]) {
      expect(parseNpmLockfile(body, 'package-lock.json', 'p').kind).toBe('invalid');
    }
  });

  it('rejects a lockfile with no version', () => {
    const result = parseNpmLockfile({ packages: {} }, 'package-lock.json', 'p');
    expect(result.kind).toBe('invalid');
  });

  it('reports an empty lockfile as an empty inventory, not a failure', () => {
    // A real and legitimate state: a project with no dependencies at all.
    const result = parsed({ lockfileVersion: 3, packages: { '': {} } });
    expect(result.packages).toHaveLength(0);
    expect(result.coverage.totalPackages).toBe(0);
  });

  it('survives entries of every wrong type', () => {
    const result = parsed({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { a: '^1' } },
        'node_modules/a': { version: '1.0.0' },
        'node_modules/b': null,
        'node_modules/c': 'string',
        'node_modules/d': 42,
        'node_modules/e': [],
        'node_modules/f': { version: null },
        'node_modules/g': { version: { nested: true } },
      },
    });

    // The well-formed entry survives; the rest are skipped or recorded as versionless.
    expect(byName(result.packages, 'a').resolution).toBe('resolved');
    expect(result.packages.every((pkg) => pkg.name.length > 0)).toBe(true);
  });

  it('does not treat inherited object properties as packages', () => {
    // Lockfile keys are attacker-controlled. A naive `obj[key]` walk resolves
    // `__proto__`, `constructor` and `toString` to inherited values.
    const result = parsed({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/real': { version: '1.0.0' },
      },
    });

    expect(result.packages).toHaveLength(1);
    expect(result.packages.map((pkg) => pkg.name)).toEqual(['real']);
  });

  it('ignores a __proto__ key rather than acting on it', () => {
    const body = JSON.parse(
      '{"lockfileVersion":3,"packages":{"":{},"__proto__":{"polluted":true},"node_modules/ok":{"version":"1.0.0"}}}',
    ) as unknown;

    const result = parsed(body);
    expect(result.packages.map((pkg) => pkg.name)).toEqual(['ok']);
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });

  it('does not overflow on a deeply nested v1 tree', () => {
    // The input a recursive walker would crash on, which is exactly the input a depth
    // bound exists to reject.
    let deepest: Record<string, unknown> = { version: '1.0.0' };
    for (let index = 0; index < 5000; index += 1) {
      deepest = { version: '1.0.0', dependencies: { [`pkg-${index}`]: deepest } };
    }

    const result = parseNpmLockfile(
      { lockfileVersion: 1, dependencies: { root: deepest } },
      'package-lock.json',
      'package-lock.json',
    );

    expect(result.kind).toBe('parsed');
    if (result.kind !== 'parsed') return;
    // The depth bound was hit, and said so rather than silently truncating.
    expect(result.coverage.transitiveCoverage).toBe('partial');
    expect(result.notes.some((note) => note.includes('levels deep'))).toBe(true);
  });

  it('bounds the number of entries read', () => {
    const packages: Record<string, unknown> = { '': {} };
    for (let index = 0; index < 25000; index += 1) {
      packages[`node_modules/pkg-${index}`] = { version: '1.0.0' };
    }

    const result = parsed({ lockfileVersion: 3, packages });
    expect(result.packages).toHaveLength(20000);
    expect(result.coverage.transitiveCoverage).toBe('partial');
    expect(result.notes.some((note) => note.includes('truncated'))).toBe(true);
  });

  // ---- Versions that must never reach OSV --------------------------------

  it('never marks a non-exact version as resolved', () => {
    const result = parsed({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/ranged': { version: '^1.2.3' },
        'node_modules/tagged': { version: 'latest' },
        'node_modules/aliased': { version: 'npm:other@1.0.0' },
        'node_modules/missing': {},
        'node_modules/exact': { version: '1.2.3' },
      },
    });

    expect(byName(result.packages, 'exact').resolution).toBe('resolved');
    for (const name of ['ranged', 'tagged', 'aliased', 'missing']) {
      expect(byName(result.packages, name).resolution).not.toBe('resolved');
    }

    // The invariant that matters: only the exact version is ever queried.
    const queryable = queryablePackages(result.packages);
    expect(queryable.map((pkg) => pkg.name)).toEqual(['exact']);
  });

  it('excludes workspace link entries from the inventory', () => {
    const result = parsed({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/my-app': { resolved: 'packages/app', link: true },
        'node_modules/lodash': { version: '4.17.21' },
      },
    });

    // A link points at a directory in this repository: no registry identity, nothing to
    // check, and counting it would inflate the dependency count.
    expect(result.packages.map((pkg) => pkg.name)).toEqual(['lodash']);
    expect(result.notes.some((note) => note.includes('workspace link'))).toBe(true);
  });
});

describe('packageNameFromPath', () => {
  it('reads names from every lockfile path shape', () => {
    expect(packageNameFromPath('node_modules/lodash')).toBe('lodash');
    expect(packageNameFromPath('node_modules/@babel/core')).toBe('@babel/core');
    // Nested install: the package is the one after the LAST node_modules.
    expect(packageNameFromPath('node_modules/a/node_modules/b')).toBe('b');
    expect(packageNameFromPath('node_modules/a/node_modules/@scope/b')).toBe('@scope/b');
    // Workspace install.
    expect(packageNameFromPath('packages/app/node_modules/x')).toBe('x');
  });

  it('returns null for paths that name no package', () => {
    expect(packageNameFromPath('')).toBeNull();
    expect(packageNameFromPath('packages/app')).toBeNull();
    expect(packageNameFromPath('node_modules/')).toBeNull();
    expect(packageNameFromPath('node_modules/@scope')).toBeNull();
  });
});

describe('mergeInventories', () => {
  function inventory(
    entries: readonly { name: string; version: string; dev?: boolean }[],
    path: string,
  ) {
    const result = parseNpmLockfile(
      {
        lockfileVersion: 3,
        packages: {
          '': { dependencies: Object.fromEntries(entries.map((e) => [e.name, '*'])) },
          ...Object.fromEntries(
            entries.map((e) => [`node_modules/${e.name}`, { version: e.version, dev: e.dev }]),
          ),
        },
      },
      'package-lock.json',
      path,
    );
    if (result.kind !== 'parsed') throw new Error('expected parsed');
    return {
      packages: result.packages,
      source: 'package-lock.json' as const,
      transitiveCoverage: result.coverage.transitiveCoverage,
    };
  }

  it('does not double-count the same package across workspaces', () => {
    const merged = mergeInventories(
      [
        inventory([{ name: 'lodash', version: '4.17.21' }], 'packages/a/package-lock.json'),
        inventory([{ name: 'lodash', version: '4.17.21' }], 'packages/b/package-lock.json'),
      ],
      [],
    );

    // Two workspaces depending on the same version is one dependency, not two.
    expect(merged.packages).toHaveLength(1);
    expect(merged.coverage.totalPackages).toBe(1);
    expect(merged.coverage.duplicateEntries).toBe(1);
  });

  it('keeps genuinely different versions separate', () => {
    const merged = mergeInventories(
      [
        inventory([{ name: 'lodash', version: '4.17.21' }], 'a/package-lock.json'),
        inventory([{ name: 'lodash', version: '3.0.0' }], 'b/package-lock.json'),
      ],
      [],
    );
    expect(merged.packages).toHaveLength(2);
  });

  it('never downgrades what is known about a merged package', () => {
    const asDirectProduction = inventory([{ name: 'x', version: '1.0.0' }], 'a/package-lock.json');
    const asTransitiveDev = {
      ...asDirectProduction,
      packages: asDirectProduction.packages.map((pkg) => ({
        ...pkg,
        relationship: 'transitive' as const,
        scope: 'development' as const,
      })),
    };

    const merged = mergeInventories([asTransitiveDev, asDirectProduction], []);
    const pkg = merged.packages[0];

    // Declared directly somewhere means direct; shipping to users somewhere means
    // production. Taking the first seen would hide both.
    expect(pkg?.relationship).toBe('direct');
    expect(pkg?.scope).toBe('production');
  });

  it('takes the weakest transitive coverage across sources', () => {
    const full = inventory([{ name: 'a', version: '1.0.0' }], 'a/package-lock.json');
    const partial = {
      ...full,
      transitiveCoverage: 'partial' as const,
    };
    const merged = mergeInventories([full, partial], []);

    // An inventory is only as complete as its least complete part.
    expect(merged.coverage.transitiveCoverage).toBe('partial');
  });
});
