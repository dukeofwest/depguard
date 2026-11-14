import { describe, expect, it } from 'vitest';

import {
  declaredResolution,
  nugetCoverage,
  parseCentralVersions,
  parseNuGetLockfile,
  parsePackagesConfig,
  parseProjectFile,
  type CentralVersions,
} from './nuget';
import { XML_LIMITS, parseXml } from './xml';
import { queryablePackages } from '../sbom/spdx-parser';
import { PURL_TYPE_TO_ECOSYSTEM, VERIFIED_ECOSYSTEMS } from './ecosystems';
import type { NormalizedPackage } from '../../core/models/dependency.model';

function project(text: string, central: CentralVersions | null = null, path = 'App/App.csproj') {
  const result = parseProjectFile(text, path, 'csproj', central);
  if (result.kind !== 'parsed') {
    throw new Error(`expected parsed, got: ${result.reason}`);
  }
  return result;
}

function byName(packages: readonly NormalizedPackage[], name: string): NormalizedPackage {
  const found = packages.find((pkg) => pkg.name.toLowerCase() === name.toLowerCase());
  if (found === undefined) {
    throw new Error(`expected to find ${name} in ${packages.map((p) => p.name).join(', ')}`);
  }
  return found;
}

const CSPROJ = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>`;

// ===========================================================================
// XML safety
// ===========================================================================

describe('parseXml', () => {
  it('parses a valid project file', () => {
    const result = parseXml(CSPROJ);
    expect(result.kind).toBe('parsed');
    if (result.kind !== 'parsed') return;
    expect(result.root.name).toBe('Project');
    expect(result.root.attributes['sdk']).toBe('Microsoft.NET.Sdk');
  });

  it('refuses any DOCTYPE declaration', () => {
    // This single rule forecloses the whole XXE and entity-expansion class, rather than
    // trying to tell a safe DTD from a hostile one.
    const result = parseXml('<!DOCTYPE foo><Project />');
    expect(result.kind).toBe('rejected');
    if (result.kind !== 'rejected') return;
    expect(result.reason).toContain('DOCTYPE');
  });

  it('refuses an XML external entity attempt (XXE)', () => {
    const xxe = `<?xml version="1.0"?>
<!DOCTYPE project [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<Project><Name>&xxe;</Name></Project>`;
    expect(parseXml(xxe).kind).toBe('rejected');
  });

  it('refuses an entity expansion attempt (billion laughs)', () => {
    const bomb = `<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<Project>&lol3;</Project>`;
    expect(parseXml(bomb).kind).toBe('rejected');
  });

  it('refuses an undeclared entity reference even with no DOCTYPE', () => {
    // Without a DTD there is nothing to expand it from, so it is either malformed or an
    // attack. Either way, refusing is correct.
    const result = parseXml('<Project><Name>&custom;</Name></Project>');
    expect(result.kind).toBe('rejected');
  });

  it('decodes only the five built-in entities and numeric references', () => {
    const result = parseXml('<P a="&lt;&gt;&amp;&apos;&quot;&#65;&#x42;">t</P>');
    expect(result.kind).toBe('parsed');
    if (result.kind !== 'parsed') return;
    expect(result.root.attributes['a']).toBe(`<>&'"AB`);
  });

  it('rejects surrogate and out-of-range numeric references', () => {
    for (const reference of ['&#xD800;', '&#0;', '&#x110000;']) {
      expect(parseXml(`<P a="${reference}" />`).kind, reference).toBe('rejected');
    }
  });

  it('bounds nesting depth', () => {
    const deep = `${'<a>'.repeat(XML_LIMITS.maxDepth + 10)}x${'</a>'.repeat(XML_LIMITS.maxDepth + 10)}`;
    const result = parseXml(deep);
    expect(result.kind).toBe('rejected');
    if (result.kind !== 'rejected') return;
    expect(result.reason).toContain('levels deep');
  });

  it('bounds the node count', () => {
    const many = `<r>${'<a/>'.repeat(XML_LIMITS.maxNodes + 10)}</r>`;
    const result = parseXml(many);
    expect(result.kind).toBe('rejected');
    if (result.kind !== 'rejected') return;
    expect(result.reason).toContain('elements');
  });

  it('bounds file size', () => {
    const result = parseXml(`<P>${'x'.repeat(XML_LIMITS.maxBytes + 1)}</P>`);
    expect(result.kind).toBe('rejected');
    if (result.kind !== 'rejected') return;
    expect(result.reason).toContain('larger than');
  });

  it('bounds attribute count and value length', () => {
    const attributes = Array.from(
      { length: XML_LIMITS.maxAttributesPerElement + 5 },
      (_, i) => `a${i}="v"`,
    ).join(' ');
    expect(parseXml(`<P ${attributes} />`).kind).toBe('rejected');

    const long = 'x'.repeat(XML_LIMITS.maxValueLength + 1);
    expect(parseXml(`<P a="${long}" />`).kind).toBe('rejected');
  });

  it('rejects malformed XML rather than guessing', () => {
    for (const bad of [
      '<Project>',
      '<Project></Other>',
      '<Project a=unquoted />',
      '<Project a />',
      '<>',
      'not xml at all',
      '',
    ]) {
      expect(parseXml(bad).kind, JSON.stringify(bad)).toBe('rejected');
    }
  });

  it('rejects content after the root element', () => {
    // Two roots is malformed, and silently taking the first would be a guess.
    expect(parseXml('<A /><B />').kind).toBe('rejected');
  });

  it('skips comments, the XML declaration and CDATA', () => {
    const result = parseXml(
      '<?xml version="1.0" encoding="utf-8"?><!-- c --><Project><![CDATA[x]]><A /></Project>',
    );
    expect(result.kind).toBe('parsed');
    if (result.kind !== 'parsed') return;
    expect(result.root.children).toHaveLength(1);
  });

  it('handles an empty project', () => {
    const result = parseXml('<Project />');
    expect(result.kind).toBe('parsed');
    if (result.kind !== 'parsed') return;
    expect(result.root.children).toHaveLength(0);
  });

  it('keeps namespace-prefixed names intact', () => {
    const result = parseXml('<msb:Project xmlns:msb="x"><msb:ItemGroup /></msb:Project>');
    expect(result.kind).toBe('parsed');
  });
});

// ===========================================================================
// The defining rule: declared is not resolved
// ===========================================================================

describe('declared versus resolved versions (§7.2)', () => {
  it('treats a bare NuGet version as a MINIMUM, never as installed', () => {
    const result = project(CSPROJ);
    const json = byName(result.packages, 'Newtonsoft.Json');

    // `Version="13.0.1"` is shorthand for `[13.0.1, )`. The project may well have
    // restored 13.0.3. Querying OSV with 13.0.1 would report advisories fixed in the
    // version actually in use — a false positive that looks completely plausible.
    expect(json.declaredVersion).toBe('13.0.1');
    expect(json.resolution).toBe('declared-minimum');
    expect(json.skipReason).toBe('version-not-exact');

    // The invariant. This is the single most important assertion in the .NET work.
    expect(queryablePackages(result.packages)).toEqual([]);
  });

  it('notes that a version string shaped like an exact version is not one', () => {
    const json = byName(project(CSPROJ).packages, 'Newtonsoft.Json');
    // `versionKind` describes the string's shape, which IS exact; `resolution` describes
    // what it means, which is not. Conflating the two is the trap.
    expect(json.versionKind).toBe('exact');
    expect(json.resolution).not.toBe('resolved');
  });

  it('accepts NuGet bracketed exact syntax as resolved', () => {
    const result = project(
      `<Project><ItemGroup>
        <PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" />
      </ItemGroup></Project>`,
    );
    // `[13.0.1]` is NuGet's "exactly this version" syntax: the only single-value form
    // that genuinely pins, and so the only one that may be queried.
    const json = byName(result.packages, 'Newtonsoft.Json');
    expect(json.resolution).toBe('resolved');
    expect(queryablePackages(result.packages)).toHaveLength(1);
  });

  it('classifies every declared version form', () => {
    expect(declaredResolution('13.0.1')).toBe('declared-minimum');
    expect(declaredResolution('[13.0.1]')).toBe('resolved');
    expect(declaredResolution('[1.0,2.0)')).toBe('declared-range');
    expect(declaredResolution('(1.0,)')).toBe('declared-range');
    expect(declaredResolution('13.0.*')).toBe('declared-range');
    expect(declaredResolution('*')).toBe('declared-range');
    expect(declaredResolution('[1.0,]')).toBe('declared-range');
    expect(declaredResolution('')).toBe('declared-range');
    expect(declaredResolution('not-a-version')).toBe('declared-range');
  });

  it('prefers the lockfile resolution when both exist', () => {
    // The scenario §7.5 asks for explicitly: declared 13.0.1, resolved 13.0.3.
    const declared = project(CSPROJ);
    const lock = parseNuGetLockfile(
      {
        version: 1,
        dependencies: {
          '.NETCoreApp,Version=v8.0': {
            'Newtonsoft.Json': { type: 'Direct', requested: '[13.0.1, )', resolved: '13.0.3' },
          },
        },
      },
      'App/packages.lock.json',
    );
    if (lock.kind !== 'parsed') throw new Error('expected parsed');

    const resolved = byName(lock.packages, 'Newtonsoft.Json');
    expect(resolved.declaredVersion).toBe('13.0.3');
    expect(resolved.resolution).toBe('resolved');

    // The declaration and the resolution remain distinguishable by provenance.
    expect(byName(declared.packages, 'Newtonsoft.Json').source).toBe('csproj');
    expect(resolved.source).toBe('packages.lock.json');

    // Only the resolved version is queried, and it is the lockfile's, not the project's.
    const queryable = queryablePackages([...declared.packages, ...lock.packages]);
    expect(queryable).toHaveLength(1);
    expect(queryable[0]?.declaredVersion).toBe('13.0.3');
  });
});

// ===========================================================================
// packages.lock.json
// ===========================================================================

describe('parseNuGetLockfile', () => {
  const LOCK = {
    version: 1,
    dependencies: {
      '.NETCoreApp,Version=v8.0': {
        'Newtonsoft.Json': { type: 'Direct', requested: '[13.0.1, )', resolved: '13.0.1' },
        'Microsoft.Extensions.Logging': { type: 'Transitive', resolved: '8.0.0' },
      },
    },
  };

  it('reads resolved versions and the direct/transitive split', () => {
    const result = parseNuGetLockfile(LOCK, 'packages.lock.json');
    if (result.kind !== 'parsed') throw new Error('expected parsed');

    expect(result.packages).toHaveLength(2);
    expect(byName(result.packages, 'Newtonsoft.Json').relationship).toBe('direct');
    expect(byName(result.packages, 'Microsoft.Extensions.Logging').relationship).toBe('transitive');
    expect(result.packages.every((pkg) => pkg.resolution === 'resolved')).toBe(true);
    expect(queryablePackages(result.packages)).toHaveLength(2);
  });

  it('never reads `requested` as `resolved`', () => {
    const result = parseNuGetLockfile(
      {
        version: 1,
        dependencies: {
          net8: { Example: { type: 'Project', requested: '[2.0.0, )' } },
        },
      },
      'packages.lock.json',
    );
    if (result.kind !== 'parsed') throw new Error('expected parsed');

    const pkg = byName(result.packages, 'Example');
    // The dependency stays visible, and stays unqueryable.
    expect(pkg.resolution).not.toBe('resolved');
    expect(queryablePackages(result.packages)).toEqual([]);
    expect(result.notes.some((note) => note.includes('no resolved version'))).toBe(true);
  });

  it('handles multiple target frameworks', () => {
    const result = parseNuGetLockfile(
      {
        version: 1,
        dependencies: {
          'net8.0': { A: { type: 'Direct', resolved: '1.0.0' } },
          net48: { A: { type: 'Direct', resolved: '0.9.0' } },
        },
      },
      'packages.lock.json',
    );
    if (result.kind !== 'parsed') throw new Error('expected parsed');

    // Both resolutions are real and different; collapsing them would discard one.
    expect(result.packages).toHaveLength(2);
    expect(result.notes.some((note) => note.includes('target frameworks'))).toBe(true);
  });

  it('rejects a lockfile with no dependency list', () => {
    expect(parseNuGetLockfile({ version: 1 }, 'p').kind).toBe('rejected');
    expect(parseNuGetLockfile(null, 'p').kind).toBe('rejected');
    expect(parseNuGetLockfile('text', 'p').kind).toBe('rejected');
  });

  it('survives entries of the wrong type', () => {
    const result = parseNuGetLockfile(
      {
        version: 1,
        dependencies: {
          net8: { A: { type: 'Direct', resolved: '1.0.0' }, B: null, C: 'x', D: 42 },
          bad: 'not an object',
        },
      },
      'p',
    );
    if (result.kind !== 'parsed') throw new Error('expected parsed');
    expect(result.packages).toHaveLength(1);
  });
});

// ===========================================================================
// packages.config
// ===========================================================================

describe('parsePackagesConfig', () => {
  it('reads installed versions as resolved', () => {
    const result = parsePackagesConfig(
      `<packages>
         <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net48" />
       </packages>`,
      'packages.config',
    );
    if (result.kind !== 'parsed') throw new Error('expected parsed');

    const pkg = byName(result.packages, 'Newtonsoft.Json');
    // The legacy model wrote the restored result here, so unlike a PackageReference this
    // version really is the installed one.
    expect(pkg.resolution).toBe('resolved');
    expect(pkg.relationship).toBe('unknown');
    expect(queryablePackages(result.packages)).toHaveLength(1);
  });

  it('records a missing version rather than inventing one', () => {
    const result = parsePackagesConfig('<packages><package id="A" /></packages>', 'p');
    if (result.kind !== 'parsed') throw new Error('expected parsed');
    expect(byName(result.packages, 'A').resolution).toBe('absent');
    expect(result.notes.some((note) => note.includes('no version'))).toBe(true);
  });

  it('rejects malformed XML', () => {
    expect(parsePackagesConfig('<packages>', 'p').kind).toBe('rejected');
  });
});

// ===========================================================================
// Central Package Management
// ===========================================================================

describe('Central Package Management', () => {
  const PROPS = `<Project>
    <ItemGroup>
      <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
      <PackageVersion Include="Serilog" Version="3.1.1" />
    </ItemGroup>
  </Project>`;

  it('reads central versions', () => {
    const central = parseCentralVersions(PROPS, 'Directory.Packages.props');
    expect(central?.versions['newtonsoft.json']).toBe('13.0.1');
  });

  it('applies a central version to a reference that omits one', () => {
    const central = parseCentralVersions(PROPS, 'Directory.Packages.props');
    const result = project(
      `<Project><ItemGroup>
        <PackageReference Include="Newtonsoft.Json" />
      </ItemGroup></Project>`,
      central,
    );

    const pkg = byName(result.packages, 'Newtonsoft.Json');
    expect(pkg.declaredVersion).toBe('13.0.1');
    // Still a declaration, inherited or not: central management changes where the
    // minimum comes from, not what it means.
    expect(pkg.resolution).toBe('declared-minimum');
    // Provenance points at the file the version actually came from.
    expect(pkg.sourcePath).toBe('Directory.Packages.props');
    expect(result.notes.some((note) => note.includes('Central Package Management'))).toBe(true);
  });

  it('lets a project-level VersionOverride beat the central version', () => {
    const central = parseCentralVersions(PROPS, 'Directory.Packages.props');
    const result = project(
      `<Project><ItemGroup>
        <PackageReference Include="Newtonsoft.Json" VersionOverride="12.0.3" />
      </ItemGroup></Project>`,
      central,
    );
    expect(byName(result.packages, 'Newtonsoft.Json').declaredVersion).toBe('12.0.3');
  });

  it('records no version when neither the project nor central management supplies one', () => {
    const result = project(
      `<Project><ItemGroup><PackageReference Include="Unlisted" /></ItemGroup></Project>`,
      parseCentralVersions(PROPS, 'Directory.Packages.props'),
    );
    const pkg = byName(result.packages, 'Unlisted');
    expect(pkg.resolution).toBe('absent');
    expect(pkg.declaredVersion).toBeNull();
  });

  it('returns null for unreadable props rather than throwing', () => {
    expect(parseCentralVersions('<Project>', 'p')).toBeNull();
  });
});

// ===========================================================================
// Project file details
// ===========================================================================

describe('parseProjectFile', () => {
  it('reads a version from a child element as well as an attribute', () => {
    const result = project(
      `<Project><ItemGroup>
        <PackageReference Include="Serilog"><Version>3.1.1</Version></PackageReference>
      </ItemGroup></Project>`,
    );
    expect(byName(result.packages, 'Serilog').declaredVersion).toBe('3.1.1');
  });

  it('resolves a $(Property) reference when the property is a literal', () => {
    const result = project(
      `<Project>
        <PropertyGroup><SerilogVersion>3.1.1</SerilogVersion></PropertyGroup>
        <ItemGroup><PackageReference Include="Serilog" Version="$(SerilogVersion)" /></ItemGroup>
      </Project>`,
    );
    const pkg = byName(result.packages, 'Serilog');
    expect(pkg.declaredVersion).toBe('3.1.1');
    expect(pkg.resolution).toBe('declared-minimum');
  });

  it('records an unresolvable property as unresolved rather than guessing', () => {
    const result = project(
      `<Project><ItemGroup>
        <PackageReference Include="Serilog" Version="$(UndefinedVersion)" />
      </ItemGroup></Project>`,
    );
    const pkg = byName(result.packages, 'Serilog');
    // MSBuild is never executed, so an undefined property is genuinely unknown.
    expect(pkg.resolution).toBe('unresolved');
    expect(pkg.skipReason).toBe('no-version');
    expect(result.notes.some((note) => note.includes('MSBuild property'))).toBe(true);
    expect(queryablePackages(result.packages)).toEqual([]);
  });

  it('refuses to partially substitute a property', () => {
    const result = project(
      `<Project>
        <PropertyGroup><Major>13</Major></PropertyGroup>
        <ItemGroup><PackageReference Include="A" Version="$(Major).$(Minor).0" /></ItemGroup>
      </Project>`,
    );
    // "13..0" is not a version. Admitting the value is unknown beats shipping nonsense.
    expect(byName(result.packages, 'A').resolution).toBe('unresolved');
  });

  it('keeps a conditional reference and records the uncertainty', () => {
    const result = project(
      `<Project><ItemGroup>
        <PackageReference Include="OnlyOnWindows" Version="1.0.0" Condition="'$(OS)' == 'Windows_NT'" />
      </ItemGroup></Project>`,
    );
    // DepGuard cannot evaluate MSBuild conditions, so it lists the package without
    // deciding whether it applies.
    expect(result.packages).toHaveLength(1);
    expect(result.notes.some((note) => note.includes('conditional'))).toBe(true);
  });

  it('records multi-targeting as a limitation', () => {
    const result = project(
      `<Project>
        <PropertyGroup><TargetFrameworks>net8.0;net48</TargetFrameworks></PropertyGroup>
        <ItemGroup><PackageReference Include="A" Version="1.0.0" /></ItemGroup>
      </Project>`,
    );
    expect(result.notes.some((note) => note.includes('targets 2 frameworks'))).toBe(true);
  });

  it('treats PrivateAssets=all as a development dependency', () => {
    const result = project(
      `<Project><ItemGroup>
        <PackageReference Include="StyleCop.Analyzers" Version="1.1.118" PrivateAssets="all" />
      </ItemGroup></Project>`,
    );
    expect(byName(result.packages, 'StyleCop.Analyzers').scope).toBe('development');
  });

  it('reads PackageReference Update as well as Include', () => {
    const result = project(
      `<Project><ItemGroup>
        <PackageReference Update="Serilog" Version="3.1.1" />
      </ItemGroup></Project>`,
    );
    expect(result.packages).toHaveLength(1);
  });

  it('keeps duplicate references rather than collapsing them silently', () => {
    const result = project(
      `<Project><ItemGroup>
        <PackageReference Include="A" Version="1.0.0" />
        <PackageReference Include="A" Version="1.0.0" />
      </ItemGroup></Project>`,
    );
    // Deduplication happens before querying, not during parsing — the same rule the SBOM
    // and npm parsers follow, so the inventory matches what the file says.
    expect(result.packages).toHaveLength(2);
  });

  it('says plainly that project declarations were not checked', () => {
    const result = project(CSPROJ);
    const note = result.notes.find((n) => n.includes('is a minimum, not the version restored'));
    expect(note).toBeDefined();
    // And tells the user what to do about it.
    expect(note).toContain('packages.lock.json');
  });

  it('handles an empty project file', () => {
    const result = project('<Project Sdk="Microsoft.NET.Sdk" />');
    expect(result.packages).toHaveLength(0);
  });

  it('rejects a malformed project file', () => {
    expect(parseProjectFile('<Project>', 'p', 'csproj', null).kind).toBe('rejected');
  });

  it('is case-insensitive about element and attribute names', () => {
    const result = project(
      `<project><itemgroup><packagereference include="A" version="1.0.0" /></itemgroup></project>`,
    );
    expect(result.packages).toHaveLength(1);
  });
});

// ===========================================================================
// Ecosystem metadata (P2-5)
// ===========================================================================

describe('ecosystem verification metadata', () => {
  it('maps the nuget purl type to the NuGet OSV ecosystem', () => {
    expect(PURL_TYPE_TO_ECOSYSTEM['nuget']).toBe('NuGet');
  });

  it('lists NuGet as OSV-verified, on the strength of measured behaviour', () => {
    // Measured 14 November 2026 against POST /v1/querybatch. Recorded here so the claim
    // has a test behind it rather than a comment.
    expect(VERIFIED_ECOSYSTEMS).toContain('NuGet');
    expect(VERIFIED_ECOSYSTEMS).toContain('npm');
    expect(VERIFIED_ECOSYSTEMS).toContain('PyPI');
  });

  it('does not list ecosystems whose matching has never been exercised', () => {
    // §5.2 and constraint 18: no claim without a working, tested implementation.
    for (const ecosystem of ['Maven', 'Go', 'crates.io', 'RubyGems', 'Packagist'] as const) {
      expect(VERIFIED_ECOSYSTEMS, ecosystem).not.toContain(ecosystem);
    }
  });

  it('keeps OSV compatibility separate from discovery capability', () => {
    // NuGet is OSV-verified AND manifest-parsing is implemented — but a .csproj yields
    // no queryable version, so being on the verified list must not be read as "NuGet
    // dependencies get checked". This test exists to keep those claims distinct.
    const declared = project(CSPROJ);
    expect(VERIFIED_ECOSYSTEMS).toContain('NuGet');
    expect(queryablePackages(declared.packages)).toEqual([]);
  });
});

// ===========================================================================
// Coverage claims
// ===========================================================================

describe('nugetCoverage', () => {
  it('claims no transitive coverage for declarations alone', () => {
    const packages = project(CSPROJ).packages;
    const coverage = nugetCoverage(packages, ['csproj'], []);

    // §5.7: a .csproj cannot express the transitive graph, so the report must not imply
    // it does.
    expect(coverage.transitiveCoverage).toBe('none');
    expect(coverage.queryablePackages).toBe(0);
  });

  it('claims full transitive coverage only for a lockfile', () => {
    const lock = parseNuGetLockfile(
      {
        version: 1,
        dependencies: { net8: { A: { type: 'Direct', resolved: '1.0.0' } } },
      },
      'packages.lock.json',
    );
    if (lock.kind !== 'parsed') throw new Error('expected parsed');

    expect(nugetCoverage(lock.packages, ['packages.lock.json'], []).transitiveCoverage).toBe(
      'full',
    );
    // Mixed sources: the lockfile covers its project, the .csproj files do not.
    expect(
      nugetCoverage(lock.packages, ['packages.lock.json', 'csproj'], []).transitiveCoverage,
    ).toBe('partial');
  });
});
