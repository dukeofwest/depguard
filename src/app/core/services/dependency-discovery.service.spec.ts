import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { DependencyDiscoveryService, type DiscoveryResult } from './dependency-discovery.service';
import { CacheService } from './cache.service';
import { DISCOVERY_LIMITS, RESPONSE_LIMITS, isDiscoverableManifest } from '../config/api.config';
import type { RepositoryRef, RepositorySnapshot, TreeEntry } from '../models/repository.model';

const REF: RepositoryRef = { owner: 'octocat', repo: 'demo' };
const RAW = 'https://raw.githubusercontent.com/octocat/demo/main';

const LOCKFILE = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { dependencies: { lodash: '^4.17.21' } },
    'node_modules/lodash': { version: '4.17.21' },
  },
});

function snapshot(
  entries: readonly TreeEntry[],
  options: { truncated?: boolean; treeNull?: boolean } = {},
): RepositorySnapshot {
  return {
    metadata: {
      ref: REF,
      fullName: 'octocat/demo',
      description: null,
      htmlUrl: 'https://github.com/octocat/demo',
      defaultBranch: 'main',
      isArchived: false,
      isDisabled: false,
      isFork: false,
      visibility: 'public',
      stars: 0,
      forks: 0,
      openIssues: 0,
      sizeKb: 1,
      primaryLanguage: null,
      licenseSpdxId: null,
      licenseName: null,
      topics: [],
      createdAt: null,
      updatedAt: null,
      pushedAt: '2026-11-14T00:00:00Z',
    },
    tree: options.treeNull === true ? null : { entries, truncated: options.truncated ?? false },
    workflows: null,
    latestRelease: null,
    contributorCount: null,
    languages: null,
    weeklyCommits: null,
    fileContents: {},
    sourceStates: {},
    retrievedAt: '2026-11-14T00:00:00Z',
  };
}

function blob(path: string): TreeEntry {
  return { path, type: 'blob', sizeBytes: 100 };
}

describe('isDiscoverableManifest', () => {
  it('accepts supported lockfiles at any depth', () => {
    expect(isDiscoverableManifest('package-lock.json')).toBe(true);
    expect(isDiscoverableManifest('packages/app/package-lock.json')).toBe(true);
    expect(isDiscoverableManifest('npm-shrinkwrap.json')).toBe(true);
  });

  it('matches the basename exactly, not as a prefix or substring', () => {
    // The pattern allowlist is the whole security property: a near-miss name must not
    // qualify, or the "fixed basenames" claim is not true.
    for (const path of [
      'package-lock.json.bak',
      'docs/package-lock.json.md',
      'my-package-lock.json',
      'package-lock.jsonx',
      'package.json',
      'yarn.lock',
      'Cargo.lock',
      '.github/workflows/ci.yml',
    ]) {
      expect(isDiscoverableManifest(path), path).toBe(false);
    }
  });

  it('rejects traversal and empty segments', () => {
    for (const path of [
      '../package-lock.json',
      'a/../../package-lock.json',
      './package-lock.json',
      'a//package-lock.json',
      '',
    ]) {
      expect(isDiscoverableManifest(path), path).toBe(false);
    }
  });

  it('rejects an absurdly long path', () => {
    expect(isDiscoverableManifest(`${'a/'.repeat(2000)}package-lock.json`)).toBe(false);
  });
});

describe('DependencyDiscoveryService', () => {
  let service: DependencyDiscoveryService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), DependencyDiscoveryService],
    });
    service = TestBed.inject(DependencyDiscoveryService);
    httpMock = TestBed.inject(HttpTestingController);
    TestBed.inject(CacheService).clear();
  });

  afterEach(() => {
    try {
      httpMock.verify();
    } finally {
      TestBed.resetTestingModule();
    }
  });

  function discover(
    entries: readonly TreeEntry[],
    options: { truncated?: boolean; treeNull?: boolean } = {},
  ): { result: () => DiscoveryResult } {
    let value: DiscoveryResult | null = null;
    service.discover(REF, snapshot(entries, options)).subscribe((v) => (value = v));
    return {
      result: () => {
        if (value === null) throw new Error('discovery did not complete');
        return value as DiscoveryResult;
      },
    };
  }

  /**
   * Drains every raw-content request, answering each as it appears.
   *
   * Discovery fetches sequentially through `concatMap`, so only one request is in flight
   * at a time and `match()` sees one at a time. Returns the URLs in the order requested.
   */
  function drain(body: string = LOCKFILE): readonly string[] {
    const urls: string[] = [];
    for (;;) {
      const requests = httpMock.match((r) => r.url.startsWith(RAW));
      if (requests.length === 0) {
        return urls;
      }
      for (const request of requests) {
        urls.push(request.request.url);
        request.flush(body);
      }
    }
  }

  // ---- The happy path ----------------------------------------------------

  it('discovers an inventory from a root lockfile', () => {
    const pending = discover([blob('package-lock.json'), blob('README.md')]);
    httpMock.expectOne(`${RAW}/package-lock.json`).flush(LOCKFILE);

    const result = pending.result();
    expect(result.kind).toBe('discovered');
    if (result.kind !== 'discovered') return;

    expect(result.packages).toHaveLength(1);
    expect(result.packages[0]?.name).toBe('lodash');
    expect(result.coverage.inventorySource).toBe('package-lock.json');
    expect(result.sources).toEqual(['package-lock.json']);
    expect(result.partial).toBe(false);
  });

  // ---- The security boundary --------------------------------------------

  it('requests ONLY allowlisted basenames, whatever the tree contains', () => {
    // The tree is attacker-controlled: a repository owner chooses its file names. The
    // only defence is that DepGuard decides which of them it is willing to fetch.
    discover([
      blob('package-lock.json'),
      blob('.env'),
      blob('id_rsa'),
      blob('package-lock.json.bak'),
      blob('secrets/credentials.json'),
      blob('.github/workflows/deploy.yml'),
    ]);

    const requests = httpMock.match(() => true);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.request.url).toBe(`${RAW}/package-lock.json`);
    requests[0]?.flush(LOCKFILE);
  });

  it('never leaves the allowlisted origin', () => {
    discover([blob('package-lock.json'), blob('packages/a/package-lock.json')]);
    for (const url of drain()) {
      expect(url.startsWith('https://raw.githubusercontent.com/octocat/demo/')).toBe(true);
    }
  });

  it('bounds the number of files fetched', () => {
    const entries = Array.from({ length: DISCOVERY_LIMITS.maxManifestFiles + 6 }, (_, i) =>
      blob(`packages/p${i}/package-lock.json`),
    );
    const pending = discover(entries);

    // A repository shipping hundreds of candidate manifests must not produce hundreds of
    // requests from one page load.
    expect(drain()).toHaveLength(DISCOVERY_LIMITS.maxManifestFiles);

    const result = pending.result();
    expect(result.kind).toBe('discovered');
    if (result.kind !== 'discovered') return;
    // Reaching a limit is reported as incomplete discovery, never absorbed silently.
    expect(result.partial).toBe(true);
    expect(result.notes.some((note) => note.includes('not read'))).toBe(true);
  });

  it('prefers shallower lockfiles when the file limit truncates the set', () => {
    const entries = [
      blob('packages/very/deep/nested/package-lock.json'),
      blob('package-lock.json'),
      ...Array.from({ length: DISCOVERY_LIMITS.maxManifestFiles }, (_, i) =>
        blob(`packages/p${i}/package-lock.json`),
      ),
    ];
    discover(entries);

    // The root lockfile is the most representative single file, so it must not be the
    // one dropped.
    expect(drain()).toContain(`${RAW}/package-lock.json`);
  });

  it('reports an oversized lockfile as unread, not as malformed', () => {
    const pending = discover([blob('package-lock.json')]);
    // `getRawFile` truncates at the file-content limit, which would otherwise make a
    // large lockfile look like invalid JSON.
    httpMock.expectOne(`${RAW}/package-lock.json`).flush('x'.repeat(600 * 1024));

    const result = pending.result();
    expect(result.kind).toBe('parse-failed');
    if (result.kind !== 'parse-failed') return;
    expect(result.reason).toContain('larger than');
  });

  // ---- Discovery states (§4.5) ------------------------------------------

  it('distinguishes no manifest from an unreadable file list', () => {
    const noManifest = discover([blob('README.md')]).result();
    expect(noManifest.kind).toBe('no-manifest');

    const noTree = discover([], { treeNull: true }).result();
    expect(noTree.kind).toBe('cannot-determine');
  });

  it('never claims absence from a truncated file list', () => {
    // `torvalds/linux` returns 71,474 entries with truncated: true. A lockfile could be
    // among the ones GitHub did not list, so absence proves nothing.
    const result = discover([blob('README.md')], { truncated: true }).result();
    expect(result.kind).toBe('cannot-determine');
    if (result.kind !== 'cannot-determine') return;
    expect(result.reason).toContain('truncated');
  });

  it('reports a malformed lockfile as a parse failure, not an empty inventory', () => {
    const pending = discover([blob('package-lock.json')]);
    httpMock.expectOne(`${RAW}/package-lock.json`).flush('{ not json');

    const result = pending.result();
    expect(result.kind).toBe('parse-failed');
    if (result.kind !== 'parse-failed') return;
    expect(result.reason).toContain('not valid JSON');
  });

  it('reports an unsupported lockfile version as unsupported', () => {
    const pending = discover([blob('package-lock.json')]);
    httpMock.expectOne(`${RAW}/package-lock.json`).flush(JSON.stringify({ lockfileVersion: 99 }));

    const result = pending.result();
    expect(result.kind).toBe('unsupported');
  });

  it('keeps a usable inventory when one of several lockfiles fails', () => {
    const pending = discover([blob('package-lock.json'), blob('packages/a/package-lock.json')]);
    httpMock.expectOne(`${RAW}/package-lock.json`).flush(LOCKFILE);
    httpMock.expectOne(`${RAW}/packages/a/package-lock.json`).flush('{ broken');

    const result = pending.result();
    expect(result.kind).toBe('discovered');
    if (result.kind !== 'discovered') return;

    // §10.5: a partial result stays useful, and says what it lost.
    expect(result.packages).toHaveLength(1);
    expect(result.partial).toBe(true);
    expect(result.notes.some((note) => note.includes('packages/a/package-lock.json'))).toBe(true);
  });

  it('reports a file listed in the tree but not served', () => {
    const pending = discover([blob('package-lock.json')]);
    httpMock.expectOne(`${RAW}/package-lock.json`).flush('', {
      status: 404,
      statusText: 'Not Found',
    });

    const result = pending.result();
    expect(result.kind).toBe('parse-failed');
  });

  it('merges a monorepo without double-counting', () => {
    const pending = discover([
      blob('packages/a/package-lock.json'),
      blob('packages/b/package-lock.json'),
    ]);
    httpMock.expectOne(`${RAW}/packages/a/package-lock.json`).flush(LOCKFILE);
    httpMock.expectOne(`${RAW}/packages/b/package-lock.json`).flush(LOCKFILE);

    const result = pending.result();
    expect(result.kind).toBe('discovered');
    if (result.kind !== 'discovered') return;

    // The same package at the same version in two workspaces is one dependency.
    expect(result.packages).toHaveLength(1);
    expect(result.sources).toHaveLength(2);
  });

  // ---- .NET discovery (Phase D) ------------------------------------------

  describe('.NET', () => {
    const CSPROJ = `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
      <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    </ItemGroup></Project>`;

    const PROPS = `<Project><ItemGroup>
      <PackageVersion Include="Serilog" Version="3.1.1" />
    </ItemGroup></Project>`;

    const NUGET_LOCK = JSON.stringify({
      version: 1,
      dependencies: {
        '.NETCoreApp,Version=v8.0': {
          'Newtonsoft.Json': { type: 'Direct', requested: '[13.0.1, )', resolved: '13.0.3' },
          'Microsoft.Extensions.Logging': { type: 'Transitive', resolved: '8.0.0' },
        },
      },
    });

    /** Answers each sequential request with the body chosen for its path. */
    function serve(bodies: Readonly<Record<string, string>>): readonly string[] {
      const urls: string[] = [];
      for (;;) {
        const requests = httpMock.match((r) => r.url.startsWith(RAW));
        if (requests.length === 0) {
          return urls;
        }
        for (const request of requests) {
          const path = request.request.url.slice(RAW.length + 1);
          urls.push(path);
          const body = bodies[path];
          if (body === undefined) {
            request.flush('', { status: 404, statusText: 'Not Found' });
          } else {
            request.flush(body);
          }
        }
      }
    }

    it('discovers declared dependencies from a .csproj and does not query them', () => {
      const pending = discover([blob('App/App.csproj')]);
      serve({ 'App/App.csproj': CSPROJ });

      const result = pending.result();
      expect(result.kind).toBe('discovered');
      if (result.kind !== 'discovered') return;

      expect(result.packages).toHaveLength(1);
      const pkg = result.packages[0];
      expect(pkg?.name).toBe('Newtonsoft.Json');
      expect(pkg?.ecosystem).toBe('NuGet');
      // The whole point: a project-file version is a minimum, so nothing is queryable
      // and the report says so rather than claiming a clean scan.
      expect(pkg?.resolution).toBe('declared-minimum');
      expect(result.coverage.queryablePackages).toBe(0);
      expect(result.coverage.transitiveCoverage).toBe('none');
    });

    it('reads Central Package Management before the project that inherits from it', () => {
      const pending = discover([blob('Directory.Packages.props'), blob('src/App/App.csproj')]);
      const order = serve({
        'Directory.Packages.props': PROPS,
        'src/App/App.csproj': `<Project><ItemGroup>
          <PackageReference Include="Serilog" />
        </ItemGroup></Project>`,
      });

      // Ordering is load-bearing: a .csproj cannot be interpreted until the props file
      // has been read, so the props file must be fetched first.
      expect(order.indexOf('Directory.Packages.props')).toBeLessThan(
        order.indexOf('src/App/App.csproj'),
      );

      const result = pending.result();
      expect(result.kind).toBe('discovered');
      if (result.kind !== 'discovered') return;
      expect(result.packages[0]?.declaredVersion).toBe('3.1.1');
    });

    it('uses packages.lock.json for resolved versions and queries them', () => {
      const pending = discover([blob('App/packages.lock.json')]);
      serve({ 'App/packages.lock.json': NUGET_LOCK });

      const result = pending.result();
      expect(result.kind).toBe('discovered');
      if (result.kind !== 'discovered') return;

      expect(result.packages).toHaveLength(2);
      expect(result.coverage.queryablePackages).toBe(2);
      expect(result.coverage.transitiveCoverage).toBe('full');
      expect(result.coverage.inventorySource).toBe('packages.lock.json');
    });

    it('prefers the lockfile resolution over the project declaration', () => {
      const pending = discover([blob('App/App.csproj'), blob('App/packages.lock.json')]);
      serve({ 'App/App.csproj': CSPROJ, 'App/packages.lock.json': NUGET_LOCK });

      const result = pending.result();
      expect(result.kind).toBe('discovered');
      if (result.kind !== 'discovered') return;

      // Both entries exist; only the resolved one is checkable, and the declared 13.0.1
      // must never be the version queried.
      const queryable = result.packages.filter((pkg) => pkg.resolution === 'resolved');
      expect(queryable.map((pkg) => pkg.declaredVersion).sort()).toEqual(['13.0.3', '8.0.0']);
      // A lockfile plus declaration-only project files is partial, never full.
      expect(result.coverage.transitiveCoverage).toBe('partial');
    });

    it('does not treat a props file alone as an inventory', () => {
      const pending = discover([blob('Directory.Packages.props')]);
      serve({ 'Directory.Packages.props': PROPS });

      // PackageVersion declares a version for a reference made elsewhere. With no
      // project file, nothing depends on anything.
      const result = pending.result();
      expect(result.kind).toBe('no-manifest');
    });

    it('rejects a project file containing an XXE attempt', () => {
      const pending = discover([blob('App/App.csproj')]);
      serve({
        'App/App.csproj': `<!DOCTYPE p [<!ENTITY x SYSTEM "file:///etc/passwd">]><Project>&x;</Project>`,
      });

      const result = pending.result();
      expect(result.kind).toBe('parse-failed');
      if (result.kind !== 'parse-failed') return;
      expect(result.reason).toContain('DOCTYPE');
    });

    it('bounds the number of project files fetched', () => {
      const entries = Array.from({ length: DISCOVERY_LIMITS.maxProjectFiles + 10 }, (_, i) =>
        blob(`src/P${i}/P${i}.csproj`),
      );
      const pending = discover(entries);
      const served = serve(Object.fromEntries(entries.map((e) => [e.path, CSPROJ])));

      // `dotnet/machinelearning` has 83 .csproj files, so the cap has to be real.
      expect(served).toHaveLength(DISCOVERY_LIMITS.maxProjectFiles);

      const result = pending.result();
      expect(result.kind).toBe('discovered');
      if (result.kind !== 'discovered') return;
      expect(result.partial).toBe(true);
    });

    it('fetches lockfiles before project files', () => {
      const pending = discover([blob('src/App/App.csproj'), blob('src/App/packages.lock.json')]);
      const order = serve({
        'src/App/App.csproj': CSPROJ,
        'src/App/packages.lock.json': NUGET_LOCK,
      });

      expect(order.indexOf('src/App/packages.lock.json')).toBeLessThan(
        order.indexOf('src/App/App.csproj'),
      );
      expect(pending.result().kind).toBe('discovered');
    });

    it('discovers a mixed npm and NuGet repository', () => {
      const pending = discover([blob('package-lock.json'), blob('App/App.csproj')]);
      serve({ 'package-lock.json': LOCKFILE, 'App/App.csproj': CSPROJ });

      const result = pending.result();
      expect(result.kind).toBe('discovered');
      if (result.kind !== 'discovered') return;

      const ecosystems = [...new Set(result.packages.map((pkg) => pkg.ecosystem))].sort();
      expect(ecosystems).toEqual(['NuGet', 'npm']);

      // npm's lockfile gives the full graph for its packages; the .csproj gives none for
      // its own. Neither "full" nor "none" describes the result, so it is partial.
      expect(result.coverage.transitiveCoverage).toBe('partial');
      // npm's resolved versions are queryable; the .NET declaration is not.
      expect(result.coverage.queryablePackages).toBe(1);
    });

    it('accepts .vbproj and .fsproj', () => {
      const pending = discover([blob('A/A.vbproj'), blob('B/B.fsproj')]);
      serve({ 'A/A.vbproj': CSPROJ, 'B/B.fsproj': CSPROJ });

      const result = pending.result();
      expect(result.kind).toBe('discovered');
      if (result.kind !== 'discovered') return;
      expect(result.packages).toHaveLength(1);
      expect([...result.sources].sort()).toEqual(['A/A.vbproj', 'B/B.fsproj']);
    });
  });

  it('is cancellable', () => {
    const subscription = service.discover(REF, snapshot([blob('package-lock.json')])).subscribe();
    subscription.unsubscribe();

    // Unsubscribing must abandon the queue rather than leaving requests in flight.
    for (const request of httpMock.match(() => true)) {
      expect(request.cancelled).toBe(true);
    }
  });

  // ---- The aggregate download budget ------------------------------------
  //
  // These exercise the configured constants, never a test-local substitute: the claim
  // being tested is about the limit DepGuard actually ships with.

  describe('aggregate byte budget', () => {
    const CAP = DISCOVERY_LIMITS.maxManifestBytes;
    const PER_FILE = RESPONSE_LIMITS.maxFileContentBytes;
    /** A response that exactly fills one file's allowance. */
    const FULL_FILE = 'x'.repeat(PER_FILE);

    /** Serves every pending raw request until the queue is quiescent. */
    function serveAll(body: (path: string) => string): readonly string[] {
      const served: string[] = [];
      for (;;) {
        const requests = httpMock.match((r) => r.url.startsWith(RAW));
        if (requests.length === 0) {
          return served;
        }
        for (const request of requests) {
          const path = request.request.url.slice(RAW.length + 1);
          served.push(path);
          request.flush(body(path));
        }
      }
    }

    it('is exactly eight full-size files, from the shipped constants', () => {
      // Pins the arithmetic the tests below depend on. If either constant changes, this
      // fails loudly rather than letting the budget tests quietly stop exercising the
      // boundary they were written for.
      expect(CAP).toBe(4 * 1024 * 1024);
      expect(PER_FILE).toBe(512 * 1024);
      expect(CAP / PER_FILE).toBe(8);
      // And the file caps allow more candidates than the byte budget can pay for, which
      // is the only reason an aggregate limit is load-bearing at all.
      expect(DISCOVERY_LIMITS.maxProjectFiles).toBeGreaterThan(CAP / PER_FILE);
    });

    it('stops requesting files once the aggregate budget is spent', () => {
      const entries = [
        blob('package-lock.json'),
        ...Array.from({ length: DISCOVERY_LIMITS.maxProjectFiles }, (_, i) =>
          blob(`p${i}/P${i}.csproj`),
        ),
      ];
      const pending = discover(entries);

      const served = serveAll((path) => (path === 'package-lock.json' ? LOCKFILE : FULL_FILE));

      // The lockfile plus eight 512 KB project files spends the 4 MB. The remaining
      // sixteen candidates are never requested — not fetched and discarded.
      expect(served).toHaveLength(9);
      expect(served[0]).toBe('package-lock.json');
      expect(served.length).toBeLessThan(entries.length);

      const result = pending.result();
      expect(result.kind).toBe('discovered');
      if (result.kind !== 'discovered') return;

      // What was collected before exhaustion survives it.
      expect(result.packages.some((p) => p.name === 'lodash')).toBe(true);
      // And the result reads as incomplete, not as clean.
      expect(result.partial).toBe(true);
      expect(result.notes.some((note) => note.includes('4 MB'))).toBe(true);
      expect(result.notes.some((note) => note.includes('not requested'))).toBe(true);
    });

    it('charges unparseable responses to the budget', () => {
      const entries = Array.from({ length: DISCOVERY_LIMITS.maxProjectFiles }, (_, i) =>
        blob(`p${i}/P${i}.csproj`),
      );
      const pending = discover(entries);

      // 512 KB of text that is not valid XML. It contributes no packages at all, and it
      // still cost the bandwidth, so it is still charged.
      const served = serveAll(() => FULL_FILE);

      // Eight responses fill 4 MB exactly and the ninth is never requested. Were bytes
      // counted only on a successful parse, all twenty-four would have been fetched.
      expect(served).toHaveLength(8);

      const result = pending.result();
      // Nothing parsed — but "no supported manifest exists" would be false. DepGuard
      // stopped looking, and has to say which of those two happened.
      expect(result.kind).toBe('cannot-determine');
      if (result.kind !== 'cannot-determine') return;
      expect(result.reason).toContain('4 MB');
    });

    it('keeps the per-file limit separate from the aggregate one', () => {
      const pending = discover([blob('package-lock.json'), blob('packages/a/package-lock.json')]);

      const served = serveAll((path) =>
        path === 'package-lock.json' ? 'y'.repeat(PER_FILE + 1) : LOCKFILE,
      );

      // The oversized file is refused on its own 512 KB cap, with the aggregate barely
      // touched — so the next candidate is still requested and still read.
      expect(served).toEqual(['package-lock.json', 'packages/a/package-lock.json']);

      const result = pending.result();
      expect(result.kind).toBe('discovered');
      if (result.kind !== 'discovered') return;
      expect(result.packages.some((p) => p.name === 'lodash')).toBe(true);
      expect(result.partial).toBe(true);
      expect(result.notes.some((note) => note.includes('larger than'))).toBe(true);
      // A per-file refusal must not be reported as the scan running out of budget.
      expect(result.notes.some((note) => note.includes('4 MB'))).toBe(false);
    });

    it('stops pending work when a part-spent scan is cancelled', () => {
      const entries = Array.from({ length: DISCOVERY_LIMITS.maxProjectFiles }, (_, i) =>
        blob(`p${i}/P${i}.csproj`),
      );
      const subscription = service.discover(REF, snapshot(entries)).subscribe();

      // Serve two, so the queue is genuinely part-way through rather than untouched.
      for (let i = 0; i < 2; i += 1) {
        const requests = httpMock.match((r) => r.url.startsWith(RAW));
        expect(requests).toHaveLength(1);
        requests[0]?.flush(FULL_FILE);
      }

      subscription.unsubscribe();

      const open = httpMock.match((r) => r.url.startsWith(RAW));
      expect(open).toHaveLength(1);
      expect(open[0]?.cancelled).toBe(true);
      // Nothing is scheduled after the cancellation either.
      expect(httpMock.match((r) => r.url.startsWith(RAW))).toHaveLength(0);
    });

    it('gives each subscription its own budget', () => {
      // The budget is mutable state. Built once and shared, a second scan would start
      // with the first one's spending already against it and fetch nothing.
      for (let run = 0; run < 2; run += 1) {
        // Cleared so the second run genuinely re-requests the file; this is a claim
        // about the budget resetting, not about the response cache.
        TestBed.inject(CacheService).clear();

        const pending = discover([blob('package-lock.json')]);
        expect(serveAll(() => LOCKFILE)).toEqual(['package-lock.json']);

        const result = pending.result();
        expect(result.kind).toBe('discovered');
        if (result.kind !== 'discovered') return;
        expect(result.partial).toBe(false);
      }
    });
  });
});
