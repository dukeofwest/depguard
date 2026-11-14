import { describe, expect, it } from 'vitest';

import { evaluateSecurityChecks } from './security-checks';
import type { SecurityCheck } from '../../core/models/health-report.model';
import type {
  RepositorySnapshot,
  TreeEntry,
  WorkflowSummary,
} from '../../core/models/repository.model';

/**
 * Repository security configuration checks.
 *
 * Every test here answers the same question in a different place: **does this check
 * distinguish "we looked and it is not there" from "we could not look?"** Three of the
 * November 2026 audit findings were failures of exactly that distinction (P1-8, P1-9,
 * P1-10), each turning unavailable evidence into a scored outcome.
 */

function snapshot(partial: Partial<RepositorySnapshot> = {}): RepositorySnapshot {
  return {
    metadata: {
      ref: { owner: 'octocat', repo: 'demo' },
      fullName: 'octocat/demo',
      description: 'A demo',
      htmlUrl: 'https://github.com/octocat/demo',
      defaultBranch: 'main',
      isArchived: false,
      isDisabled: false,
      isFork: false,
      visibility: 'public',
      stars: 1,
      forks: 0,
      openIssues: 0,
      sizeKb: 1,
      primaryLanguage: 'TypeScript',
      licenseSpdxId: 'MIT',
      licenseName: 'MIT License',
      topics: [],
      createdAt: null,
      updatedAt: null,
      pushedAt: '2026-11-14T00:00:00Z',
    },
    tree: { entries: [], truncated: false },
    workflows: [],
    latestRelease: null,
    contributorCount: 1,
    languages: null,
    weeklyCommits: null,
    fileContents: {},
    sourceStates: {},
    retrievedAt: '2026-11-14T00:00:00Z',
    ...partial,
  };
}

function blob(path: string): TreeEntry {
  return { path, type: 'blob', sizeBytes: 100 };
}

function workflow(path: string, name: string): WorkflowSummary {
  return { name, path, state: 'active', isRepositoryDefined: true };
}

function checkFor(id: string, partial: Partial<RepositorySnapshot>): SecurityCheck {
  const found = evaluateSecurityChecks(snapshot(partial)).find((check) => check.id === id);
  if (found === undefined) {
    throw new Error(`no check with id ${id}`);
  }
  return found;
}

// ===========================================================================
// P1-8: CI detection when the Actions API fails
// ===========================================================================

describe('continuous integration check (P1-8)', () => {
  it('reports Configured from the Actions API', () => {
    const check = checkFor('ci-workflow', {
      workflows: [workflow('.github/workflows/ci.yml', 'CI')],
    });
    expect(check.status).toBe('Configured');
    expect(check.evidence.found).toContain('1 GitHub Actions workflow');
  });

  it('reports Configured from the file tree when the Actions API fails', () => {
    // The regression. `optional()` turns every transport failure into a null, so this
    // path is reached easily — and it previously reported "No CI configuration was
    // found" and deducted 15 points from a repository whose CI was plainly there.
    const check = checkFor('ci-workflow', {
      workflows: null,
      tree: { entries: [blob('.github/workflows/ci.yml')], truncated: false },
    });

    expect(check.status).toBe('Configured');
    expect(check.evidence.found).toContain('file tree');
    // The evidence names the source that established it, and what that source cannot say.
    expect(check.evidence.limitation).toContain('GitHub Actions API was unavailable');
  });

  it('reports Unknown when the Actions API fails and the tree shows no CI', () => {
    // Not "Not detected": one of the two sources could not be consulted, so absence is
    // not established (§10.1, constraint 17).
    const check = checkFor('ci-workflow', {
      workflows: null,
      tree: { entries: [blob('README.md')], truncated: false },
    });

    expect(check.status).toBe('Unknown');
    expect(check.evidence.limitation).toContain('Absence of evidence');
  });

  it('reports Unknown when neither source is readable', () => {
    expect(checkFor('ci-workflow', { workflows: null, tree: null }).status).toBe('Unknown');
  });

  it('reports Unknown when the tree is truncated and the API found nothing', () => {
    const check = checkFor('ci-workflow', {
      workflows: [],
      tree: { entries: [], truncated: true },
    });
    expect(check.status).toBe('Unknown');
  });

  it('reports Not detected only when both sources agree there is none', () => {
    const check = checkFor('ci-workflow', {
      workflows: [],
      tree: { entries: [blob('README.md')], truncated: false },
    });
    expect(check.status).toBe('Not detected');
  });

  it('recognises non-Actions CI systems', () => {
    for (const path of ['.travis.yml', 'Jenkinsfile', '.gitlab-ci.yml', 'azure-pipelines.yml']) {
      const check = checkFor('ci-workflow', {
        workflows: [],
        tree: { entries: [blob(path)], truncated: false },
      });
      expect(check.status, path).toBe('Configured');
    }
  });

  it('ignores a path that merely resembles a workflow file', () => {
    const check = checkFor('ci-workflow', {
      workflows: [],
      tree: {
        entries: [
          blob('.github/workflows/nested/deep.yml'),
          blob('.github/workflows/readme.md'),
          blob('docs/.github/workflows/ci.yml'),
        ],
        truncated: false,
      },
    });
    // GitHub does not recurse into the workflows directory, and a .md file there is not
    // a workflow. Counting them would be a false positive.
    expect(check.status).toBe('Not detected');
  });
});

// ===========================================================================
// P1-9: Dependabot evidence must match its status
// ===========================================================================

describe('Dependabot configuration check (P1-9)', () => {
  const path = '.github/dependabot.yml';

  it('reports Configured for a valid configuration', () => {
    const check = checkFor('dependabot-config', {
      tree: { entries: [blob(path)], truncated: false },
      fileContents: {
        [path]:
          'version: 2\nupdates:\n  - package-ecosystem: npm\n    schedule:\n      interval: weekly\n',
      },
    });
    expect(check.status).toBe('Configured');
    expect(check.evidence.explanation).toContain('does not prove');
  });

  it('does not credit a file that declares no updates section', () => {
    // The regression: this previously scored the full 25 points — the heaviest check in
    // the category — while its own evidence said no updates section was recognised.
    const check = checkFor('dependabot-config', {
      tree: { entries: [blob(path)], truncated: false },
      fileContents: { [path]: '# TODO: configure dependabot\n' },
    });

    expect(check.status).toBe('Not detected');
    expect(check.evidence.found).toContain('declares no "updates" section');
    // Status and evidence now agree, which §7.5 requires.
    expect(check.evidence.explanation).toContain('would not open any update pull requests');
  });

  it('does not credit an updates section with no package ecosystem', () => {
    const check = checkFor('dependabot-config', {
      tree: { entries: [blob(path)], truncated: false },
      fileContents: { [path]: 'version: 2\nupdates: []\n' },
    });
    expect(check.status).toBe('Not detected');
    expect(check.evidence.found).toContain('no package ecosystem');
  });

  it('credits multiple ecosystems and multiple entries', () => {
    const check = checkFor('dependabot-config', {
      tree: { entries: [blob(path)], truncated: false },
      fileContents: {
        [path]:
          'version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: "/"\n  - package-ecosystem: nuget\n    directory: "/src"\n  - package-ecosystem: github-actions\n',
      },
    });
    expect(check.status).toBe('Configured');
  });

  it('does not credit unrecognisable content', () => {
    for (const content of ['', 'not yaml at all', '{{{', 'updates\n', 'package-ecosystem: npm\n']) {
      const check = checkFor('dependabot-config', {
        tree: { entries: [blob(path)], truncated: false },
        fileContents: { [path]: content },
      });
      expect(check.status, JSON.stringify(content)).toBe('Not detected');
    }
  });

  it('states the subset it recognises rather than claiming full validation', () => {
    const check = checkFor('dependabot-config', {
      tree: { entries: [blob(path)], truncated: false },
      fileContents: { [path]: '# empty\n' },
    });
    // The parser is deliberately limited, so the limitation says so — a valid config in
    // an unrecognised form would land here, and the reader needs to know that.
    expect(check.evidence.limitation).toContain('a form it does not recognise');
  });

  it('reports Unknown when the file list could not be read', () => {
    expect(checkFor('dependabot-config', { tree: null }).status).toBe('Unknown');
  });

  it('reports Not detected when there is genuinely no file', () => {
    const check = checkFor('dependabot-config', {
      tree: { entries: [blob('README.md')], truncated: false },
    });
    expect(check.status).toBe('Not detected');
    expect(check.evidence.limitation).toContain('repository settings');
  });

  it('reports Unknown when the file is listed but its contents could not be fetched', () => {
    // Found by the invariant test at the foot of this file, against a first attempt at
    // P1-9 that made the status depend on content without handling the case where the
    // content is the thing that is missing.
    const check = checkFor('dependabot-config', {
      tree: { entries: [blob(path)], truncated: false },
      fileContents: {},
    });
    expect(check.status).toBe('Unknown');
    expect(check.evidence.found).toContain('could not be retrieved');
  });
});

// ===========================================================================
// P1-10: CodeQL verification must match its description
// ===========================================================================

describe('CodeQL check (P1-10)', () => {
  const CODEQL = `name: CodeQL
jobs:
  analyze:
    steps:
      - uses: github/codeql-action/init@v3
      - uses: github/codeql-action/analyze@v3
`;

  it('reports Configured when a workflow actually invokes the action', () => {
    const check = checkFor('codeql-workflow', {
      workflows: [workflow('.github/workflows/codeql.yml', 'CodeQL')],
      tree: { entries: [blob('.github/workflows/codeql.yml')], truncated: false },
      fileContents: { '.github/workflows/codeql.yml': CODEQL },
    });

    expect(check.status).toBe('Configured');
    expect(check.evidence.found).toContain('github/codeql-action');
    // The check says what it verified, and what it did not.
    expect(check.evidence.explanation).toContain('by reading the workflow file');
    expect(check.evidence.limitation).toContain('does not confirm that the workflow runs');
  });

  it('does NOT credit a workflow merely named CodeQL', () => {
    // The finding. `codeql.yml` could contain anything, and a workflow called "CodeQL"
    // that does nothing previously earned the full 15 points because the check matched
    // the name while its docblock claimed to verify the content.
    const check = checkFor('codeql-workflow', {
      workflows: [workflow('.github/workflows/codeql.yml', 'CodeQL')],
      tree: { entries: [blob('.github/workflows/codeql.yml')], truncated: false },
      fileContents: {
        '.github/workflows/codeql.yml':
          'name: CodeQL\njobs:\n  noop:\n    steps:\n      - run: echo hi\n',
      },
    });

    expect(check.status).toBe('Not detected');
    expect(check.evidence.found).toContain('named as though it configures CodeQL');
    expect(check.evidence.explanation).toContain('name does not establish what it runs');
  });

  it('finds the action in a differently-named workflow', () => {
    const check = checkFor('codeql-workflow', {
      workflows: [workflow('.github/workflows/security.yml', 'Security')],
      tree: { entries: [blob('.github/workflows/security.yml')], truncated: false },
      fileContents: { '.github/workflows/security.yml': CODEQL },
    });
    // Content verification cuts both ways: it also catches the workflow a name match
    // would have missed.
    expect(check.status).toBe('Configured');
    expect(check.evidence.source).toBe('.github/workflows/security.yml');
  });

  it('reports Unknown when workflows exist but their contents could not be read', () => {
    const check = checkFor('codeql-workflow', {
      workflows: [workflow('.github/workflows/ci.yml', 'CI')],
      tree: { entries: [blob('.github/workflows/ci.yml')], truncated: false },
      fileContents: {},
    });
    // Unavailable evidence must not become a finding.
    expect(check.status).toBe('Unknown');
    expect(check.evidence.found).toContain('could not be read');
  });

  it('reports Unknown when the file list is unreadable', () => {
    expect(checkFor('codeql-workflow', { workflows: null, tree: null }).status).toBe('Unknown');
  });

  it('reports Not detected for a repository with no workflows at all', () => {
    const check = checkFor('codeql-workflow', {
      workflows: [],
      tree: { entries: [blob('README.md')], truncated: false },
    });
    expect(check.status).toBe('Not detected');
    expect(check.evidence.limitation).toContain('without a workflow file');
  });

  it('does not credit an unsupported action reference', () => {
    const check = checkFor('codeql-workflow', {
      workflows: [workflow('.github/workflows/scan.yml', 'Scan')],
      tree: { entries: [blob('.github/workflows/scan.yml')], truncated: false },
      fileContents: {
        '.github/workflows/scan.yml':
          'jobs:\n  s:\n    steps:\n      - uses: some/other-scanner@v1\n',
      },
    });
    expect(check.status).toBe('Not detected');
  });

  it('accepts the CodeQL CLI invoked directly', () => {
    const check = checkFor('codeql-workflow', {
      workflows: [workflow('.github/workflows/scan.yml', 'Scan')],
      tree: { entries: [blob('.github/workflows/scan.yml')], truncated: false },
      fileContents: {
        '.github/workflows/scan.yml':
          'jobs:\n  s:\n    steps:\n      - run: codeql database analyze db\n',
      },
    });
    expect(check.status).toBe('Configured');
  });
});

// ===========================================================================
// P2-2: the security policy check's stated search must match its code
// ===========================================================================

describe('security policy check (P2-2)', () => {
  it('finds a policy in each supported location', () => {
    for (const path of ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md']) {
      const check = checkFor('security-policy', {
        tree: { entries: [blob(path)], truncated: false },
      });
      expect(check.status, path).toBe('Configured');
      expect(check.evidence.source, path).toBe(path);
    }
  });

  it('states every location it searched', () => {
    const check = checkFor('security-policy', {
      tree: { entries: [blob('README.md')], truncated: false },
    });
    // The evidence block is the product's claim to trustworthiness, so it has to be
    // exact: it previously omitted docs/SECURITY.md, which the code does search.
    for (const path of ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md']) {
      expect(check.evidence.checked).toContain(path);
    }
  });

  it('prefers the first matching file when several exist', () => {
    const check = checkFor('security-policy', {
      tree: {
        entries: [blob('SECURITY.md'), blob('.github/SECURITY.md'), blob('docs/SECURITY.md')],
        truncated: false,
      },
    });
    expect(check.status).toBe('Configured');
  });

  it('reports Unknown rather than Not detected on a truncated tree', () => {
    const check = checkFor('security-policy', { tree: { entries: [], truncated: true } });
    expect(check.status).toBe('Unknown');
  });

  it('reports Not detected when the tree is complete and has no policy', () => {
    expect(
      checkFor('security-policy', { tree: { entries: [blob('README.md')], truncated: false } })
        .status,
    ).toBe('Not detected');
  });
});

// ===========================================================================
// The invariant across every check
// ===========================================================================

describe('unavailable evidence never becomes a finding', () => {
  it('INVARIANT: nulling a source never turns a check into Not detected', () => {
    // §10.1 and constraint 17, asserted mechanically rather than per-check: for every
    // source, removing it may produce Unknown but must never produce a negative finding
    // that was not there when the source was available.
    const complete = snapshot({
      workflows: [workflow('.github/workflows/ci.yml', 'CI')],
      tree: {
        entries: [
          blob('.github/workflows/ci.yml'),
          blob('.github/dependabot.yml'),
          blob('SECURITY.md'),
          blob('LICENSE'),
        ],
        truncated: false,
      },
      fileContents: {
        '.github/dependabot.yml': 'version: 2\nupdates:\n  - package-ecosystem: npm\n',
        '.github/workflows/ci.yml': 'jobs:\n  t:\n    steps:\n      - run: npm test\n',
      },
    });

    const baseline = new Map(
      evaluateSecurityChecks(complete).map((check) => [check.id, check.status]),
    );

    const degradations: readonly Partial<RepositorySnapshot>[] = [
      { workflows: null },
      { tree: null },
      { tree: { entries: [], truncated: true } },
      { fileContents: {} },
      { workflows: null, tree: null, fileContents: {} },
    ];

    for (const degradation of degradations) {
      const degraded = evaluateSecurityChecks({ ...complete, ...degradation });
      for (const check of degraded) {
        const before = baseline.get(check.id);
        if (before === 'Configured') {
          // Losing a source may make a check uncertain. It must not make it a failure.
          expect(
            check.status,
            `${check.id} became ${check.status} after ${JSON.stringify(degradation)}`,
          ).not.toBe('Not detected');
        }
      }
    }
  });
});
