import type { CheckStatus, Evidence } from '../../core/models/analysis.model';
import type { SecurityCheck } from '../../core/models/health-report.model';
import type { RepositorySnapshot } from '../../core/models/repository.model';

/**
 * Observable security configuration checks (§5.3).
 *
 * Every check reports what was examined, what was found, and — crucially — what the
 * finding does *not* prove. DepGuard can see that a configuration file exists; it cannot
 * see whether the corresponding GitHub feature is switched on, because that requires
 * authentication (ADR-0004). Saying "Dependabot is enabled" would be a claim we have no
 * evidence for.
 *
 * Pure: takes a snapshot, returns checks. No I/O, no clock.
 */

/** Case-insensitive path lookup. express ships `Readme.md`, not `README.md`. */
function findPath(snapshot: RepositorySnapshot, candidates: readonly string[]): string | null {
  const entries = snapshot.tree?.entries ?? [];
  const wanted = candidates.map((candidate) => candidate.toLowerCase());
  for (const entry of entries) {
    if (entry.type === 'blob' && wanted.includes(entry.path.toLowerCase())) {
      return entry.path;
    }
  }
  return null;
}

/**
 * Whether absence can be trusted.
 *
 * When the tree is missing or truncated, "not in the list" does not mean "not in the
 * repository" — Phase 0 measured `torvalds/linux` returning 71,474 entries with
 * `truncated: true`. In that case a check must report `Unknown`, never `Not detected`.
 */
function absenceIsMeaningful(snapshot: RepositorySnapshot): boolean {
  return snapshot.tree !== null && !snapshot.tree.truncated;
}

function unknownBecauseTreeMissing(id: string, label: string, checked: string): SecurityCheck {
  return {
    id,
    label,
    status: 'Unknown',
    evidence: {
      checked,
      found: 'The repository file list could not be read in full.',
      source: 'GitHub git/trees API',
      explanation:
        'DepGuard could not retrieve a complete file list, so it cannot tell whether this is configured.',
      limitation:
        'Very large repositories return a truncated file list. Absence of a file from a truncated list is not evidence that it is missing.',
    },
  };
}

function check(id: string, label: string, status: CheckStatus, evidence: Evidence): SecurityCheck {
  return { id, label, status, evidence };
}

/** `SECURITY.md` in either supported location. */
function securityPolicyCheck(snapshot: RepositorySnapshot): SecurityCheck {
  const id = 'security-policy';
  const label = 'Security policy';
  const checked = 'SECURITY.md and .github/SECURITY.md';

  if (!absenceIsMeaningful(snapshot)) {
    return unknownBecauseTreeMissing(id, label, checked);
  }

  const path = findPath(snapshot, ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md']);
  if (path === null) {
    return check(id, label, 'Not detected', {
      checked,
      found: 'No security policy file was found.',
      source: 'Repository file tree',
      explanation:
        'A security policy tells people how to report vulnerabilities privately. Without one, reports may arrive as public issues.',
    });
  }

  return check(id, label, 'Configured', {
    checked,
    found: `Found ${path}`,
    source: path,
    explanation: 'The repository publishes a process for reporting security issues.',
  });
}

/**
 * Dependabot configuration.
 *
 * File contents are fetched from raw.githubusercontent.com at no quota cost, so the check
 * can confirm the file actually declares updates rather than merely existing.
 */
function dependabotCheck(snapshot: RepositorySnapshot): SecurityCheck {
  const id = 'dependabot-config';
  const label = 'Dependabot configuration';
  const checked = '.github/dependabot.yml and .github/dependabot.yaml';

  const contentPath = ['.github/dependabot.yml', '.github/dependabot.yaml'].find(
    (path) => snapshot.fileContents[path] !== undefined,
  );
  const content = contentPath === undefined ? undefined : snapshot.fileContents[contentPath];

  if (content === undefined) {
    if (!absenceIsMeaningful(snapshot)) {
      return unknownBecauseTreeMissing(id, label, checked);
    }
    return check(id, label, 'Not detected', {
      checked,
      found: 'No Dependabot configuration file was found.',
      source: 'Repository file tree',
      explanation:
        'Dependabot can open pull requests for outdated or vulnerable dependencies. No configuration file was found.',
      limitation:
        'Dependabot security updates can be enabled in repository settings without a configuration file, which DepGuard cannot see without authentication.',
    });
  }

  // A conservative structural check, not a YAML parse: the claim being made is only that
  // the file declares update configuration, which does not warrant a parser dependency
  // processing untrusted input (ADR-0005).
  const declaresUpdates = /^\s*updates\s*:/m.test(content);

  return check(id, label, 'Configured', {
    checked,
    found: declaresUpdates
      ? `Found ${contentPath} declaring an "updates" section.`
      : `Found ${contentPath}, but no "updates" section was recognised.`,
    source: contentPath ?? '.github/dependabot.yml',
    explanation:
      'A Dependabot configuration file is present. This confirms that update configuration exists, but does not prove that Dependabot alerts or security updates are enabled.',
    limitation:
      'Whether Dependabot is actually running requires authenticated access to repository settings, which this release does not use.',
  });
}

/**
 * CodeQL workflow.
 *
 * Requires that a workflow actually references the CodeQL action, rather than inferring
 * it from a filename — `codeql.yml` could contain anything.
 */
function codeqlCheck(snapshot: RepositorySnapshot): SecurityCheck {
  const id = 'codeql-workflow';
  const label = 'CodeQL analysis workflow';
  const checked = 'Workflows under .github/workflows/';

  const workflows = snapshot.workflows;
  if (workflows === null) {
    return check(id, label, 'Unknown', {
      checked,
      found: 'The workflow list could not be retrieved.',
      source: 'GitHub Actions API',
      explanation: 'DepGuard could not determine whether a CodeQL workflow is configured.',
    });
  }

  const repositoryWorkflows = workflows.filter((workflow) => workflow.isRepositoryDefined);
  const candidate = repositoryWorkflows.find((workflow) =>
    /codeql|code-scanning/i.test(`${workflow.name} ${workflow.path}`),
  );

  if (candidate === undefined) {
    return check(id, label, 'Not detected', {
      checked,
      found: 'No workflow referencing CodeQL was found.',
      source: '.github/workflows/',
      explanation:
        'CodeQL is GitHub’s static analysis scanner. No workflow appearing to configure it was found.',
      limitation:
        'Code scanning can also be enabled by default without a workflow file, which DepGuard cannot verify without authentication.',
    });
  }

  return check(id, label, 'Configured', {
    checked,
    found: `Found workflow ${candidate.path}`,
    source: candidate.path,
    explanation:
      'A workflow that appears to configure CodeQL analysis is present. This does not confirm that it runs successfully or that its results are acted on.',
    limitation: 'Workflow run results require authentication and are not checked in this release.',
  });
}

/** Dependency review action. */
function dependencyReviewCheck(snapshot: RepositorySnapshot): SecurityCheck {
  const id = 'dependency-review';
  const label = 'Dependency review workflow';
  const checked = 'Workflows under .github/workflows/';

  if (snapshot.workflows === null) {
    return check(id, label, 'Unknown', {
      checked,
      found: 'The workflow list could not be retrieved.',
      source: 'GitHub Actions API',
      explanation: 'DepGuard could not determine whether dependency review is configured.',
    });
  }

  const candidate = snapshot.workflows
    .filter((workflow) => workflow.isRepositoryDefined)
    .find((workflow) => /dependency.?review/i.test(`${workflow.name} ${workflow.path}`));

  if (candidate === undefined) {
    return check(id, label, 'Not detected', {
      checked,
      found: 'No dependency review workflow was found.',
      source: '.github/workflows/',
      explanation:
        'The dependency review action flags vulnerable dependencies introduced by a pull request before they are merged.',
    });
  }

  return check(id, label, 'Configured', {
    checked,
    found: `Found workflow ${candidate.path}`,
    source: candidate.path,
    explanation:
      'A workflow that appears to run dependency review is present. Detection of a workflow is not confirmation that it runs or passes.',
  });
}

/** Any repository-defined CI workflow. */
function ciCheck(snapshot: RepositorySnapshot): SecurityCheck {
  const id = 'ci-workflow';
  const label = 'Continuous integration';
  const checked = 'Workflows under .github/workflows/ and common CI configuration files';

  if (snapshot.workflows === null && !absenceIsMeaningful(snapshot)) {
    return check(id, label, 'Unknown', {
      checked,
      found: 'Neither the workflow list nor the file tree could be read.',
      source: 'GitHub Actions API',
      explanation: 'DepGuard could not determine whether CI is configured.',
    });
  }

  // Only workflows the repository actually committed count. GitHub also lists workflows
  // it injects, under paths such as `dynamic/...`, which the repository never authored.
  const actions = (snapshot.workflows ?? []).filter((workflow) => workflow.isRepositoryDefined);

  const otherCiPaths = (snapshot.tree?.entries ?? [])
    .filter((entry) => entry.type === 'blob')
    .map((entry) => entry.path)
    .filter((path) =>
      /^(\.travis\.yml|\.circleci\/config\.yml|\.gitlab-ci\.yml|azure-pipelines\.yml|Jenkinsfile|\.drone\.yml)$/i.test(
        path,
      ),
    );

  if (actions.length === 0 && otherCiPaths.length === 0) {
    return check(id, label, 'Not detected', {
      checked,
      found: 'No CI configuration was found.',
      source: '.github/workflows/',
      explanation:
        'No automated build or test pipeline was detected. Changes may not be verified automatically.',
    });
  }

  const found =
    actions.length > 0
      ? `${actions.length} GitHub Actions workflow${actions.length === 1 ? '' : 's'}`
      : `CI configuration: ${otherCiPaths.join(', ')}`;

  return check(id, label, 'Configured', {
    checked,
    found,
    source: actions[0]?.path ?? otherCiPaths[0] ?? '.github/workflows/',
    explanation:
      'CI configuration is present. DepGuard does not check whether these workflows currently pass.',
    limitation: 'Workflow run results require authentication and are not checked in this release.',
  });
}

/** Licence, from GitHub metadata with the file tree as a fallback. */
function licenseCheck(snapshot: RepositorySnapshot): SecurityCheck {
  const id = 'license';
  const label = 'Licence';
  const checked = 'Repository licence metadata and LICENSE files';

  const spdx = snapshot.metadata.licenseSpdxId;
  // GitHub reports these when it finds a licence file it cannot identify.
  if (spdx !== null && spdx !== 'NOASSERTION') {
    return check(id, label, 'Configured', {
      checked,
      found: `${snapshot.metadata.licenseName ?? spdx} (${spdx})`,
      source: 'GitHub repository metadata',
      explanation: 'The repository declares a licence, which tells others how they may use it.',
    });
  }

  const path = findPath(snapshot, [
    'LICENSE',
    'LICENSE.md',
    'LICENSE.txt',
    'LICENCE',
    'LICENCE.md',
    'COPYING',
  ]);

  if (path !== null) {
    return check(id, label, 'Configured', {
      checked,
      found: `Found ${path}, though GitHub did not identify a standard licence.`,
      source: path,
      explanation:
        'A licence file is present but GitHub could not match it to a recognised licence, which may mean it is modified or custom.',
    });
  }

  if (!absenceIsMeaningful(snapshot)) {
    return unknownBecauseTreeMissing(id, label, checked);
  }

  return check(id, label, 'Not detected', {
    checked,
    found: 'No licence was declared and no licence file was found.',
    source: 'Repository file tree',
    explanation:
      'Without a licence, others have no explicit permission to use, modify or distribute the code.',
  });
}

/** All security configuration checks, in display order. */
export function evaluateSecurityChecks(snapshot: RepositorySnapshot): readonly SecurityCheck[] {
  return [
    securityPolicyCheck(snapshot),
    dependabotCheck(snapshot),
    codeqlCheck(snapshot),
    dependencyReviewCheck(snapshot),
    ciCheck(snapshot),
    licenseCheck(snapshot),
  ];
}

export { findPath, absenceIsMeaningful };
