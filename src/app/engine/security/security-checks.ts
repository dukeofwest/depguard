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
  const checked = 'SECURITY.md, .github/SECURITY.md and docs/SECURITY.md';

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

    // The tree lists a configuration file but its contents could not be fetched. Now
    // that the status depends on the contents, this has to be `Unknown`: the file exists
    // and DepGuard could not read it, which is not the same as there being none.
    const listed = findPath(snapshot, ['.github/dependabot.yml', '.github/dependabot.yaml']);
    if (listed !== null) {
      return check(id, label, 'Unknown', {
        checked,
        found: `${listed} exists but its contents could not be retrieved, so its update configuration was not inspected.`,
        source: listed,
        explanation:
          'DepGuard could not determine whether this configuration declares any updates.',
        limitation:
          'A Dependabot configuration file is only inspected if its contents can be retrieved from raw.githubusercontent.com.',
      });
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
  //
  // The supported subset is deliberately narrow and stated as such: a top-level
  // `updates:` key, followed by at least one list entry naming a `package-ecosystem`.
  // That is what Dependabot requires to do anything at all.
  const declaresUpdates = /^[ \t]*updates[ \t]*:/m.test(content);
  const declaresEcosystem = /^[ \t]*-?[ \t]*package-ecosystem[ \t]*:[ \t]*\S/m.test(content);
  const source = contentPath ?? '.github/dependabot.yml';

  // P1-9: the file's existence is not the evidence. A `dependabot.yml` containing only a
  // comment previously scored the full 25 points — the heaviest check in the category —
  // while the evidence beside it read "no updates section was recognised". §7.5 requires
  // that the score and the explanation agree, and they did not.
  if (!declaresUpdates || !declaresEcosystem) {
    return check(id, label, 'Not detected', {
      checked,
      found: declaresUpdates
        ? `Found ${contentPath}, which declares an "updates" section but no package ecosystem within it.`
        : `Found ${contentPath}, but it declares no "updates" section.`,
      source,
      explanation:
        'A Dependabot configuration file is present but declares no usable update configuration, so Dependabot would not open any update pull requests from it.',
      limitation:
        'DepGuard recognises a top-level "updates" key containing at least one "package-ecosystem" entry. A valid configuration written in a form it does not recognise would be reported this way, and Dependabot security updates can also be enabled in repository settings with no configuration file at all.',
    });
  }

  return check(id, label, 'Configured', {
    checked,
    found: `Found ${contentPath} declaring an "updates" section with at least one package ecosystem.`,
    source,
    explanation:
      'A Dependabot configuration file is present and declares update configuration. This does not prove that Dependabot alerts or security updates are enabled.',
    limitation:
      'Whether Dependabot is actually running requires authenticated access to repository settings, which this release does not use.',
  });
}

/**
 * Matches a real reference to GitHub's CodeQL action.
 *
 * `github/codeql-action/init` or `/analyze`, at any version, with or without a SHA pin.
 * Also accepts the `codeql` CLI invoked directly, which a few projects do.
 */
const CODEQL_ACTION = /uses\s*:\s*["']?github\/codeql-action\/(init|analyze)/i;
const CODEQL_CLI = /\bcodeql\s+(database|github)\s+/i;

/**
 * CodeQL workflow.
 *
 * Reads the workflow **file**, not its name. `codeql.yml` could contain anything, and a
 * workflow called "CodeQL" that does nothing previously earned the full 15 points. The
 * docblock here used to claim this verification while the code matched filenames (P1-10);
 * now the claim and the code agree.
 *
 * Workflow contents are fetched from `raw.githubusercontent.com`, which costs no API
 * quota — which is the only reason content-level verification is affordable at all.
 */
function codeqlCheck(snapshot: RepositorySnapshot): SecurityCheck {
  const id = 'codeql-workflow';
  const label = 'CodeQL analysis workflow';
  const checked = 'The contents of workflow files under .github/workflows/';

  const workflowContents = Object.entries(snapshot.fileContents).filter(([path]) =>
    path.toLowerCase().startsWith('.github/workflows/'),
  );

  // Positive evidence first: a file that genuinely invokes the action.
  const verified = workflowContents.find(
    ([, content]) => CODEQL_ACTION.test(content) || CODEQL_CLI.test(content),
  );

  if (verified !== undefined) {
    return check(id, label, 'Configured', {
      checked,
      found: `${verified[0]} references the github/codeql-action.`,
      source: verified[0],
      explanation:
        'A workflow that invokes GitHub’s CodeQL action is present, verified by reading the workflow file rather than by its name.',
      limitation:
        'This does not confirm that the workflow runs, passes, or that its findings are acted on. Workflow run results require authentication and are not checked in this release.',
    });
  }

  // A workflow whose *name* suggests CodeQL but whose contents do not invoke it. Worth
  // distinguishing: it is the case a name-matching check got wrong, in the direction that
  // awards points for nothing.
  const namedOnly = (snapshot.workflows ?? [])
    .filter((workflow) => workflow.isRepositoryDefined)
    .find((workflow) => /codeql|code-scanning/i.test(`${workflow.name} ${workflow.path}`));

  if (namedOnly !== undefined && workflowContents.length > 0) {
    return check(id, label, 'Not detected', {
      checked,
      found: `${namedOnly.path} is named as though it configures CodeQL, but its contents do not reference the CodeQL action.`,
      source: namedOnly.path,
      explanation:
        'A workflow’s name does not establish what it runs. No workflow invoking GitHub’s CodeQL action was found.',
      limitation:
        'Code scanning can also be enabled in repository settings without a workflow file, which DepGuard cannot verify without authentication.',
    });
  }

  // No contents to read: either the tree was unreadable, or there are no workflow files.
  if (workflowContents.length === 0) {
    const hasWorkflows = (snapshot.workflows ?? []).some(
      (workflow) => workflow.isRepositoryDefined,
    );

    // Workflows exist but their contents could not be fetched. Reporting "not detected"
    // here would turn unavailable evidence into a finding (§10.1).
    if (hasWorkflows || !absenceIsMeaningful(snapshot)) {
      return check(id, label, 'Unknown', {
        checked,
        found: 'Workflow files could not be read, so their contents were not inspected.',
        source: '.github/workflows/',
        explanation:
          'DepGuard could not determine whether a CodeQL workflow is configured, because it could not read the workflow files.',
        limitation:
          'A workflow file is only inspected if the repository file list includes it and its contents can be retrieved.',
      });
    }
  }

  return check(id, label, 'Not detected', {
    checked,
    found: 'No workflow invoking the CodeQL action was found.',
    source: '.github/workflows/',
    explanation:
      'CodeQL is GitHub’s static analysis scanner. No workflow referencing its action was found.',
    limitation:
      'Code scanning can also be enabled by default without a workflow file, which DepGuard cannot verify without authentication.',
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

  // Only workflows the repository actually committed count. GitHub also lists workflows
  // it injects, under paths such as `dynamic/...`, which the repository never authored.
  const actions = (snapshot.workflows ?? []).filter((workflow) => workflow.isRepositoryDefined);

  const treePaths = (snapshot.tree?.entries ?? [])
    .filter((entry) => entry.type === 'blob')
    .map((entry) => entry.path);

  // P1-8: the tree is a second, independent source for the same fact. The previous
  // version searched it only for six *non*-Actions CI files, so a repository whose CI is
  // GitHub Actions reported "No CI configuration was found" and lost 15 points whenever
  // the Actions API call failed — and `optional()` turns every transport failure into a
  // null, so that path was reached easily.
  const workflowPaths = treePaths.filter((path) =>
    /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(path),
  );

  const otherCiPaths = treePaths.filter((path) =>
    /^(\.travis\.yml|\.circleci\/config\.yml|\.gitlab-ci\.yml|azure-pipelines\.yml|Jenkinsfile|\.drone\.yml)$/i.test(
      path,
    ),
  );

  if (actions.length > 0 || workflowPaths.length > 0 || otherCiPaths.length > 0) {
    const fromApi = actions.length > 0;
    const count = fromApi ? actions.length : workflowPaths.length;

    const found =
      count > 0
        ? `${count} GitHub Actions workflow${count === 1 ? '' : 's'}${fromApi ? '' : ', listed in the repository file tree'}`
        : `CI configuration: ${otherCiPaths.join(', ')}`;

    return check(id, label, 'Configured', {
      checked,
      found,
      // Naming the source that actually established the finding, so a reader can tell
      // which evidence was used.
      source: fromApi
        ? (actions[0]?.path ?? '.github/workflows/')
        : (workflowPaths[0] ?? otherCiPaths[0] ?? '.github/workflows/'),
      explanation:
        'CI configuration is present. DepGuard does not check whether these workflows currently pass.',
      limitation: fromApi
        ? 'Workflow run results require authentication and are not checked in this release.'
        : 'The GitHub Actions API was unavailable, so this was established from the repository file list. A workflow file exists; whether it is valid or runs was not checked.',
    });
  }

  // Nothing found. That only means "no CI" if both sources could actually be consulted:
  // the Actions API answered, and the file list is complete.
  if (snapshot.workflows === null || !absenceIsMeaningful(snapshot)) {
    return check(id, label, 'Unknown', {
      checked,
      found:
        snapshot.workflows === null
          ? 'The workflow list could not be retrieved, and no CI configuration file was found in the repository file list.'
          : 'The repository file list could not be read in full.',
      source: snapshot.workflows === null ? 'GitHub Actions API' : 'GitHub git/trees API',
      explanation: 'DepGuard could not determine whether CI is configured.',
      limitation:
        'Absence of evidence from an unavailable source is not evidence that CI is missing.',
    });
  }

  return check(id, label, 'Not detected', {
    checked,
    found: 'No CI configuration was found.',
    source: '.github/workflows/',
    explanation:
      'No automated build or test pipeline was detected. Changes may not be verified automatically.',
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
