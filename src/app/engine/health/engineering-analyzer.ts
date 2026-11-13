import type { EngineeringSignals, SecurityCheck } from '../../core/models/health-report.model';
import type { RepositorySnapshot } from '../../core/models/repository.model';
import { absenceIsMeaningful, findPath } from '../security/security-checks';

/**
 * Engineering and project quality signals (§5.5).
 *
 * These are *observable signals*, not quality judgements. §5.5 is explicit: the presence
 * of a test directory does not mean tests are comprehensive, and DepGuard must say
 * "test configuration detected" rather than anything about coverage or correctness. The
 * wording throughout reflects that.
 */

/** Directories and files that indicate a test setup. */
const TEST_DIRECTORY = /^(test|tests|spec|specs|__tests__|src\/test|src\/tests)\//i;
const TEST_CONFIG =
  /^(jest\.config\.(js|ts|mjs|cjs|json)|vitest\.config\.(js|ts|mjs)|karma\.conf\.js|pytest\.ini|tox\.ini|phpunit\.xml(\.dist)?|\.mocharc\.(json|yml|yaml|js)|cypress\.config\.(js|ts)|playwright\.config\.(js|ts))$/i;
const TEST_FILE = /(\.|_|-)(test|spec)\.[a-z]+$/i;

function documentationCheck(
  snapshot: RepositorySnapshot,
  id: string,
  label: string,
  candidates: readonly string[],
  explanation: string,
): SecurityCheck {
  const path = findPath(snapshot, candidates);
  if (path !== null) {
    return {
      id,
      label,
      status: 'Configured',
      evidence: {
        checked: candidates.join(', '),
        found: `Found ${path}`,
        source: path,
        explanation,
      },
    };
  }

  if (!absenceIsMeaningful(snapshot)) {
    return {
      id,
      label,
      status: 'Unknown',
      evidence: {
        checked: candidates.join(', '),
        found: 'The repository file list could not be read in full.',
        source: 'GitHub git/trees API',
        explanation: 'DepGuard could not determine whether this file is present.',
        limitation: 'Absence from a truncated file list is not evidence that a file is missing.',
      },
    };
  }

  return {
    id,
    label,
    status: 'Not detected',
    evidence: {
      checked: candidates.join(', '),
      found: 'No matching file was found.',
      source: 'Repository file tree',
      explanation,
    },
  };
}

/**
 * Test configuration detection.
 *
 * Reports only that a test setup is *present*. It says nothing about coverage, whether
 * the tests pass, or whether they are meaningful — none of which is observable without
 * running them, which DepGuard never does (§14).
 */
function testingCheck(snapshot: RepositorySnapshot): SecurityCheck {
  const id = 'tests';
  const label = 'Test configuration';
  const checked = 'Test directories, test configuration files and test file naming patterns';

  const entries = snapshot.tree?.entries ?? [];
  const paths = entries.filter((entry) => entry.type === 'blob').map((entry) => entry.path);
  const directories = entries.map((entry) => entry.path);

  const matchedDirectory = directories.find((path) => TEST_DIRECTORY.test(path));
  const matchedConfig = paths.find((path) => TEST_CONFIG.test(path));
  const matchedFile = paths.find((path) => TEST_FILE.test(path));
  const evidencePath = matchedConfig ?? matchedDirectory ?? matchedFile;

  if (evidencePath !== undefined) {
    return {
      id,
      label,
      status: 'Configured',
      evidence: {
        checked,
        found: `Found ${evidencePath}`,
        source: evidencePath,
        explanation:
          'Test configuration was detected. This indicates that automated tests exist; it says nothing about how much of the code they cover or whether they pass.',
        limitation:
          'DepGuard does not execute repository code, so test quality, coverage and results cannot be assessed.',
      },
    };
  }

  if (!absenceIsMeaningful(snapshot)) {
    return {
      id,
      label,
      status: 'Unknown',
      evidence: {
        checked,
        found: 'The repository file list could not be read in full.',
        source: 'GitHub git/trees API',
        explanation: 'DepGuard could not determine whether tests are configured.',
        limitation: 'Large repositories return a truncated file list.',
      },
    };
  }

  return {
    id,
    label,
    status: 'Not detected',
    evidence: {
      checked,
      found: 'No recognisable test directory, configuration or test file was found.',
      source: 'Repository file tree',
      explanation:
        'No test setup was detected using common naming conventions. Projects using unusual layouts may still have tests.',
      limitation: 'Detection is based on common conventions and may miss unconventional setups.',
    },
  };
}

/** Repository description and topics — basic discoverability. */
function descriptionCheck(snapshot: RepositorySnapshot): SecurityCheck {
  const hasDescription = snapshot.metadata.description !== null;
  const topicCount = snapshot.metadata.topics.length;

  return {
    id: 'project-description',
    label: 'Project description',
    status: hasDescription ? 'Configured' : 'Not detected',
    evidence: {
      checked: 'Repository description and topics',
      found: hasDescription
        ? `Description present${topicCount > 0 ? `, ${topicCount} topic${topicCount === 1 ? '' : 's'}` : ', no topics'}`
        : 'No repository description is set.',
      source: 'GitHub repository metadata',
      explanation: hasDescription
        ? 'The repository describes its purpose, which helps people understand what it does.'
        : 'Without a description, visitors must infer the project’s purpose from its code.',
    },
  };
}

export function analyseEngineering(snapshot: RepositorySnapshot): EngineeringSignals {
  const readme = documentationCheck(
    snapshot,
    'readme',
    'README',
    ['README.md', 'README', 'README.rst', 'README.txt', 'Readme.md', 'readme.md'],
    'A README is the entry point for anyone evaluating or using the project.',
  );

  const contributing = documentationCheck(
    snapshot,
    'contributing',
    'Contributing guide',
    ['CONTRIBUTING.md', '.github/CONTRIBUTING.md', 'CONTRIBUTING.rst'],
    'A contributing guide tells newcomers how to propose changes.',
  );

  const codeOfConduct = documentationCheck(
    snapshot,
    'code-of-conduct',
    'Code of conduct',
    ['CODE_OF_CONDUCT.md', '.github/CODE_OF_CONDUCT.md'],
    'A code of conduct sets expectations for participation in the project.',
  );

  const tests = testingCheck(snapshot);
  const description = descriptionCheck(snapshot);

  const checks = [readme, contributing, codeOfConduct, tests, description];

  return {
    checks,
    hasReadme: readme.status === 'Configured',
    // null when unknown, so "we could not look" stays distinct from "there are none".
    hasTests: tests.status === 'Unknown' ? null : tests.status === 'Configured',
    hasCi: (snapshot.workflows ?? []).some((workflow) => workflow.isRepositoryDefined),
  };
}
