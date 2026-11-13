import type { OsvEcosystem } from '../../core/models/dependency.model';

/**
 * Package URL type to OSV ecosystem mapping.
 *
 * This lives in the engine rather than in `core/models` because it is analysis data, not
 * application vocabulary — and because the engine may only import *types* from the
 * application layers (§4.4). Importing it as a value from `core/models` would give the
 * engine a runtime dependency on the application, which the purity rules reject.
 *
 * `githubactions` and `github` are deliberately absent. Both appear in real GitHub SBOMs
 * — Phase 0 measured 17 and 1 respectively in `npm/cli` — but neither is an OSV package
 * ecosystem in this form, so packages carrying them are reported as unsupported rather
 * than queried and silently returning nothing.
 */
export const PURL_TYPE_TO_ECOSYSTEM: Readonly<Record<string, OsvEcosystem>> = {
  npm: 'npm',
  pypi: 'PyPI',
  maven: 'Maven',
  golang: 'Go',
  cargo: 'crates.io',
  nuget: 'NuGet',
  gem: 'RubyGems',
  composer: 'Packagist',
} as const;

/**
 * Ecosystems verified against live SBOM data in Phase 0.
 *
 * Only `npm` and `PyPI` were actually observed. The rest are mapped on documentation
 * alone, and §5.2 forbids claiming ecosystem support that has not been demonstrated — so
 * the report states which ecosystems are verified rather than implying parity.
 */
export const VERIFIED_ECOSYSTEMS: readonly OsvEcosystem[] = ['npm', 'PyPI'] as const;

export function isVerifiedEcosystem(ecosystem: OsvEcosystem): boolean {
  return VERIFIED_ECOSYSTEMS.includes(ecosystem);
}
