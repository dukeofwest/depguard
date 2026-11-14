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
 * Ecosystems whose **vulnerability matching** has been verified against live OSV data.
 *
 * This is deliberately narrow, and it is one of four separate questions that must not be
 * conflated (P2-5):
 *
 * 1. **OSV query compatibility** — does OSV answer correctly for this ecosystem's package
 *    identities and version strings? That is what this list records.
 * 2. **SBOM ingestion** — can DepGuard normalise this ecosystem out of GitHub's
 *    dependency graph? True for every entry in `PURL_TYPE_TO_ECOSYSTEM`.
 * 3. **Manifest parsing** — can DepGuard read this ecosystem's files directly? Only npm
 *    and NuGet, and see `docs/audits/DEPENDENCY-ECOSYSTEM-SUPPORT.md` for which files.
 * 4. **Resolved-version discovery** — can DepGuard obtain versions that are actually
 *    installed? npm always (lockfiles record them); NuGet only from `packages.lock.json`
 *    or `packages.config`, never from a `.csproj`.
 *
 * `npm` and `PyPI` were observed in live SBOMs in Phase 0. `NuGet` was added in the
 * November 2026 remediation on the strength of direct measurement against
 * `POST /v1/querybatch`: `Newtonsoft.Json`, `newtonsoft.json` and `NEWTONSOFT.JSON` at
 * 9.0.1 all returned `GHSA-5crp-9r3c-p9vr`, and both two- and four-part version strings
 * matched — so OSV normalises NuGet ids case-insensitively and normalises versions, and
 * DepGuard needs no normalisation of its own. Those measurements are regression-tested in
 * `nuget.spec.ts`.
 *
 * Being on this list does **not** mean an ecosystem's dependencies can be discovered, and
 * the report says so separately. The remaining mappings rest on documentation alone, and
 * §5.2 forbids claiming support that has not been demonstrated.
 */
export const VERIFIED_ECOSYSTEMS: readonly OsvEcosystem[] = ['npm', 'PyPI', 'NuGet'] as const;
