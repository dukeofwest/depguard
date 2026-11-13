# DepGuard

**Know the health of any GitHub repository.**

DepGuard analyses a public GitHub repository and produces one evidence-backed report
covering its dependencies, security configuration, maintenance activity and engineering
signals.

> **Status: in development.** Phases 0–4 are complete: the analysis engine and both API
> integrations work end to end and are verified against live GitHub and OSV data. The user
> interface is not built yet (Phase 5), so the application currently renders its shell
> only. This README is completed in Phase 7 and claims no feature that is not built.

---

## What it does

Given a repository URL, DepGuard reports five categories:

| Category                   | What it examines                                          |
| -------------------------- | --------------------------------------------------------- |
| **Dependency Security**    | Known advisories affecting resolved dependency versions   |
| **Dependency Health**      | Inventory completeness, ecosystems, metadata quality      |
| **Security Configuration** | Security policy, Dependabot config, CodeQL workflow, CI   |
| **Maintenance & Activity** | Commit and release recency, archived status, contributors |
| **Engineering Quality**    | Documentation, test configuration, CI/CD, licensing       |

It is **not** a replacement for Dependabot, CodeQL, Snyk, Socket, OSV-Scanner or Trivy. It
consolidates observable repository signals and is explicit about what it cannot verify.

## Honesty by design

Phase 0 measured the limits of this approach against live APIs before any code was
written, and three findings shaped the product:

- **Vulnerability coverage depends on lockfiles.** GitHub's SBOM reports versions as
  declared. Without a committed lockfile, those are ranges (`^1.2.1`), not resolved
  versions. OSV silently returns _wrong_ results for a range, so DepGuard queries only
  exact versions. Measured coverage ranged from 84.9% (`npm/cli`) to **0%**
  (`request/request`). Below 50%, the category reports _insufficient data_ rather than a
  misleading clean result.
- **Unknown is never "safe".** PYSEC advisories carry no severity at all (22 of 22
  measured), so `Unknown` is a real severity, excluded from scoring rather than treated as
  low risk.
- **Missing data is not a zero.** A category that cannot be measured is excluded and its
  weight redistributed, so a score is never inflated or deflated by absence.

Full evidence: [`docs/phase-0/FEASIBILITY-REPORT.md`](docs/phase-0/FEASIBILITY-REPORT.md).

## Privacy

Analysis runs entirely in your browser. DepGuard contacts exactly three hosts —
`api.github.com`, `raw.githubusercontent.com` and `api.osv.dev` — and never follows a URL
found inside repository content. There are no accounts, no tokens and no storage: the MVP
analyses public repositories anonymously, so there is no credential to leak.

Anonymous GitHub access is limited to **60 requests per hour per IP**. A scan costs about
9, so expect roughly 6 scans per hour. The UI shows the remaining budget.

## Tech stack

Angular 21 (standalone, zoneless, signals) · strict TypeScript · native CSS with design
tokens · Vitest. No Nx, no NgModules, no UI component framework, and no runtime
dependencies beyond Angular and RxJS.

The analysis logic lives in [`src/app/engine/`](src/app/engine/) as pure TypeScript with no
Angular, DOM or I/O dependencies. That boundary is enforced by both ESLint and a unit test
([`engine-purity.spec.ts`](src/app/engine/engine-purity.spec.ts)), so a violation fails CI.

## Local development

Requires Node 20.19+, 22.12+ or 24+.

```bash
npm install
npm start            # dev server at http://localhost:4200
```

### Verification

```bash
npm run lint         # ESLint, including the engine purity rules
npm run typecheck    # strict tsc, including noUncheckedIndexedAccess
npm test             # Vitest, watch mode
npm run test:ci      # single run
npm run format       # Prettier
```

### Build

```bash
npm run build                                  # production
npm run build -- --configuration github-pages  # adds base href /depguard/
```

The `github-pages` configuration is what CI deploys; it sets the base href to match the
project-page URL.

### Smoke test

[`tools/smoke-test.mjs`](tools/smoke-test.mjs) loads a built bundle in headless Chrome and
reports console errors, rendered content and mobile layout overflow:

```bash
npm run build -- --configuration github-pages
node tools/smoke-test.mjs dist/depguard/browser
```

## Documentation

- [Phase 0 feasibility report](docs/phase-0/FEASIBILITY-REPORT.md) — API matrix, SBOM and
  OSV findings, scoring model, risks
- [Browser CORS proof](docs/phase-0/BROWSER-CORS-PROOF.md) — the architectural risk,
  tested in a real browser
- [Architecture decision records](docs/adr/)

## Licence

MIT
