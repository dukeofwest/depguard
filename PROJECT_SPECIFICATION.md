# Project Specification & AI Agent Implementation Prompt

# DepGuard: GitHub Repository Health Analyzer

**Project name:** DepGuard  
**Repository name:** `depguard`  
**Product category:** GitHub Repository Health & Security Intelligence  
**Application type:** Standalone Angular 21 Single-Page Application  
**Release target:** MVP v1.0  
**Deployment target:** GitHub Pages  
**Production URL:** `https://dukeofwest.github.io/depguard/`  
**Development approach:** Phased, incremental implementation with mandatory approval gates  
**Primary objective:** Build a polished, reliable and genuinely useful GitHub repository analysis platform that can become a portfolio project, demonstrate meaningful GitHub API integration and provide a foundation for a future commercial product.

---

# 1. YOUR ROLE AND RESPONSIBILITIES

Act as a senior software architect, senior Angular engineer, application security engineer and product-minded technical lead.

You are responsible for designing, implementing, testing, documenting and preparing DepGuard for production deployment.

Do not treat this as a tutorial or a demonstration application. Build it as a real product that could eventually be used by developers, engineering teams and organisations evaluating the health of GitHub repositories.

You must:

- Make technically sound architectural decisions.
- Prefer simple, maintainable solutions over unnecessary abstractions.
- Verify assumptions before implementing features that depend on external APIs.
- Use official API documentation as the primary source of truth.
- Identify technical limitations honestly.
- Avoid fabricated data, findings, scores and unsupported conclusions.
- Implement features completely rather than leaving placeholder functionality.
- Maintain strict TypeScript standards.
- Write meaningful automated tests.
- Document important decisions and limitations.
- Keep the application secure, responsive and accessible.
- Work incrementally and preserve a working application throughout development.

**Important execution rule:**

Do not start writing application code until Phase 0 has been completed, reviewed and explicitly approved.

Do not silently skip phases, acceptance criteria or approval gates.

After completing each phase, provide a concise but sufficiently detailed report containing:

1. What was implemented or investigated.
2. Important architectural and technical decisions.
3. Files created or modified.
4. Tests performed and their results.
5. Known limitations and outstanding issues.
6. Any decisions requiring my approval.
7. The exact next phase you recommend.

Do not ask me to make decisions that you can reasonably make using the requirements in this specification.

If you encounter a genuine architectural blocker, explain the problem, present the alternatives and recommend one.

---

# 2. PRODUCT VISION

## 2.1 What is DepGuard?

DepGuard is an independent GitHub Repository Health Analyzer.

A user enters a public GitHub repository URL. DepGuard analyses the repository and produces an understandable, evidence-backed assessment of its overall health.

The objective is to help developers answer questions such as:

- Is this repository actively maintained?
- Does it contain known vulnerable dependencies?
- Are its dependencies maintained and reasonably up to date?
- Does the project follow basic security practices?
- Does it have automated testing and CI/CD?
- Does it have adequate documentation?
- Is its licensing information available?
- Does it show signs of being abandoned?
- What are the most important risks?
- What should the repository owner improve first?

DepGuard should turn information that normally requires inspecting multiple GitHub pages and security tools into one coherent report.

It must not claim to perform a complete code security audit. It analyses observable repository signals and explicitly communicates what it cannot verify.

## 2.2 Product positioning

**DepGuard helps developers understand the health, security and maintenance quality of any public GitHub repository in one report.**

It is not intended to replace:

- GitHub Dependabot.
- GitHub CodeQL.
- Snyk.
- Socket.
- OSV-Scanner.
- Trivy.
- Dedicated static application security testing tools.

Instead, it provides a consolidated repository assessment that combines several independent signals.

## 2.3 Target users

Primary audiences:

1. **Individual developers:** Evaluate repositories before using or contributing to them.
2. **Open-source maintainers:** Understand weaknesses and improvement opportunities in their projects.
3. **Engineering teams:** Perform an initial assessment of third-party dependencies and open-source projects.
4. **Technical leads:** Quickly evaluate repository maintenance and engineering hygiene.
5. **Developers exploring open source:** Identify projects that appear active, documented and reasonably maintained.

## 2.4 Product principles

Every part of DepGuard must follow these principles:

- Evidence before conclusions.
- Transparency before impressive-looking scores.
- No fabricated information.
- Unknown does not mean failed.
- Missing configuration does not automatically mean a vulnerability.
- Repository activity is not proof of code quality.
- A healthy-looking repository is not necessarily secure.
- A repository with no detected vulnerabilities is not guaranteed to be safe.
- All scores must be explainable and reproducible.
- The application should remain useful even when some data sources are unavailable.

---

# 3. STRICT PROJECT BOUNDARIES

DepGuard must be a completely independent project.

There is an existing npm project called `universal-file-preview`.

The following restrictions are mandatory:

- Do not modify `universal-file-preview`.
- Do not import or depend on `universal-file-preview`.
- Do not copy its source code.
- Do not introduce a shared monorepo.
- Do not modify its GitHub repository.
- Do not change its package, releases, dependencies or deployment.
- Do not assume that functionality from that project is available.
- Do not make DepGuard dependent on any of its deployments.

DepGuard must have its own:

- GitHub repository.
- Angular application.
- Source code.
- Dependency tree.
- Build pipeline.
- GitHub Pages deployment.
- README.
- Documentation.
- Release history.

The intended repository is:

`dukeofwest/depguard`

The intended production URL is:

`https://dukeofwest.github.io/depguard/`

---

# 4. TECHNOLOGY STACK AND CODING STANDARDS

## 4.1 Required technology

Use:

- Angular 21.
- TypeScript with strict mode.
- Angular standalone components.
- Angular Signals for application and UI state.
- RxJS for asynchronous streams and HTTP orchestration.
- Angular HttpClient.
- Functional HTTP interceptors where appropriate.
- Native CSS, CSS Grid and Flexbox.
- CSS custom properties for design tokens.
- Angular Router only if the application genuinely needs routing.
- Jest or Angular's supported native test runner, after verifying compatibility with Angular 21.

Do not use Nx.

Do not introduce NgModules.

## 4.2 TypeScript requirements

Enable and maintain:

- `strict: true`
- `noUncheckedIndexedAccess: true`
- `noImplicitOverride: true`
- `noFallthroughCasesInSwitch: true`

Use strict typing throughout.

Never use `any`.

Prefer:

- `readonly` properties.
- Readonly interfaces where appropriate.
- Discriminated unions.
- Explicit return types for important public functions.
- Type guards for external API responses.
- Narrowed types rather than unsafe assertions.
- `as const` for stable literal configurations.

Do not solve TypeScript errors using:

- `any`.
- Broad type assertions.
- `@ts-ignore`.
- Disabling strict compiler options.
- Unnecessary non-null assertions.

If an external API response is untrusted, validate and normalize it before using it internally.

## 4.3 Angular conventions

Use:

- `inject()` for dependency injection.
- Standalone components.
- Signals for synchronous application state.
- `computed()` for derived state.
- RxJS for asynchronous workflows, HTTP requests, cancellation and polling.
- `takeUntilDestroyed()` where appropriate.
- OnPush change detection where applicable.

Avoid unnecessary use of `effect()`.

Do not use effects as a replacement for normal data flow or derived state.

Avoid:

- Unnecessary services.
- Overengineering.
- Deeply nested components.
- Excessive abstraction.
- Duplicate state.
- Unnecessary third-party libraries.
- jQuery.
- Heavy UI libraries.

Do not install Angular Material, PrimeNG, Bootstrap or similar component frameworks.

Build a lightweight, coherent design system using native Angular and CSS.

## 4.4 Pure TypeScript analysis engine

The directory:

`src/app/engine/`

must contain pure TypeScript.

It must not import:

- `@angular/*`
- Browser DOM APIs.
- `window`.
- `document`.
- Angular services.
- Components.
- Injectable dependencies.

The engine should be independently unit-testable.

It should contain deterministic logic for:

- Normalising repository data.
- Parsing SBOM data.
- Normalising dependencies.
- Processing vulnerability findings.
- Evaluating repository health checks.
- Calculating scores.
- Generating recommendations.
- Producing the final report model.

Do not introduce unnecessary abstraction simply to make the engine appear reusable.

---

# 5. PRODUCT FEATURES AND MVP SCOPE

The MVP must provide five main analysis categories.

## 5.1 Category A: Dependency Security

<priority>Core feature</priority>

Analyse known vulnerabilities in repository dependencies.

### Data sources

Primary source:

- GitHub Dependency Graph SBOM API.

Vulnerability intelligence:

- OSV.dev API.

Use the official documentation:

- GitHub REST API: https://docs.github.com/en/rest
- GitHub dependency graph: https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph
- OSV API: https://google.github.io/osv.dev/api/

Verify the current endpoints, permissions, response formats and lifecycle status before implementing anything.

### Required functionality

1. Retrieve the repository SBOM where available.
2. Parse supported SPDX JSON data.
3. Extract package names, versions, ecosystems and package URLs.
4. Normalise packages.
5. Query OSV.dev using batch requests.
6. Match vulnerabilities against dependency versions.
7. Deduplicate findings.
8. Present vulnerability severity and available metadata.
9. Identify patched versions when supplied by the vulnerability source.
10. Provide references to authoritative advisories.

### Vulnerability information

Where available, display:

- Vulnerability ID.
- CVE identifier.
- GHSA identifier.
- Summary.
- Description.
- Severity.
- CVSS score.
- Affected package.
- Installed version.
- Affected version range.
- Patched version.
- Publication date.
- Modification date.
- Advisory references.

Do not assume every OSV record contains every field.

Do not invent severity or patched versions.

If a severity is unavailable, show `Unknown`.

### Vulnerability severity

Use the following categories:

- Critical.
- High.
- Medium.
- Low.
- Unknown.

Use the source-provided severity when available.

If severity needs to be derived from CVSS, document the exact mapping and version used.

Never silently substitute your own severity assessment for the original advisory data.

### Important limitations

- OSV does not cover every vulnerability source.
- GitHub SBOM availability can vary.
- Package ecosystem mappings must be correct.
- Dependency versions may be missing or ambiguous.
- An SBOM may not represent every dependency used at runtime.

The report must disclose these limitations.

Do not label a dependency safe merely because OSV returned no matching vulnerability.

---

## 5.2 Category B: Dependency Health

Evaluate the general condition of repository dependencies.

This category should complement vulnerability detection rather than duplicate it.

### Initial checks

- Total dependencies identified.
- Ecosystem distribution.
- Direct versus transitive dependency counts, when supported by reliable SBOM relationship information.
- Packages without identifiable versions.
- Packages with incomplete metadata.
- Packages with deprecated status, only when verified using a reliable source.
- Packages with known vulnerabilities.
- Dependencies with available remediation versions.

### Ecosystems

Start with ecosystems that can be reliably identified from GitHub SBOM data and OSV package URLs.

Potential ecosystems include:

- npm.
- PyPI.
- Maven.
- Go.
- Cargo.
- NuGet.
- RubyGems.

Do not claim comprehensive ecosystem support until it has been tested.

### Outdated dependencies

Do not label packages outdated based solely on an old-looking version number.

For MVP v1.0, outdated dependency detection should only be implemented when current package registry information can be retrieved reliably.

If registry integration is outside the practical scope of the MVP, display:

`Version freshness analysis: Not available`

Do not fabricate latest versions.

Do not introduce multiple package registry integrations without a clear technical justification.

### Dependency inventory

Display a searchable and filterable table containing:

- Package name.
- Ecosystem.
- Installed version.
- Direct/transitive classification where known.
- Vulnerability count.
- Highest known severity.
- Metadata availability.

Allow users to filter by ecosystem, severity and vulnerability status.

---

## 5.3 Category C: Security Configuration

Evaluate observable repository security practices.

Inspect the repository's file tree and relevant file contents where available.

### Required checks

**1. Security policy**

Check for:

- `SECURITY.md`
- `.github/SECURITY.md`

**2. Dependabot configuration**

Check for:

- `.github/dependabot.yml`
- `.github/dependabot.yaml`

Validate the YAML structure and recognise whether it contains plausible update configuration.

File existence alone must not be presented as proof that Dependabot alerts or security updates are enabled.

**3. CodeQL workflow**

Inspect:

- `.github/workflows/`

Identify workflows that appear to configure CodeQL analysis.

Do not claim CodeQL is actively running merely because a workflow file exists.

**4. Dependency review**

Look for a GitHub Actions workflow using the dependency review action.

Distinguish a detected workflow from an enabled and successfully running security feature.

**5. CI/CD**

Identify available CI configurations, including:

- GitHub Actions workflows.
- Other detectable CI configuration files where practical.

**6. License**

Check for:

- Root `LICENSE`.
- `LICENSE.md`.
- `LICENSE.txt`.
- Other recognised license files.

Retrieve repository license metadata from GitHub where available.

**7. Documentation**

Check for:

- `README.md`.
- `CONTRIBUTING.md`.
- `CODE_OF_CONDUCT.md`.

### Status model

Every check must have one of these statuses:

- `Configured`
- `Not detected`
- `Unknown`
- `Not applicable`

Do not use binary pass/fail logic where the evidence does not justify it.

### Evidence

Every check must include:

- What was checked.
- What was found.
- The source or file path.
- A short explanation.
- Any limitations.

For example:

`Dependabot configuration: Configured`

Evidence:

`.github/dependabot.yml`

Explanation:

`A Dependabot configuration file was found. This confirms that update configuration is present, but does not prove that Dependabot alerts or security updates are enabled.`

---

## 5.4 Category D: Repository Maintenance and Activity

<priority>Key differentiating feature</priority>

Evaluate whether a repository appears actively maintained.

Use GitHub REST API data.

### Required signals

- Repository creation date.
- Last update date.
- Last push date.
- Last release date, if available.
- Number of stars.
- Number of forks.
- Open issues count.
- Repository archived status.
- Repository visibility.
- Default branch.
- Number of contributors, where reliably available.
- Recent commit activity, where available.
- Release activity, where available.

### Maintenance analysis

Evaluate:

- Time since last commit.
- Time since last release.
- Recent commit frequency.
- Whether the repository is archived.
- Whether activity appears to have stopped.
- Whether releases appear to be maintained.

Do not interpret a low number of commits as automatic evidence of poor quality.

Some projects are mature and need very few changes.

Do not treat stars or forks as a direct measure of engineering quality.

### Activity categories

Use understandable classifications:

- Recently active.
- Active.
- Limited activity.
- Potentially stale.
- Archived.
- Insufficient data.

Thresholds must be documented and configurable in one place.

Do not scatter arbitrary time thresholds throughout components and services.

For example, the distinction between recently active and potentially stale should be based on transparent thresholds rather than subjective conclusions.

### Historical activity

Use GitHub's available endpoints only where useful.

If commit history or release history cannot be retrieved, show that the analysis is incomplete.

Do not invent historical activity.

---

## 5.5 Category E: Engineering and Project Quality Signals

Evaluate observable indicators of repository completeness and engineering practices.

### Initial checks

**Documentation**

- README availability.
- Contributing guide.
- Code of conduct.
- Documentation directory, where detectable.

**Testing**

- Test directories.
- Recognisable test configuration files.
- Test-related scripts in supported manifests.
- CI workflows that appear to execute tests.

**Build and automation**

- CI configuration.
- Build workflows.
- Release workflows, where detectable.

**Project information**

- Repository description.
- Topics.
- License.
- Default branch.
- Releases.

### Important restrictions

Do not claim that a repository has good test coverage merely because a test directory exists.

Do not claim that tests pass unless an authoritative workflow result confirms this.

Do not claim code quality, maintainability or architectural quality based solely on file presence.

Use wording such as:

`Test configuration detected`

rather than:

`Tests are comprehensive`

The purpose is to provide observable engineering signals, not to pretend to perform a full code review.

---

# 6. REPOSITORY HEALTH SCORING

The scoring system is a central part of DepGuard.

It must be deterministic, explainable and transparent.

Do not create an arbitrary score simply to make the dashboard look impressive.

## 6.1 Overall score

Display a score from 0 to 100.

Suggested initial weighting:

| Category                        | Weight |
| ------------------------------- | -----: |
| Dependency security             |    35% |
| Dependency health               |    15% |
| Security configuration          |    20% |
| Maintenance and activity        |    15% |
| Engineering and project quality |    15% |
| Total                           |   100% |

These weights are starting proposals, not unquestionable facts.

During Phase 0, evaluate whether they are technically and product-wise reasonable.

Document the final decision in an architecture decision record.

## 6.2 Category scores

Each category should have its own score.

The overall score should be calculated from available, sufficiently reliable category scores.

Do not automatically treat unavailable data as zero.

Do not automatically award full marks for unavailable data.

Unknown results must be excluded from the relevant calculation and reduce the confidence or coverage indicator.

## 6.3 Coverage

Every report must include a coverage indicator.

Coverage communicates how much of the intended analysis could actually be completed.

For example:

- Dependency analysis: Available.
- Security configuration: Partially available.
- Maintenance analysis: Available.
- Engineering checks: Available.

Display both:

- Overall score.
- Analysis coverage.

A score of 92 with 45% coverage must not look equivalent to a score of 92 with 100% coverage.

## 6.4 Score interpretation

Suggested labels:

- 90–100: Excellent.
- 75–89: Good.
- 60–74: Fair.
- 40–59: Needs attention.
- 0–39: Poor.

Validate these labels against the actual scoring model.

Avoid presenting them as industry-certified security ratings.

The UI must clearly state that the score is DepGuard's heuristic assessment, not a formal security certification.

## 6.5 Scoring requirements

Every score deduction must be traceable to an underlying finding.

The scoring engine must:

- Avoid duplicate deductions.
- Use stable severity weights.
- Use capped deductions.
- Handle missing information.
- Handle empty repositories.
- Handle unavailable API data.
- Handle incomplete SBOMs.
- Handle archived repositories.
- Produce deterministic results.
- Include explanations for deductions.

A repository with no detected vulnerabilities must not automatically receive a perfect security score.

A repository with an unavailable dependency graph must not be treated as vulnerability-free.

Security configuration findings must not be presented as known vulnerabilities.

Do not penalise the same underlying problem multiple times across different categories unless there is a clear, documented reason.

## 6.6 Example score explanation

The report should be able to explain something like:

`Repository Health Score: 76/100`

- Dependency security: 82/100.
- Dependency health: 90/100.
- Security configuration: 65/100.
- Maintenance: 78/100.
- Engineering quality signals: 70/100.

Reasons:

- Two high-severity dependency advisories detected.
- Security policy file not detected.
- CodeQL workflow not detected.
- Repository has recent commit activity.
- README and license information detected.

The actual numbers must always come from the scoring engine. This example is illustrative only.

---

# 7. REPOSITORY REPORT AND REMEDIATION GUIDANCE

The final analysis should not merely display metrics.

It must help the user understand what to do next.

## 7.1 Prioritised recommendations

Generate actionable recommendations from actual findings.

Examples:

- Upgrade a vulnerable dependency to a supported patched version.
- Add a security policy.
- Configure Dependabot.
- Add automated dependency review.
- Add or improve CI workflows.
- Add missing project documentation.
- Review dependencies with incomplete version metadata.
- Investigate stale repository activity.

Recommendations must be linked to the underlying evidence.

Do not generate recommendations based on assumptions.

## 7.2 Priority levels

Use:

- Critical.
- High.
- Medium.
- Low.
- Informational.

Priority should be based on the severity and impact of the actual finding.

Do not label a missing README as critical.

Do not label a missing security policy as a confirmed vulnerability.

## 7.3 Report export

Provide a complete JSON report export.

The report should contain:

- Repository identity.
- Analysis timestamp.
- Data source information.
- Overall health score.
- Coverage information.
- Category scores.
- Dependency inventory.
- Vulnerability findings.
- Security checks.
- Maintenance signals.
- Engineering quality signals.
- Recommendations.
- Analysis limitations.

Use a versioned report schema.

The export must not contain:

- Personal access tokens.
- Sensitive authentication data.
- Internal application secrets.
- Unnecessary personal information.

A polished downloadable PDF report may be considered for a later release, but is not a requirement for MVP v1.0.

---

# 8. DATA SOURCES AND API INTEGRATION

## 8.1 GitHub REST API

Use GitHub REST API as the primary source for repository information.

Official documentation:

https://docs.github.com/en/rest

Potential endpoints include:

- Repository metadata.
- Repository contents.
- Repository tree.
- Repository languages.
- Contributors.
- Commits.
- Releases.
- Workflow files.
- Dependency graph SBOM.

Verify every endpoint before implementation.

Do not assume every endpoint is available for every public repository.

Handle:

- HTTP 404.
- HTTP 403.
- HTTP 422.
- HTTP 429 where applicable.
- Rate-limit exhaustion.
- Missing permissions.
- Archived repositories.
- Inaccessible resources.
- Incomplete responses.
- Network errors.

## 8.2 GitHub SBOM

The GitHub Dependency Graph SBOM workflow must be investigated in Phase 0.

Verify the currently supported asynchronous generation and retrieval workflow using official documentation.

Investigate:

- Whether public repositories can be analysed anonymously.
- Whether the required API endpoints work without authentication.
- Whether the SBOM is returned successfully.
- How generation and retrieval statuses work.
- How asynchronous processing is handled.
- How temporary download redirects behave.
- Whether browser CORS restrictions prevent retrieval.
- Whether the response is SPDX JSON.
- Whether the SBOM can be downloaded directly by an Angular application deployed on GitHub Pages.

Do not rely on old synchronous endpoint behaviour.

Do not invent endpoint response structures.

The exact API workflow must be demonstrated with real requests against multiple public repositories.

If the direct-browser workflow does not work reliably, investigate a minimal serverless proxy.

Potential future hosting:

- Cloudflare Workers.
- Another suitable low-cost serverless platform.

Do not implement the proxy without first presenting the alternatives and their costs.

## 8.3 OSV.dev

Use:

`https://api.osv.dev/v1/querybatch`

Verify the current API schema.

Implement:

- Correct ecosystem mapping.
- Correct package identification.
- Batch request chunking.
- Request cancellation.
- Bounded concurrency.
- Error handling.
- Deduplication.
- Response validation.

Use:

`GET /v1/vulns/{id}`

only when additional vulnerability details are genuinely needed.

Do not retrieve vulnerability details individually without a reason.

Avoid unnecessary requests.

## 8.4 API rate limits and caching

Unauthenticated GitHub REST API access is limited.

Implement:

- Rate-limit header tracking.
- Remaining request display.
- Reset time handling.
- Sensible in-memory caching.
- Request deduplication.
- Retry with bounded exponential backoff where appropriate.
- Clear rate-limit error messages.

Do not retry indefinitely.

Do not retry requests that cannot reasonably succeed without user action.

Do not store sensitive data.

Cache only what is useful for the current application session.

---

# 9. AUTHENTICATION AND PRIVACY

## 9.1 MVP authentication

Do not implement GitHub OAuth or Personal Access Token input in MVP v1.0.

The initial product should analyse public repositories anonymously.

This keeps the first release simpler and avoids asking users to provide credentials to a new application.

## 9.2 Privacy

The application must clearly communicate:

- Which repository information it retrieves.
- Which external APIs it contacts.
- Whether data is stored.
- Whether analysis is performed in the browser.
- Whether any third-party service receives repository information.

Do not silently upload repository data.

Do not execute repository code.

Do not automatically download arbitrary files or follow arbitrary URLs discovered in repository content.

Use only controlled, expected GitHub and OSV API destinations.

Do not use repository-provided HTML as trusted content.

Treat all API responses as untrusted input.

---

# 10. APPLICATION ARCHITECTURE

Keep the architecture simple and modular.

Suggested structure:

```text
src/
  app/
    core/
      models/
        repository.model.ts
        dependency.model.ts
        vulnerability.model.ts
        security-check.model.ts
        health-report.model.ts
        recommendation.model.ts
        api-error.model.ts

      api/
        github-api.service.ts
        osv-api.service.ts

      services/
        repository-analysis.service.ts
        report-export.service.ts
        cache.service.ts
        rate-limit.service.ts

      state/
        scan.store.ts

    engine/
      sbom/
        spdx-parser.ts

      dependencies/
        dependency-normalizer.ts
        purl-normalizer.ts

      security/
        vulnerability-processor.ts
        security-checks.ts

      health/
        maintenance-analyzer.ts
        engineering-analyzer.ts
        dependency-health-analyzer.ts

      scoring/
        category-scorer.ts
        overall-scorer.ts

      recommendations/
        recommendation-engine.ts

      report/
        report-builder.ts

    features/
      landing/
        landing.component.ts

      dashboard/
        dashboard.component.ts

      components/
        health-score/
        category-score/
        vulnerability-list/
        dependency-table/
        security-check-list/
        maintenance-summary/
        recommendations/
        analysis-progress/

    shared/
      components/
      pipes/
      utils/

    app.config.ts
    app.routes.ts
    app.component.ts

  assets/
  styles/
```

This is a proposed structure.

Adjust it when there is a clear technical reason, but do not create unnecessary directories or abstractions.

## 10.1 GitHub API service

Responsible for:

- Repository metadata.
- File and directory inspection.
- Commit and release information.
- Contributor information where available.
- SBOM generation and retrieval.
- API rate-limit information.

Keep API-specific response models separate from application domain models.

## 10.2 OSV API service

Responsible for:

- Batch vulnerability queries.
- Request chunking.
- Response validation.
- Vulnerability detail retrieval when necessary.
- Request cancellation.
- Bounded concurrency.

## 10.3 Analysis engine

Responsible for deterministic processing.

No HTTP requests.

No Angular dependencies.

No DOM access.

No direct dependency on UI components.

## 10.4 Scan store

Use Angular Signals for application state.

Use RxJS for asynchronous operations.

Support:

- Starting analysis.
- Progress updates.
- Cancellation.
- Error handling.
- Resetting previous results.
- Preventing stale responses.
- Exposing computed report state.

Use a clearly defined state machine.

Suggested states:

```text
idle
validatingRepository
fetchingRepository
fetchingRepositoryFiles
generatingSbom
waitingForSbom
retrievingSbom
analysingDependencies
checkingVulnerabilities
checkingSecurityConfiguration
analysingMaintenance
analysingEngineeringSignals
calculatingHealthScore
buildingReport
completed
failed
cancelled
```

Do not show artificial progress percentages.

Progress should reflect actual completed work.

Ensure that starting a new scan cancels or invalidates the previous scan so stale results cannot overwrite current results.

## 10.5 Error handling

Use typed application errors.

Distinguish:

- Invalid repository URL.
- Unsupported repository URL.
- Repository not found.
- Repository inaccessible.
- GitHub API rate limit.
- GitHub API unavailable.
- SBOM unavailable.
- SBOM generation failure.
- Unsupported SBOM format.
- OSV API unavailable.
- Partial analysis.
- Internal processing error.

Never display raw stack traces to users.

Keep useful diagnostic information available during development.

---

# 11. USER EXPERIENCE AND DESIGN REQUIREMENTS

The application must look and feel like a polished developer SaaS product.

Do not create a generic Angular starter page.

Do not use default browser-looking forms and tables.

Do not overdecorate the interface.

## 11.1 Visual direction

Use a modern cybersecurity and developer-tool aesthetic.

Suggested direction:

- Dark navy background.
- Slightly lighter card surfaces.
- Subtle blue accent colour.
- Restrained severity colours.
- Clear typography.
- Good spacing.
- Thin borders.
- Consistent corner radii.
- Subtle shadows.
- Responsive layouts.

Suggested palette:

```css
:root {
  --color-background: #0b1120;
  --color-surface: #111b2e;
  --color-surface-raised: #17243a;
  --color-border: #26354d;
  --color-text-primary: #f1f5f9;
  --color-text-secondary: #94a3b8;
  --color-accent: #3b82f6;
  --color-success: #22c55e;
  --color-warning: #f59e0b;
  --color-danger: #ef4444;
}
```

These are initial suggestions, not mandatory final colours.

Use design tokens instead of scattering colours throughout components.

## 11.2 Landing page

The landing page should immediately communicate the product's purpose.

Include:

- DepGuard logo/wordmark.
- Short headline.
- Clear product explanation.
- GitHub repository URL input.
- Analyse button.
- Short privacy statement.
- Example analysis or example report.
- Explanation of the five analysis categories.
- Link to GitHub repository.
- Footer with documentation and limitations.

Example headline:

**Know the health of any GitHub repository.**

Supporting text:

`Analyse dependencies, security practices, maintenance activity and engineering signals in one clear report.`

Example input:

`https://github.com/owner/repository`

Validate the URL before making API requests.

Only accept supported GitHub repository URLs.

Do not allow arbitrary external URLs.

## 11.3 Analysis progress

Display meaningful stages.

Example:

1. Validating repository.
2. Retrieving repository information.
3. Inspecting project files.
4. Generating dependency inventory.
5. Checking known vulnerabilities.
6. Evaluating security configuration.
7. Analysing maintenance activity.
8. Calculating repository health.

Provide useful messages if one category cannot be completed.

Do not show an endless loading spinner.

## 11.4 Dashboard

The dashboard is the most important UI.

It should contain:

**A. Repository header**

- Repository owner/name.
- Description.
- GitHub link.
- Stars.
- Forks.
- Default branch.
- Last pushed date.
- Archived status.
- Analysis timestamp.

**B. Overall health score**

- Large score.
- Health classification.
- Coverage indicator.
- Short explanation.

**C. Category overview**

Display five category cards:

- Dependency Security.
- Dependency Health.
- Security Configuration.
- Maintenance and Activity.
- Engineering and Project Quality.

Each card should show:

- Score, if available.
- Status.
- Important findings.
- Coverage.

**D. Critical findings**

Highlight the most important issues.

**E. Prioritised recommendations**

Show the highest-priority improvements first.

**F. Detailed analysis**

Use clearly separated sections or tabs:

- Overview.
- Dependencies.
- Vulnerabilities.
- Security.
- Maintenance.
- Engineering.

**G. Export**

Provide JSON report export.

## 11.5 Responsive design

Support:

- Desktop.
- Laptop.
- Tablet.
- Mobile.

The dependency table must remain usable on smaller screens.

Do not simply shrink desktop content.

Use appropriate responsive layouts and mobile-friendly navigation.

## 11.6 Accessibility

Implement:

- Semantic HTML.
- Keyboard navigation.
- Visible focus states.
- Accessible form labels.
- Appropriate colour contrast.
- Meaningful status labels.
- Screen-reader-friendly score and severity information.
- Reduced-motion support.

Do not rely on colour alone to communicate severity.

---

# 12. PERFORMANCE AND RELIABILITY

The application must remain responsive when analysing larger repositories.

Implement sensible safeguards:

- Maximum supported SBOM response size.
- Maximum number of packages processed in one batch.
- OSV request chunking.
- Bounded concurrency.
- Request timeouts.
- Cancellation support.
- Memory-conscious parsing.
- Duplicate request prevention.
- Bounded polling for asynchronous GitHub operations.

Do not assume repository size is small.

Do not create an unbounded number of HTTP requests.

Do not block the UI while processing a large SBOM.

Investigate whether a Web Worker is genuinely necessary. If parsing large SBOMs noticeably blocks the UI, propose a worker implementation with clear boundaries and measurable benefits.

Do not introduce worker infrastructure just for architectural decoration.

---

# 13. TESTING STRATEGY

Testing is mandatory throughout development.

Do not postpone all tests until the end.

## 13.1 Unit tests

Test the pure analysis engine extensively.

Required areas:

- SPDX parsing.
- Invalid SBOM handling.
- Missing package metadata.
- PURL normalisation.
- Ecosystem identification.
- Vulnerability matching.
- Vulnerability deduplication.
- Security configuration checks.
- Maintenance analysis.
- Engineering signal detection.
- Category scoring.
- Overall scoring.
- Coverage calculation.
- Recommendation generation.
- Report generation.

## 13.2 API tests

Test:

- Successful GitHub requests.
- Missing repositories.
- Rate-limit responses.
- Missing SBOM.
- Asynchronous SBOM generation.
- SBOM polling.
- Redirect and retrieval behaviour.
- OSV batch requests.
- Partial OSV responses.
- Network errors.
- Request cancellation.
- Timeout behaviour.

## 13.3 Component tests

Test:

- Landing page validation.
- Loading states.
- Error states.
- Dashboard rendering.
- Empty states.
- Unknown states.
- Partial analysis.
- Dependency filtering.
- Vulnerability filtering.
- JSON export.

## 13.4 Integration tests

Test a complete analysis workflow using controlled fixtures.

Do not hardcode fake API responses in production services.

Fixtures are acceptable in test code.

## 13.5 Real repository validation

Use several real public repositories during development.

Include repositories representing different scenarios:

1. A large, active repository.
2. A small, active repository.
3. A repository with known vulnerable dependencies.
4. A repository with incomplete security configuration.
5. An archived repository.
6. A repository without an available dependency graph.
7. A repository with limited or missing metadata.

Record what was actually observed.

Do not invent expected vulnerability findings.

For vulnerability test fixtures, use known OSV advisory records and verify that the package/version matching behaves correctly.

---

# 14. SECURITY REQUIREMENTS

Security must be considered throughout the project.

Mandatory requirements:

- No credentials in the MVP.
- No arbitrary URL fetching.
- No execution of repository content.
- No execution of package scripts.
- No use of `eval`.
- No unsafe HTML injection.
- No bypassing Angular sanitisation.
- No unnecessary local storage.
- No secret data in logs.
- No credentials in exported reports.
- Validate all external API responses.
- Validate repository URL input.
- Enforce response size limits.
- Handle malformed JSON.
- Handle malicious package names and metadata.
- Avoid unsafe rendering of repository content.
- Avoid following untrusted external links automatically.

Treat repository metadata, package names, vulnerability descriptions and file contents as untrusted input.

Ensure that the application cannot accidentally expose sensitive browser information through rendering or export functionality.

---

# 15. GITHUB DEVELOPER PROGRAM AND PORTFOLIO OBJECTIVES

DepGuard should demonstrate meaningful use of GitHub's developer platform.

The GitHub integration must be genuine and central to the product.

Do not create superficial API calls solely to claim GitHub API integration.

Use GitHub data to provide useful repository analysis.

Document:

- GitHub API endpoints used.
- Why each endpoint is needed.
- API permissions and authentication requirements.
- Rate-limit handling.
- Error handling.
- Caching.
- API limitations.
- Data sources.
- Privacy behaviour.

The README must clearly explain how DepGuard uses GitHub APIs.

Do not claim that building this project guarantees GitHub Developer Program acceptance.

The project should be sufficiently polished to demonstrate:

- Real API integration.
- Good engineering practices.
- Clear documentation.
- Meaningful developer value.
- Responsible API usage.
- A usable product.

---

# 16. FUTURE COMMERCIAL DIRECTION

The MVP should be designed so that future commercial functionality can be introduced without rewriting the entire application.

However, do not implement monetisation in v1.0.

Potential future features:

- GitHub App authentication.
- Private repository analysis.
- Multiple repository monitoring.
- Scheduled health scans.
- Historical score tracking.
- Shareable reports.
- Team dashboards.
- Organisation-level analysis.
- Email notifications.
- Dependency update monitoring.
- PDF exports.
- API access.
- Paid usage tiers.

Do not build these features now.

Do not introduce payment processing, billing, user accounts, databases or backend infrastructure in the initial release unless Phase 0 demonstrates that a specific requirement cannot reasonably be met otherwise.

The MVP must remain focused.

---

# 17. IMPLEMENTATION PHASES

Follow the phases below in order.

Each phase has explicit deliverables and acceptance criteria.

Do not move forward automatically when an approval gate is required.

---

## PHASE 0: TECHNICAL FEASIBILITY AND PRODUCT VALIDATION

**Status:** Mandatory. No application code.

This phase determines whether the proposed product can actually be delivered with the selected architecture.

Do not create the Angular application yet.

### 0.1 Verify GitHub API feasibility

Investigate the official GitHub REST API.

Confirm:

- Repository metadata access.
- Repository tree and contents access.
- Commit information.
- Release information.
- Contributor information.
- Repository language information.
- SBOM generation and retrieval.
- Anonymous access for public repositories.
- Current API rate limits.
- Relevant API permissions.
- Response formats.
- Endpoint limitations.

Use official documentation.

### 0.2 Prove SBOM retrieval

This is a critical technical requirement.

Perform real requests against multiple public repositories.

Demonstrate the complete asynchronous SBOM workflow.

Investigate browser CORS behaviour, especially any temporary download redirects.

Confirm whether Angular running on GitHub Pages can retrieve and process the SBOM without a backend.

Document:

- Exact endpoints.
- Request methods.
- Relevant headers.
- Actual response status codes.
- Polling behaviour.
- Redirect behaviour.
- CORS results.
- SBOM format.
- Failure cases.

Do not simply assume that a successful API response means the browser can download the SBOM.

### 0.3 Verify OSV integration

Test:

- Batch query format.
- Supported ecosystems.
- Package URL handling.
- Version matching.
- Vulnerability metadata.
- Missing severity information.
- Large batch handling.
- Rate limits or practical request constraints.

Use real test requests.

### 0.4 Validate repository health signals

Identify which health signals can be retrieved reliably from public GitHub APIs.

Create a matrix:

| Signal              | Data source | Available anonymously? | Reliability     | MVP    |
| ------------------- | ----------- | ---------------------- | --------------- | ------ |
| Repository metadata | GitHub REST | Verify                 | High/Medium/Low | Yes/No |
| SBOM                | GitHub REST | Verify                 | High/Medium/Low | Yes/No |
| Vulnerabilities     | OSV         | Verify                 | High/Medium/Low | Yes/No |
| Security files      | GitHub REST | Verify                 | High/Medium/Low | Yes/No |
| Recent commits      | GitHub REST | Verify                 | High/Medium/Low | Yes/No |
| Releases            | GitHub REST | Verify                 | High/Medium/Low | Yes/No |
| Contributors        | GitHub REST | Verify                 | High/Medium/Low | Yes/No |
| Test configuration  | GitHub REST | Verify                 | High/Medium/Low | Yes/No |
| License             | GitHub REST | Verify                 | High/Medium/Low | Yes/No |

Do not classify a signal as reliable without evidence.

### 0.5 Validate architecture

Recommend the simplest architecture that supports the MVP.

Specifically investigate:

- Whether browser-only analysis is practical.
- Whether SBOM parsing needs a Web Worker.
- Whether a serverless proxy is necessary.
- Whether native browser APIs are sufficient.
- Whether any third-party npm package is genuinely needed.
- Whether the report can be generated entirely in memory.

Do not introduce a backend by default.

### 0.6 Define scoring

Propose:

- Category weights.
- Category calculation rules.
- Coverage calculation.
- Unknown handling.
- Missing data handling.
- Deduplication rules.
- Score interpretation.
- Confidence limitations.

Include worked examples.

### 0.7 Define the MVP

Identify exactly which features can be delivered reliably.

Separate:

- MVP requirements.
- Deferred features.
- Unsupported features.
- Features requiring a backend.
- Features requiring authentication.

### Phase 0 deliverables

Create a technical feasibility report containing:

1. Product feasibility assessment.
2. GitHub API endpoint matrix.
3. SBOM proof-of-concept results.
4. Browser CORS findings.
5. OSV proof-of-concept results.
6. Repository health signal matrix.
7. Recommended architecture.
8. Proposed data models.
9. Scoring model.
10. API rate-limit strategy.
11. Security considerations.
12. Estimated technical risks.
13. Final MVP scope.
14. Implementation plan for subsequent phases.

Also create an initial architecture decision record for important decisions.

**Acceptance criteria:**

- GitHub API feasibility has been demonstrated.
- SBOM retrieval has been tested rather than assumed.
- OSV integration has been tested.
- CORS limitations are documented.
- Every MVP metric has a real data source.
- Scoring rules are defined.
- The implementation architecture is justified.

**Approval gate:**

Stop and present the report.

Do not create application code until I explicitly approve Phase 0.

---

## PHASE 1: PROJECT INITIALISATION AND FOUNDATION

Start only after Phase 0 approval.

### Tasks

1. Create the standalone Angular 21 application.
2. Configure TypeScript strict options.
3. Configure linting and formatting.
4. Configure the chosen test runner.
5. Configure application routing if required.
6. Establish the directory structure.
7. Set up environment-independent API configuration.
8. Create core domain models.
9. Create the initial design tokens.
10. Create the global application layout.
11. Create the GitHub Pages deployment workflow.
12. Add basic project documentation.

### Requirements

- No Nx.
- No NgModules.
- No unnecessary libraries.
- No mock production API services.
- No unrelated features.
- No references to external projects.

### Acceptance criteria

- Application builds successfully.
- Tests run successfully.
- Strict TypeScript compilation passes.
- Linting passes.
- GitHub Pages base path is handled correctly.
- Application works locally.
- Deployment workflow is ready.

Do not implement the analysis engine yet.

---

## PHASE 2: GITHUB DATA INTEGRATION

Implement the GitHub API integration.

### Tasks

1. Validate GitHub repository URLs.
2. Parse owner and repository names.
3. Retrieve repository metadata.
4. Retrieve supported repository file information.
5. Retrieve commit and release information.
6. Retrieve contributor information where supported.
7. Retrieve repository language information.
8. Retrieve security configuration files.
9. Implement SBOM generation.
10. Implement asynchronous SBOM polling.
11. Retrieve and validate the resulting SBOM.
12. Implement rate-limit tracking.
13. Implement request caching.
14. Implement cancellation.
15. Implement typed API errors.

### Requirements

- Use the exact endpoints verified in Phase 0.
- Do not duplicate API requests unnecessarily.
- Do not poll indefinitely.
- Do not retry forever.
- Handle partial API availability.
- Validate all external responses.
- Do not expose raw API errors to the UI.

### Acceptance criteria

- Real public repositories can be analysed at the data-retrieval level.
- Repository metadata is correctly mapped.
- SBOM retrieval works for supported repositories.
- Unsupported repositories produce useful explanations.
- Rate limits are handled correctly.
- Cancellation works.
- Tests cover success and failure paths.

---

## PHASE 3: PURE TYPESCRIPT ANALYSIS ENGINE

Implement the analysis engine.

Keep it independent of Angular.

### Tasks

Implement the following modules:

**SBOM**

- SPDX parser.
- Package extraction.
- Metadata normalisation.
- Malformed SBOM handling.

**Dependencies**

- Package URL normalisation.
- Ecosystem identification.
- Version handling.
- Direct/transitive classification where supported.
- Duplicate handling.

**Security**

- OSV vulnerability matching.
- Vulnerability normalisation.
- Severity extraction.
- Advisory deduplication.
- Security configuration evaluation.

**Maintenance**

- Last commit analysis.
- Release recency analysis.
- Archived status.
- Activity classification.
- Contributor signals where available.

**Engineering**

- Documentation checks.
- Test configuration detection.
- CI/CD detection.
- License checks.
- Project completeness signals.

**Scoring**

- Category scores.
- Coverage calculation.
- Overall score.
- Score explanations.
- Unknown handling.

**Recommendations**

- Evidence-based recommendations.
- Priority classification.
- Recommendation deduplication.

**Report**

- Final report construction.
- Schema versioning.
- Stable report structure.

### Acceptance criteria

- Engine has zero Angular imports.
- Engine has zero DOM dependencies.
- Unit tests cover normal and malformed input.
- Identical input produces identical results.
- Unknown data is handled correctly.
- Scores are explainable.
- No recommendations are generated without evidence.
- No duplicate deductions occur.

---

## PHASE 4: OSV VULNERABILITY INTELLIGENCE

Complete the dependency security workflow.

### Tasks

1. Connect the OSV client to the analysis workflow.
2. Convert supported dependencies into valid OSV queries.
3. Implement batching.
4. Implement chunking.
5. Implement bounded concurrency if required.
6. Normalise vulnerability responses.
7. Match affected version ranges correctly.
8. Deduplicate advisories.
9. Retrieve additional advisory information only when required.
10. Generate actionable remediation guidance.

### Acceptance criteria

- Known test vulnerabilities are detected correctly.
- Unaffected versions are not incorrectly flagged.
- Missing severity is represented accurately.
- Duplicate vulnerabilities are not counted repeatedly.
- Large dependency inventories are handled safely.
- OSV failures do not crash the entire report.
- Partial vulnerability analysis is clearly identified.

---

## PHASE 5: FRONTEND AND DASHBOARD

Build the complete user experience.

### Tasks

**Landing page**

- Branding.
- Product explanation.
- GitHub repository input.
- Validation.
- Analyse action.
- Privacy information.

**Analysis experience**

- Real progress stages.
- Cancellation.
- Loading states.
- Error states.
- Partial analysis handling.

**Dashboard**

- Repository overview.
- Overall health score.
- Coverage.
- Five category summaries.
- Critical findings.
- Recommendations.
- Detailed analysis sections.

**Dependency interface**

- Search.
- Ecosystem filter.
- Severity filter.
- Vulnerability status.
- Dependency details.

**Security interface**

- Configuration checks.
- Evidence.
- File paths.
- Explanations.

**Maintenance interface**

- Recent activity.
- Last push.
- Release information.
- Archived status.
- Activity classification.

**Engineering interface**

- Documentation.
- Testing signals.
- CI/CD signals.
- License information.

**Export**

- JSON report export.
- Versioned report format.

### Acceptance criteria

- Complete workflow from landing page to report.
- No placeholder data in production.
- No artificial progress.
- All dashboard values come from the actual report.
- Partial results are handled correctly.
- Responsive layout works.
- Accessibility requirements are met.
- Errors are understandable.
- JSON export is valid and complete.

---

## PHASE 6: QUALITY, SECURITY AND PERFORMANCE HARDENING

Perform a comprehensive quality review.

### 6.1 Code quality

- Run strict TypeScript compilation.
- Run linting.
- Run formatting checks.
- Run unit tests.
- Run integration tests.
- Remove dead code.
- Remove unnecessary dependencies.
- Review architecture.
- Check for duplicated logic.

### 6.2 Security review

Review:

- External API response handling.
- Repository URL validation.
- Untrusted metadata rendering.
- XSS risks.
- Unsafe HTML.
- Secret exposure.
- Exported data.
- Arbitrary network requests.
- Denial-of-service risks.
- Excessive parsing.
- Memory usage.
- Request concurrency.

### 6.3 Performance review

Test:

- Small repositories.
- Large repositories.
- Large SBOMs.
- Large dependency inventories.
- Slow API responses.
- API rate-limit exhaustion.
- Partial failures.

Identify unnecessary API calls and expensive calculations.

### 6.4 User experience review

Test:

- Empty states.
- Error states.
- Missing metadata.
- Unsupported SBOM.
- No detected vulnerabilities.
- Repositories with many vulnerabilities.
- Archived repositories.
- Mobile layout.
- Keyboard navigation.

### Acceptance criteria

- No known critical or high-severity application security issues remain unresolved.
- All tests pass.
- Strict TypeScript compilation passes.
- No unhandled promise rejections.
- No stale scan results.
- No infinite polling.
- No unbounded requests.
- Application remains usable with partial data.
- Important limitations are visible to users.

Document any remaining security or reliability risks rather than hiding them.

---

## PHASE 7: DOCUMENTATION AND PRODUCTION READINESS

Prepare DepGuard for public release.

### README

Create a professional README containing:

1. Product introduction.
2. Problem being solved.
3. Key features.
4. Screenshots.
5. Live demo link.
6. Technology stack.
7. Architecture overview.
8. Data sources.
9. GitHub API integration.
10. OSV integration.
11. Scoring methodology.
12. Coverage and limitations.
13. Privacy statement.
14. Local development instructions.
15. Testing instructions.
16. Build instructions.
17. Deployment instructions.
18. Roadmap.
19. License.

Do not claim features that are not implemented.

### Additional documentation

Create:

- `docs/ARCHITECTURE.md`
- `docs/SCORING.md`
- `docs/DATA-SOURCES.md`
- `docs/PRIVACY.md`
- `docs/SECURITY.md`
- `docs/API-LIMITATIONS.md`
- `docs/ROADMAP.md`

Create architecture decision records for important decisions.

### GitHub repository configuration

Prepare:

- Repository description.
- Topics.
- README badges where appropriate.
- GitHub Actions CI.
- GitHub Pages deployment.
- Issue templates if useful.
- Contribution guidance.
- Security policy.
- License.

Do not claim that security scanning or CI is enabled unless it has actually been configured and verified.

### Deployment

Deploy to:

`https://dukeofwest.github.io/depguard/`

Verify:

- Production build.
- Correct base href.
- Static asset loading.
- Routing behaviour.
- Browser console.
- Real repository analysis.
- Mobile rendering.
- JSON export.

### Acceptance criteria

- Production build succeeds.
- GitHub Pages deployment succeeds.
- Live URL works.
- README is complete.
- Documentation matches implementation.
- No broken links.
- No development placeholders.
- No mock production data.
- No exposed credentials.

---

## PHASE 8: FINAL MVP VALIDATION AND RELEASE

This is the final release gate.

Perform an end-to-end assessment.

### Validate with real repositories

Use the repository scenarios defined in Phase 0.

For each one, record:

- Repository URL.
- API retrieval success.
- SBOM availability.
- Dependency count.
- Vulnerability query outcome.
- Security configuration results.
- Maintenance results.
- Engineering signals.
- Coverage.
- Overall score.
- Known limitations.

Do not alter scoring simply to make results look more attractive.

### Final product review

Evaluate:

- Does DepGuard solve a real problem?
- Is the value clear within the first few seconds?
- Can a new user analyse a repository without instructions?
- Are findings trustworthy?
- Are scores explainable?
- Are unknowns handled correctly?
- Is the dashboard understandable?
- Is the application fast enough?
- Is the product genuinely useful compared with existing tools?

### Release preparation

Prepare:

- Version `1.0.0`.
- Release notes.
- Final README.
- Final screenshots.
- Production URL.
- Known limitations.
- Future roadmap.

Do not publish a release or push changes to the repository without explicit authorisation.

---

# 18. MVP ACCEPTANCE CRITERIA

The MVP is considered complete only when all of the following are satisfied.

## Product

- [ ] User can enter a public GitHub repository URL.
- [ ] Repository validation works.
- [ ] Repository metadata is retrieved.
- [ ] Dependency inventory is generated where SBOM data is available.
- [ ] Vulnerability analysis works through OSV.
- [ ] Security configuration checks work.
- [ ] Maintenance analysis works.
- [ ] Engineering signal checks work.
- [ ] Overall health score is calculated.
- [ ] Category scores are calculated.
- [ ] Coverage is displayed.
- [ ] Findings have supporting evidence.
- [ ] Recommendations are actionable.
- [ ] JSON report export works.

## Technical

- [ ] Angular 21.
- [ ] Standalone components.
- [ ] No Nx.
- [ ] Strict TypeScript.
- [ ] Zero `any` types.
- [ ] Pure TypeScript analysis engine.
- [ ] No unnecessary dependencies.
- [ ] Tests pass.
- [ ] Linting passes.
- [ ] Production build succeeds.

## Security and reliability

- [ ] No authentication credentials in MVP.
- [ ] External responses are validated.
- [ ] No unsafe HTML rendering.
- [ ] No arbitrary URL fetching.
- [ ] Request cancellation works.
- [ ] API limits are handled.
- [ ] Partial results are supported.
- [ ] Unknown data is not treated as a failure.
- [ ] No fabricated scores or findings.

## User experience

- [ ] Landing page is polished.
- [ ] Dashboard is polished.
- [ ] Responsive design works.
- [ ] Loading and error states are implemented.
- [ ] Accessibility requirements are addressed.
- [ ] Privacy information is available.

## Deployment and documentation

- [ ] GitHub Pages deployment works.
- [ ] Production URL works.
- [ ] README is complete.
- [ ] Architecture is documented.
- [ ] Scoring methodology is documented.
- [ ] Data sources are documented.
- [ ] Limitations are documented.

---

# 19. IMPORTANT DEVELOPMENT RULES

These rules apply to every phase.

### Rule 1: Do not overengineer

Choose the simplest implementation that satisfies the requirements.

Do not create interfaces, adapters, factories or abstract classes unless they solve an actual problem.

### Rule 2: Do not invent functionality

If an API does not provide a piece of information, report that it is unavailable.

Do not approximate missing data and present it as fact.

### Rule 3: Do not silently change scope

If a feature is not feasible, explain why and recommend an alternative.

Do not quietly remove requirements.

### Rule 4: Keep the application working

After each implementation phase:

- Build.
- Test.
- Lint.
- Fix regressions.

Do not accumulate unresolved errors.

### Rule 5: Keep code straightforward

Prefer readable, maintainable code over clever abstractions.

Avoid unnecessary services and excessive indirection.

### Rule 6: Verify third-party dependencies

Before installing a new npm package:

1. Explain what it is needed for.
2. Check whether native Angular or browser functionality is sufficient.
3. Evaluate maintenance and security.
4. Add it only when justified.

### Rule 7: Document decisions

Important architectural decisions must be recorded.

Do not repeatedly revisit already approved decisions without new evidence.

### Rule 8: Do not fake completion

A phase is not complete because files have been created.

It is complete when its acceptance criteria have been tested.

### Rule 9: Preserve the project boundary

Never modify, depend on or interact with `universal-file-preview`.

### Rule 10: Stop at approval gates

Phase 0 must be approved before implementation.

For subsequent phases, report results and wait for approval when a decision or scope change is needed. Otherwise, proceed according to the approved plan.

---

# 20. FIRST TASK: START PHASE 0

Your first task is to begin Phase 0 only.

Do not initialise Angular.

Do not create application source files.

Do not install npm dependencies.

Do not start implementing the dashboard.

Instead, investigate the feasibility of the complete DepGuard Repository Health Analyzer.

Prioritise the following questions:

1. Can an unauthenticated browser application retrieve GitHub repository metadata reliably?
2. Can it retrieve the new asynchronous GitHub SBOM workflow?
3. Does the temporary SBOM download workflow work from a browser hosted on GitHub Pages?
4. Can OSV.dev be queried directly from the browser?
5. Which repository health signals can be retrieved reliably without authentication?
6. What are the practical GitHub API rate-limit constraints?
7. Which checks can be implemented accurately without executing repository code?
8. What is the simplest architecture that can deliver the MVP?
9. What scoring model is defensible and transparent?
10. What must be deferred to avoid turning the MVP into an unnecessarily large project?

Use real API requests, official documentation and reproducible evidence wherever possible.

Your final Phase 0 report must contain enough technical detail for me to approve the architecture and implementation plan without having to investigate the APIs myself.

**Do not write application code until I explicitly approve the Phase 0 report.**

The objective is not to build the largest possible repository scanner. The objective is to build a polished, reliable and differentiated GitHub Repository Health Analyzer that developers will actually find useful.
