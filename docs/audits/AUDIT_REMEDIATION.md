# DepGuard: Audit Remediation and Repository Health Improvements

## Implementation Specification for AI Agent

**Project:** DepGuard  
**Repository:** `https://github.com/dukeofwest/depguard`  
**Deployment:** `https://dukeofwest.github.io/depguard/`  
**Audit baseline:** `main` at commit `d7e6336`  
**Audit date:** 14 November 2026  
**Scope:** Remediation of the findings in the 14 November 2026 technical audit  
**Implementation approach:** Six controlled phases, with correctness and evidence quality taking priority over feature expansion.

---

# 1. Your role and primary objective

Act as a senior TypeScript and Angular engineer with strong experience in application security, dependency analysis, software supply-chain security, GitHub APIs, vulnerability databases, and automated testing.

Your task is to implement the findings from the DepGuard technical audit.

This is a targeted remediation project. It is **not** an opportunity to redesign DepGuard, replace its architecture, introduce a new framework, or perform broad refactoring.

Your primary objective is to make DepGuard's analysis more accurate, transparent, complete, and resistant to misleading results.

The implementation must address six phases:

1. **Phase A:** Fix confirmed OSV vulnerability loss.
2. **Phase B:** Correct scoring, coverage, and uncertainty handling.
3. **Phase C:** Improve npm dependency discovery and source-state reporting.
4. **Phase D:** Introduce careful .NET/NuGet dependency discovery.
5. **Phase E:** Correct repository security and engineering checks.
6. **Phase F:** Address remaining reporting, documentation, and consistency findings.

Implement these phases in order. Do not skip a phase because another change appears more interesting or easier.

The audit is the authoritative source for the problems to solve. Do not silently replace its findings with assumptions or introduce unsupported claims.

---

# 2. Existing project architecture and constraints

## 2.1 Preserve the existing architecture

Before changing anything, inspect the repository and understand its current architecture.

DepGuard currently uses:

- Angular 21.
- Standalone Angular components.
- Strict TypeScript.
- Angular Signals and RxJS.
- Angular `HttpClient`.
- A pure TypeScript analysis engine.
- GitHub REST API integration.
- OSV.dev integration.
- GitHub Pages deployment.
- Browser-side repository analysis without a conventional application backend.

The existing architectural separation is intentional.

Preserve the following boundaries:

### Core and analysis engine

The engine should remain deterministic and independent of browser or Angular infrastructure.

It must not directly perform:

- HTTP requests.
- DOM operations.
- Browser storage operations.
- Random number generation.
- Clock-dependent operations.
- Direct GitHub API access.
- Direct OSV API access.

The engine should consume data supplied through its existing interfaces and return analysis results.

### API and service layer

The Angular API and service layer remains responsible for:

- GitHub API communication.
- OSV communication.
- Request cancellation.
- Timeouts.
- Rate-limit handling.
- Response validation.
- Fetching repository files.
- Mapping external responses into internal models.
- Reporting unavailable or incomplete data.

### UI and reporting

The presentation layer remains responsible for displaying:

- Analysis results.
- Findings.
- Scores.
- Coverage.
- Warnings.
- Unsupported or unavailable evidence.
- Partial analysis states.

Do not move responsibilities between these layers unless a specific audit finding cannot be fixed otherwise.

## 2.2 Non-negotiable constraints

1. Do not introduce Nx.
2. Do not migrate Angular or TypeScript versions.
3. Do not replace the existing analysis engine.
4. Do not introduce a backend.
5. Do not introduce a database.
6. Do not introduce a new state-management library.
7. Do not add dependencies unless a concrete technical requirement justifies them.
8. Do not use `any`.
9. Preserve strict TypeScript settings.
10. Preserve existing public interfaces unless a change is necessary and all affected consumers are updated.
11. Avoid unnecessary services, abstractions, factories, and helper layers.
12. Do not refactor unrelated components or modules.
13. Do not rename unrelated files or public APIs.
14. Do not modify unrelated styling or UI behaviour.
15. Do not change scoring weights without independent justification and an impact analysis.
16. Do not suppress failing tests to make the implementation pass.
17. Do not silently turn missing information into a successful or clean result.
18. Do not claim support for an ecosystem or analysis capability that has not actually been implemented and tested.

Use the smallest maintainable implementation that addresses each finding.

## 2.3 Security principles

Treat all external repository information as untrusted.

This includes:

- Repository metadata.
- Dependency manifests.
- Lockfiles.
- SBOM documents.
- XML files.
- JSON files.
- GitHub API responses.
- OSV API responses.
- Workflow files.
- Security configuration files.

Never execute repository code, package scripts, build scripts, or arbitrary commands from scanned repositories.

Do not introduce arbitrary URL fetching. Repository file discovery must use the existing GitHub request architecture and approved file-fetching paths.

Preserve existing protections against:

- XSS.
- XML entity expansion.
- Oversized responses.
- Excessive nesting.
- Excessive parser work.
- Memory exhaustion.
- Unbounded requests.
- Unsafe redirects.
- Malformed external data.

Any new parser or discovery mechanism must follow the same security principles.

---

# 3. Baseline and implementation discipline

Before modifying code, establish the exact starting state.

## 3.1 Inspect the repository

Inspect:

- Current Git branch.
- Current commit.
- Working tree status.
- Package scripts.
- TypeScript configuration.
- Angular configuration.
- Test configuration.
- Existing architecture and module boundaries.
- Existing engine models and interfaces.
- Existing GitHub and OSV API services.
- Existing scoring implementation.
- Existing report generation.
- Existing test coverage.

Do not assume that the audit line numbers are still correct. Locate the relevant implementation in the current checkout.

The audit baseline is `d7e6336`, but the actual working tree may contain additional changes. Record the actual starting commit and working-tree status before proceeding.

## 3.2 Establish baseline test results

Run the existing project test suite using the repository's supported commands.

The audit reported:

- 313 passing tests.
- No runtime dependency carrying an advisory.
- Existing application security hardening.
- Existing URL validation.
- Existing request allowlisting.
- Existing response parsing limits.
- Existing CSP and Trusted Types checks.
- 8 quota-consuming GitHub requests per scan.

Verify these claims against the current checkout where possible.

Do not claim a test passed if it was not executed.

Record:

- Test command.
- Number of passing tests.
- Number of failing tests.
- Build result.
- Lint result, if available.
- Any pre-existing failures.

## 3.3 Work phase by phase

For every phase:

1. Inspect the affected implementation.
2. Identify the exact cause of the finding.
3. Write or update regression tests.
4. Demonstrate that the relevant regression test fails against the old behaviour where practical.
5. Implement the smallest appropriate fix.
6. Run the focused tests.
7. Run the broader test suite.
8. Run the production build.
9. Review the diff for unrelated modifications.
10. Document the outcome.

Do not proceed to the next phase while a critical correctness regression from the current phase remains unresolved.

Keep changes logically separated by phase. Use separate commits if the existing repository workflow supports them and the working tree permits it.

Do not overwrite, discard, reset, or otherwise modify pre-existing user changes.

---

# 4. Phase A: Fix confirmed OSV vulnerability loss

**Priority:** P0  
**Audit finding:** P0-1  
**Objective:** Prevent confirmed vulnerability matches from disappearing when OSV advisory detail requests fail.

This is the highest-priority issue in the audit.

## 4.1 Problem description

The current OSV processing flow has a confirmed correctness problem.

The audit identified:

- `core/api/osv-api.service.ts:183-192` catches advisory detail-fetch errors and returns `null`.
- The accumulator drops those null records.
- `engine/security/vulnerability-processor.ts:235` iterates over `records`, not the original `matches`.
- A vulnerability confirmed by OSV querybatch can therefore disappear if the subsequent advisory detail request fails.
- The resulting analysis can report no findings.
- `packagesFailed` remains zero.
- `failureReason` remains null.
- The scan can appear completed even though a confirmed vulnerability was not fully processed.

The existing test in `osv-api.service.spec.ts:204` checks that one record survives, but does not verify that a missing advisory is disclosed.

## 4.2 Required implementation

Preserve the distinction between:

1. An OSV query returning no vulnerability match.
2. An OSV query confirming a vulnerability match.
3. A confirmed match whose advisory details were successfully retrieved.
4. A confirmed match whose advisory detail request failed.
5. An OSV query that failed entirely.

A confirmed match must not be silently discarded.

When an advisory detail request fails:

- Retain enough information to identify the missing advisory.
- Record that the detail retrieval failed.
- Ensure the package or scan is marked as incomplete.
- Ensure the final analysis cannot be interpreted as a clean result.
- Preserve successfully retrieved advisories.
- Preserve the existing partial-result handling where possible.

Use the existing result model and partial-analysis mechanisms rather than introducing a parallel result system.

If the existing model cannot express the failure accurately, extend it minimally.

Do not invent advisory details from an ID alone.

## 4.3 Required behaviour

### Scenario A: All advisory details retrieved

Given:

- OSV querybatch confirms one advisory.
- The advisory detail request succeeds.

Expected:

- The advisory appears in the vulnerability results.
- The analysis retains its existing successful behaviour.
- No unnecessary partial failure is introduced.

### Scenario B: Only confirmed advisory detail request fails

Given:

- OSV querybatch confirms one advisory.
- Its detail request fails.

Expected:

- The advisory is not silently discarded.
- The scan is marked as partial or incomplete.
- The result contains an explicit failure reason.
- The package failure count or equivalent failure information is updated.
- The report must not claim that no known vulnerabilities were found.

### Scenario C: One of two advisory detail requests fails

Given:

- OSV querybatch confirms two advisories.
- One detail request succeeds.
- One detail request fails.

Expected:

- The successfully retrieved advisory remains visible.
- The missing advisory is disclosed.
- The analysis is marked as partial.
- The report does not imply that the successful result represents complete coverage.

### Scenario D: No vulnerability matches

Given:

- OSV querybatch returns no matches.
- No detail requests are needed.

Expected:

- The result remains a valid no-match result.
- It must not be marked partial merely because there were no advisory details to retrieve.

## 4.4 Required tests

Add regression tests for:

- One confirmed advisory with successful detail retrieval.
- One confirmed advisory with failed detail retrieval.
- Two confirmed advisories where one detail request fails.
- All confirmed advisory detail requests failing.
- No confirmed advisories.
- Correct partial-result propagation.
- Correct failure counts.
- Correct report output.
- No false clean result when a confirmed match was lost.

The tests must assert the final user-visible analysis state, not merely an internal observable emission.

## 4.5 Acceptance criteria

- [ ] A confirmed OSV match cannot silently disappear.
- [ ] Failed advisory detail retrieval is represented explicitly.
- [ ] Successfully retrieved advisories remain available.
- [ ] Incomplete advisory retrieval produces a partial result.
- [ ] A partial result cannot be presented as a complete clean scan.
- [ ] Existing successful OSV behaviour remains unchanged.
- [ ] Regression tests cover the failure scenarios above.
- [ ] All existing tests pass.
- [ ] No unrelated architecture changes are introduced.

**Do not continue to Phase B until this phase is complete and verified.**

---

# 5. Phase B: Correct scoring, coverage, and uncertainty handling

**Priority:** P1  
**Audit findings:** P1-3, P1-4, P1-5, P1-6, P1-7, P1-11  
**Additional cleanup:** P2-1

The purpose of this phase is to ensure that scores accurately represent the available evidence.

A repository must not receive an artificially high score because information is missing, unavailable, or incorrectly classified.

## 5.1 P1-3: Clarify the two coverage percentages

The audit found that two different percentages are displayed beside each other without sufficient explanation:

- 60% represents the share of intended analysis weight that is scorable.
- 50% represents the scorable weight after accounting for evidence coverage.

These are different measurements.

The report currently risks making them appear contradictory.

### Required implementation

Inspect the existing coverage calculation and report rendering.

Make the terminology explicit.

Use labels that communicate what each percentage measures.

The report must distinguish:

- Analysis weight that is currently scorable.
- Evidence coverage within that scorable analysis.

Do not combine these values into a single percentage unless the underlying model explicitly defines that metric.

Do not change the existing scoring weights as part of this fix.

### Tests

- Verify the two percentages retain their intended calculations.
- Verify the report labels are unambiguous.
- Verify missing evidence does not cause the values to be misrepresented.
- Verify both values remain internally consistent.

## 5.2 P1-4: Correct the maintenance score description

The current maintenance score can reach 100/100 because it measures recent push activity.

A repository with a recent push but only one commit can receive a perfect maintenance score.

This is misleading if the report presents the result as a broad measure of maintenance quality.

### Required implementation

Inspect the maintenance scoring inputs and its displayed label.

The audit does not authorize inventing new maintenance metrics or changing the scoring weights.

At minimum:

- Make the label accurately describe the evidence being measured.
- Do not describe push recency as a complete measure of maintenance health.
- Make the limitation visible in the report or metric description.

If you believe a broader maintenance metric is necessary, document it separately as a future proposal. Do not introduce an unverified metric during this remediation.

### Tests

- A repository with a recent push and one commit must not be described as having comprehensively excellent maintenance.
- The displayed metric description must match the actual calculation.
- Existing score calculations must remain unchanged unless a specific audit finding requires a correction.

## 5.3 P1-5: Correct coverage for metrics that do not affect scores

The audit found that:

- `contributorCount`
- `daysSinceLastRelease`

are included in coverage calculations but do not affect the score.

This makes the coverage representation misleading.

### Required implementation

Inspect how each metric contributes to:

- Category coverage.
- Overall coverage.
- Score calculation.
- Report presentation.

A metric must not silently contribute to coverage as though it were a scored input when it does not affect the score.

Choose the smallest consistent solution:

- Exclude metrics that do not contribute to the score from score-related coverage calculations; or
- Clearly distinguish informational metrics from scored metrics.

Preserve any useful informational data in the report.

Do not add new scoring weights.

### Tests

- Verify contributor count does not artificially increase scored coverage.
- Verify release recency does not artificially increase scored coverage.
- Verify informational values can still be displayed.
- Verify overall coverage remains mathematically consistent.

## 5.4 P1-6: Correct missing commit activity handling

The audit found that missing commit activity (`null`) scores better than known zero activity.

The audit also notes that GitHub HTTP 202 can mean statistics are still being computed.

Unknown information must not be treated as positive evidence.

### Required implementation

Inspect how commit activity is represented and scored.

Distinguish:

- Known positive activity.
- Known zero activity.
- Unknown activity.
- Statistics still being computed.
- Failed retrieval.

Do not convert missing data into zero without an explicit reason.

Do not reward unknown activity more than known positive activity.

The audit suggests either:

1. Removing the zero-activity deduction; or
2. Making the coverage consequence visible enough that the category is appropriately uncertain.

Evaluate the existing model and choose the least disruptive correct approach.

Preserve the distinction between unavailable and known zero.

### Tests

- Known positive activity.
- Known zero activity.
- Missing activity.
- HTTP 202 or equivalent pending state.
- API failure.
- Correct score and coverage behaviour for each state.

A test must specifically prove that missing activity cannot produce an unjustified score advantage.

## 5.5 P1-7: Correct dependency health coverage

The audit found that dependency health hardcodes:

`coverage: 1`

This implies full coverage even when freshness and deprecation information are unavailable.

### Required implementation

Inspect the dependency health model.

Identify which inputs are actually available and which are not.

Do not report complete coverage when important inputs are missing.

The implementation must distinguish between:

- Data successfully evaluated.
- Data not supported by the current source.
- Data unavailable.
- Data not checked.

Use the existing coverage model where possible.

Do not invent dependency freshness or deprecation information.

### Tests

- Verify unavailable freshness data does not count as full coverage.
- Verify unavailable deprecation data does not count as full coverage.
- Verify available dependency information remains usable.
- Verify the final dependency health score and coverage are consistent.

## 5.6 P1-11: Apply the partial-coverage score ceiling unconditionally

The audit identified a scoring defect.

Current behaviour:

- With queryable ratio 0.70 and no findings, the score is 88.
- With the same queryable ratio and one Low finding, the score becomes 99.

A vulnerability finding increases the score.

This is unacceptable.

The current partial-coverage ceiling only applies when findings are empty.

### Required implementation

Apply the coverage ceiling after all deductions, regardless of whether findings exist.

The audit proposes the following calculation:

```typescript
score = Math.min(
  Math.max(0, 100 - totalDeductions),
  coverage.queryableRatio < 1 ? Math.round(60 + 40 * coverage.queryableRatio) : 100,
);
```

Inspect the actual scoring implementation before applying this expression.

Preserve the intended existing deduction calculations and ensure the coverage ceiling is applied at the correct point.

Do not change the scoring weights.

### Required tests

At minimum:

- Full coverage, no findings.
- Full coverage, one finding.
- Partial coverage, no findings.
- Partial coverage, one Low finding.
- Partial coverage, multiple findings.
- Zero queryable coverage.
- Boundary values around a queryable ratio of 1.
- Score never exceeds the coverage ceiling.

Add a property-style or table-driven test proving:

**At fixed coverage, adding findings must never increase the score.**

Also verify that adding deductions cannot increase the score.

## 5.7 P2-1: Remove redundant coverage arithmetic

The audit found that the overall coverage formula divides by scorable weight and then multiplies by the same weight, causing the operations to cancel.

This is dead arithmetic.

Inspect the formula and simplify it without changing its actual intended result.

Do not use this cleanup as an excuse to redefine coverage.

### Tests

- Verify existing expected coverage values remain unchanged.
- Verify edge cases such as zero scorable weight.
- Verify the simplified implementation is equivalent to the intended formula.

## 5.8 Phase B acceptance criteria

- [ ] Coverage percentages have clear and accurate labels.
- [ ] Maintenance labels do not overstate what is measured.
- [ ] Informational metrics do not artificially inflate scored coverage.
- [ ] Unknown commit activity is not rewarded as positive evidence.
- [ ] Dependency health no longer hardcodes full coverage when evidence is missing.
- [ ] The partial-coverage ceiling applies regardless of findings.
- [ ] Adding findings cannot increase a score at fixed coverage.
- [ ] Coverage calculations remain mathematically consistent.
- [ ] No scoring weights are changed without a separately justified proposal.
- [ ] All relevant tests pass.

---

# 6. Phase C: Improve npm dependency discovery and source-state reporting

**Priority:** P1  
**Audit findings:** P1-1 and P1-2  
**Objective:** Discover dependencies from repository manifests and lockfiles when GitHub's dependency graph is unavailable, while reporting source failures accurately.

This is a major product improvement.

## 6.1 P1-1: Add npm manifest and lockfile fallback

### Problem description

The audit found that DepGuard currently relies on the GitHub dependency graph for dependency discovery.

However, GitHub does not provide a dependency graph for every repository.

The audit verified that:

- `dukeofwest/depguard` returns 404 from the GitHub SBOM endpoint, including in the authenticated test.
- `expressjs/express` returns 200.
- `Newtonsoft/Newtonsoft.Json` returns 404.
- DepGuard's repository contains a complete `package-lock.json`.
- The lockfile contains 587 `node_modules` entries.
- All 587 entries have exact resolved versions.
- The repository has 6 production and 581 development dependency entries.
- There are 17 direct dependencies.
- The repository tree is already retrieved for other analysis checks.
- Raw GitHub file content can be retrieved through the existing raw-content path without consuming GitHub API quota.

A repository with a valid lockfile should not be reported as having no dependency inventory simply because the GitHub dependency graph is unavailable.

### Required implementation

Add an npm dependency discovery fallback using repository files already listed in the retrieved GitHub tree.

The implementation must:

1. Preserve the existing GitHub dependency graph as the preferred source.
2. Attempt a lockfile fallback when the dependency graph is genuinely unavailable.
3. Discover npm lockfiles from tree-listed paths.
4. Fetch eligible files through the existing approved raw GitHub content mechanism.
5. Parse supported lockfile formats.
6. Convert discovered dependencies into the existing internal dependency model.
7. Preserve exact resolved versions.
8. Preserve dependency provenance.
9. Report incomplete or unavailable inventories honestly.

Do not execute npm.

Do not run `npm install`, `npm ci`, package scripts, or repository code.

Do not access arbitrary URLs from lockfile content.

### Supported npm lockfile formats

Implement support for the relevant `package-lock.json` formats:

- Lockfile version 1.
- Lockfile version 2.
- Lockfile version 3.

Inspect the actual existing dependency model before implementing the parser.

Use the existing dependency representation wherever possible.

Avoid introducing a new parallel npm-specific dependency model unless it is genuinely necessary.

### Discovery rules

Use an explicit, fixed allowlist of repository file patterns.

At minimum, evaluate:

- `package-lock.json`.
- Workspace or nested project lockfiles where supported by the existing tree-discovery design.

Do not recursively fetch arbitrary repository files.

Do not scan arbitrary source files for dependency declarations.

The existing repository tree is the source of candidate paths. Only fetch paths that:

- Are present in that tree.
- Match an explicitly approved pattern.
- Pass the existing URL and path validation.
- Fit the configured request and resource limits.

Support monorepos carefully. Do not assume a repository has only one package or one lockfile.

Define how multiple lockfiles are handled. Avoid double-counting the same dependency when aggregating workspaces.

### Dependency information

For each dependency, preserve as much of the following as the current model supports:

- Package name.
- Package ecosystem.
- Exact resolved version.
- Direct or transitive classification.
- Production or development classification where available.
- Source file.
- Source type.
- Lockfile version.
- Dependency provenance.

Do not infer a resolved version when it is absent.

Do not classify a dependency as resolved merely because a manifest contains a version range.

Do not treat a malformed or unsupported lockfile as an empty inventory.

### Lockfile parsing and safety

The parser must:

- Reject malformed JSON safely.
- Enforce file-size limits.
- Enforce appropriate structural limits.
- Avoid excessive recursion.
- Avoid unbounded allocation.
- Handle missing or unexpected properties safely.
- Validate package names and version values.
- Handle duplicate or conflicting entries predictably.
- Avoid unsafe object-property assumptions.
- Avoid prototype-pollution vulnerabilities.
- Avoid executing package metadata or scripts.

Do not silently ignore parsing failures.

Return a meaningful state indicating whether the inventory was successfully parsed, partially parsed, unsupported, invalid, or unavailable.

### Security review gate for repository file discovery

The audit explicitly identifies that adding fallback discovery widens the current fixed-path security property.

This change requires a documented security review.

Before implementation is considered complete:

1. Document the existing file-fetching boundary.
2. Document the additional allowed file patterns.
3. Explain how candidate paths are derived from the GitHub tree.
4. Explain how paths are validated.
5. Explain how arbitrary URL fetching is prevented.
6. Explain how response size and parsing limits are enforced.
7. Explain how request budgets are respected.
8. Explain how cancellation and timeouts are handled.
9. Verify that a malicious repository cannot cause arbitrary files or URLs to be fetched.
10. Add regression tests for path and resource-limit violations.

Do not quietly widen file discovery without recording this review.

## 6.2 P1-2: Distinguish dependency graph failures from genuine absence

### Problem description

The audit found that the current SBOM parsing and optional retrieval logic collapses multiple states into overly broad outcomes.

Current states include:

- `parsed`.
- `unavailable`.
- `invalid`.

The current `RepositoryDataService.optional` behaviour maps multiple transport failures to `null`.

This can cause the report to say that GitHub has no dependency graph when the actual problem was:

- Rate limiting.
- Network failure.
- HTTP 403.
- Another API error.

These cases are not equivalent.

### Required implementation

Represent source retrieval and parsing states accurately.

At minimum, distinguish:

- Successfully retrieved and parsed.
- Not found or genuinely unavailable.
- Forbidden or access denied.
- Rate limited.
- Network failure.
- Timeout.
- Cancelled.
- Invalid content.
- Unsupported format.
- Partially processed.

Use the project's existing error and result conventions. Do not introduce unnecessary layers.

A 404 from the GitHub SBOM endpoint may be described as an unavailable dependency graph, but do not claim the repository has disabled a setting. The audit could not establish why a particular repository returned 404.

Do not claim that a missing GitHub dependency graph proves that no dependencies exist.

If the GitHub graph is unavailable and the npm lockfile fallback succeeds, report the fallback as the source of the dependency inventory.

If both sources fail, report the actual failure state.

### Tests

Test:

- GitHub SBOM success.
- GitHub SBOM 404.
- GitHub SBOM 403.
- Rate limiting.
- Network failure.
- Timeout.
- Cancellation.
- Invalid SBOM content.
- Unsupported SBOM format.
- Successful npm lockfile fallback after SBOM 404.
- Successful npm lockfile fallback after an API failure where the fallback is still permitted.
- Both discovery methods unavailable.
- No supported dependency inventory found.

Ensure that a 403 or rate-limit response is never rendered as a confirmed absence of dependencies.

## 6.3 Performance and API budget

The audit reports that:

- The existing request budget is 8 quota-consuming requests per scan.
- Raw GitHub file contents do not consume GitHub API quota.

Preserve the existing request budget.

Do not add unnecessary GitHub API requests.

Reuse the existing tree result.

Use the raw-content mechanism only for approved tree-listed files.

Limit the number of lockfiles fetched and parsed.

Ensure that cancellation, timeouts, and resource limits remain effective.

Do not assume raw GitHub content is unlimited or safe simply because it does not consume GitHub API quota.

## 6.4 Phase C acceptance criteria

- [ ] A valid npm lockfile can provide dependency inventory when the GitHub dependency graph is unavailable.
- [ ] Lockfile versions 1, 2, and 3 are handled correctly.
- [ ] Resolved versions are preserved accurately.
- [ ] Direct and transitive dependencies are classified correctly where supported by the lockfile.
- [ ] Production and development classifications are preserved where available.
- [ ] Multiple lockfiles and monorepos are handled without unintended duplication.
- [ ] Invalid and unsupported lockfiles are reported accurately.
- [ ] GitHub 404, 403, rate limit, network failure, and timeout are distinguishable.
- [ ] Missing GitHub graph data is not presented as proof of no dependencies.
- [ ] No repository code or scripts are executed.
- [ ] File discovery uses an explicit allowlist and tree-derived paths.
- [ ] The widened file-discovery boundary has a documented security review.
- [ ] Existing GitHub request budgets remain respected.
- [ ] Tests cover parsing, discovery, provenance, error states, and security boundaries.

---

# 7. Phase D: Introduce careful .NET/NuGet dependency discovery

**Priority:** P1 feature gap  
**Related audit finding:** P2-5  
**Objective:** Add useful .NET dependency discovery without confusing declared versions with resolved versions.

This phase must be implemented conservatively.

The audit verified that OSV can match NuGet packages, but it did not verify complete live .NET SBOM ingestion.

It also found that the current application does not parse .NET dependency manifests.

Do not advertise general NuGet repository scanning as supported until the implementation and tests demonstrate that support.

## 7.1 Current verified behaviour

The audit established:

- The SBOM ingestion layer supports purl type `nuget`.
- NuGet can be mapped to the OSV ecosystem `NuGet`.
- OSV matching was tested for `Newtonsoft.Json`.
- Case variants matched the same advisory.
- Both two-part and four-part version forms were tested.
- `System.Text.Encodings.Web` was also tested.
- `Newtonsoft.Json@13.0.3` returned no advisory in the tested request.
- These are observed behaviours, not a guarantee of every OSV contract.

Preserve the existing SBOM-based NuGet support.

Do not confuse this with repository manifest parsing.

## 7.2 Critical version correctness requirement

A .NET project can contain:

```xml
<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
```

This value may represent a minimum or requested version, not the version actually resolved and installed.

The project could resolve `13.0.3`.

A naive parser that treats `13.0.1` as an exact resolved version can produce false vulnerability findings.

This is a critical correctness trap.

### Non-negotiable rule

**Never send a declared minimum or version range to OSV as though it were a resolved package version.**

The internal model must distinguish at least:

- Declared dependency.
- Resolved dependency.

Preserve version provenance.

Only query OSV using a version that is genuinely resolved.

Do not fabricate a resolved version from a declared version.

If the available information is only a declaration, report it as declared and explain that vulnerability matching against an installed version is not possible from that evidence.

## 7.3 Supported .NET files

Evaluate support for these files:

- `.csproj`
- `.fsproj`
- `.vbproj`
- `Directory.Packages.props`
- `Directory.Build.props`
- `packages.lock.json`
- `packages.config`
- `.sln`

Use only files listed in the retrieved repository tree and only through the approved repository-file discovery mechanism.

Do not fetch arbitrary project files outside the tree.

Do not execute `dotnet restore`, build commands, or project scripts.

## 7.4 Implementation stages

Implement the NuGet work in the following order.

### Stage 1: Safe project-file parsing

Parse supported project XML files safely.

The parser must reject or safely handle:

- DTD declarations.
- External entities.
- Entity expansion attempts.
- Excessive nesting.
- Oversized attributes.
- Malformed XML.
- Excessive file size.
- Unexpected XML structures.

Do not use a parser configuration that permits external entity resolution.

Do not use unsafe DOM operations or browser-dependent parsing inside the pure engine.

Keep I/O and XML acquisition outside the pure analysis engine.

### Stage 2: PackageReference extraction

Support basic `PackageReference` entries.

Capture:

- Package name.
- Declared version.
- Source project file.
- Target framework where available.
- Conditional declaration information where available.
- Whether the version was declared directly or inherited.

Do not claim a resolved version at this stage.

### Stage 3: Central Package Management

Support `Directory.Packages.props`.

Account for:

- `PackageVersion` entries.
- Central version definitions.
- Project-level overrides.
- Inheritance and relevant property references where the implementation can resolve them safely.
- Multiple project files.
- Missing or unresolved properties.

Do not guess the result of an unresolved MSBuild property.

### Stage 4: Project properties and overrides

Evaluate the practical support required for:

- `$(Property)` references.
- `Directory.Build.props`.
- Project-level version overrides.
- Conditional package references.
- Multi-targeting.

If the implementation cannot safely determine which conditional declaration applies, preserve the uncertainty rather than choosing an arbitrary version.

Do not pretend to execute or fully evaluate MSBuild.

This is static analysis, not an MSBuild implementation.

### Stage 5: Resolved versions

Support resolved package information from `packages.lock.json`.

Use the lockfile as the source of resolved versions where its structure and target information permit reliable interpretation.

Support `packages.config` according to the evidence it actually provides.

Be explicit about the difference between:

- Declared direct dependencies.
- Resolved direct dependencies.
- Resolved transitive dependencies.
- Unresolved declarations.

A project without a lockfile may not expose its complete transitive dependency graph.

Do not claim full transitive dependency coverage when the available files only contain declarations.

### Stage 6: OSV integration

Map valid NuGet package identifiers and resolved versions to OSV queries.

Use the existing ecosystem mapping and vulnerability processing infrastructure.

Do not introduce a separate vulnerability engine for NuGet.

Do not query OSV using:

- Version ranges.
- Minimum versions.
- Unresolved MSBuild properties.
- Unknown versions.
- Guessed versions.

Normalize package identifiers and versions carefully.

Preserve the original source value and normalized query value where useful for provenance and diagnostics.

## 7.5 Required tests

### XML parser tests

- Valid project XML.
- Malformed XML.
- DTD declaration.
- External entity attempt.
- Entity expansion attempt.
- Excessive nesting.
- Oversized attribute.
- Oversized file.
- Unexpected namespace.
- Empty project.

### Package extraction tests

- Basic `PackageReference`.
- Missing version.
- Explicit version.
- Version range.
- Central Package Management.
- Project-level override.
- `Directory.Build.props`.
- `$(Property)` reference.
- Unresolved property.
- Conditional package reference.
- Multiple target frameworks.
- Duplicate package references.

### Lockfile tests

- Resolved direct dependency.
- Resolved transitive dependency.
- Multiple target frameworks.
- Missing target information.
- Invalid lockfile.
- Unsupported lockfile content.
- Duplicate or conflicting entries.

### Version correctness tests

Include this specific regression:

Given:

```xml
<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
```

When there is no resolved lockfile information:

- The dependency must be represented as declared.
- It must not be treated as resolved.
- `13.0.1` must not be sent to OSV as an installed version.

Also test a project where the declaration is `13.0.1` but the lockfile resolves `13.0.3`.

Expected:

- The resolved version is `13.0.3`.
- OSV is queried using `13.0.3`.
- The declaration and resolution provenance remain distinguishable.

### OSV tests

- NuGet ecosystem mapping.
- Case normalization.
- Tested two-part and four-part version behaviour.
- Known advisory match.
- No advisory match.
- OSV failure.
- Partial advisory retrieval.

Treat the audit's observed OSV behaviours as regression-test expectations, not as a reason to assume all NuGet version formats are universally supported.

## 7.6 Support and reporting requirements

Until the relevant parser and tests are implemented:

- Do not advertise general .NET manifest scanning.
- Do not imply that all NuGet dependencies are discovered.
- Do not imply that a `.csproj` declaration is a resolved installed dependency.

After implementation:

- Distinguish SBOM-derived NuGet dependencies from manifest-derived dependencies.
- Distinguish declared from resolved versions.
- Distinguish lockfile-backed transitive inventory from declaration-only inventory.
- Report unsupported or unavailable project information explicitly.

Update ecosystem verification metadata only when the corresponding support is actually implemented and tested.

The audit notes that NuGet is currently absent from `VERIFIED_ECOSYSTEMS` despite the OSV behaviour having been measured. Review this carefully and update the metadata only to the extent that the actual support justifies it.

## 7.7 Phase D acceptance criteria

- [ ] Existing SBOM-based NuGet support remains functional.
- [ ] Supported .NET project and lockfile formats are explicitly documented.
- [ ] XML parsing is safe against external entity and resource-exhaustion attacks.
- [ ] Declared and resolved versions are represented separately.
- [ ] A declared minimum version is never queried as an installed version.
- [ ] Lockfile-resolved versions are used for OSV queries.
- [ ] Central Package Management and project overrides are handled correctly where supported.
- [ ] Multi-targeting and conditional declarations are represented accurately.
- [ ] Unsupported MSBuild evaluation is not guessed.
- [ ] Missing lockfiles do not lead to false transitive coverage claims.
- [ ] NuGet support is not advertised more broadly than implemented.
- [ ] Tests cover parsing, resolution, provenance, OSV integration, and security.

---

# 8. Phase E: Correct repository security and engineering checks

**Priority:** P1  
**Audit findings:** P1-8, P1-9, P1-10  
**Objective:** Ensure repository checks reflect the actual evidence available in the repository.

## 8.1 P1-8: GitHub Actions detection when the API fails

### Problem description

The audit found that GitHub Actions detection incorrectly reports no CI when:

- The GitHub Actions API fails.
- The repository tree remains readable.

The current fallback checks six non-Actions CI files but does not inspect `.github/workflows/*`.

The guard requires both the API and tree to be unreadable before falling back.

This is incorrect.

### Required implementation

Use the existing repository tree as a fallback source for GitHub Actions workflow detection.

When the Actions API fails but the tree is readable:

1. Inspect tree-listed paths under `.github/workflows/`.
2. Identify supported workflow file extensions.
3. Apply safe, bounded matching.
4. Report the evidence source.
5. Avoid claiming a workflow is valid or executable merely because its filename exists.

If workflow content is required for a stronger conclusion, fetch it only through the existing approved raw-content mechanism.

If neither the API nor the tree is readable, report the state as unknown or unavailable.

Do not report no CI when the evidence source is unavailable.

### Tests

- Actions API success with workflows.
- Actions API success with no workflows.
- Actions API failure with readable workflow tree entries.
- Actions API failure with no workflow entries.
- Actions API failure with unreadable tree.
- Network failure.
- Rate limiting.
- Invalid workflow path.
- Unsupported workflow extension.

Verify that API failure plus a readable tree does not produce a false no-CI result.

## 8.2 P1-9: Dependabot configuration evidence must match its status

### Problem description

The audit found that a Dependabot configuration containing no `updates:` section is currently reported as `Configured` and receives the full 25 points.

This overstates the evidence.

### Required implementation

Inspect the current Dependabot configuration parser and scoring logic.

A configuration file's existence is not sufficient evidence that usable update configuration exists.

Recognize the required configuration structure before assigning a configured status.

At minimum:

- A valid recognized `updates:` section is required for the configured state.
- An empty or missing `updates:` section must not receive the full configured score.
- Malformed YAML must not be treated as a valid configuration.
- Unsupported or unrecognized structures must not be interpreted as configured.

Use the existing parser and status model where possible.

Do not add an unnecessary YAML dependency.

If the current parser is intentionally limited, document the supported subset and avoid claiming broader validation.

### Tests

- Valid Dependabot configuration with updates.
- Empty updates list.
- Missing updates section.
- Missing file.
- Invalid YAML.
- Unsupported structure.
- Multiple package ecosystems.
- Multiple update entries.
- Correct status and score for every case.

## 8.3 P1-10: Verify CodeQL workflow content

### Problem description

The audit found that the CodeQL documentation claims that the workflow action is verified.

However, the current implementation only regex-matches the workflow name or path.

It does not fetch and inspect workflow contents.

This creates a mismatch between what the check claims and what it actually verifies.

### Required implementation

Prefer verifying the actual workflow content.

Use the repository tree to identify candidate workflow files.

Fetch their content through the existing approved raw-content mechanism.

Inspect the workflow for a genuine CodeQL action reference rather than relying only on the filename or workflow name.

The check must distinguish:

- A workflow with a recognized CodeQL action.
- A workflow whose name merely contains CodeQL.
- A workflow that cannot be inspected.
- No matching workflow found.
- Invalid or unsupported workflow content.

Do not execute the workflow.

Do not claim that CodeQL analysis is successfully running just because a workflow references the action.

The check should describe exactly what it verified.

If actual content verification cannot be implemented safely, correct the documentation and scoring claims to match the weaker evidence. Do not retain a false verification claim.

### Tests

- Valid CodeQL workflow containing a recognized action.
- Workflow name contains CodeQL but has no action reference.
- Different workflow filename with a valid action.
- Missing workflow content.
- API failure with readable tree.
- Invalid workflow content.
- Unsupported action reference.
- Workflow content retrieval failure.
- Correct final status and explanation.

## 8.4 Phase E acceptance criteria

- [ ] GitHub Actions detection uses tree evidence when the Actions API fails.
- [ ] Unavailable evidence is not presented as proof of no CI.
- [ ] Dependabot status requires recognized configuration evidence.
- [ ] Empty or missing `updates:` does not receive the full configured score.
- [ ] CodeQL verification checks actual workflow content or accurately describes weaker evidence.
- [ ] No repository workflows are executed.
- [ ] All file reads remain within the approved repository-file discovery boundary.
- [ ] Tests cover success, failure, unavailable, malformed, and unsupported cases.

---

# 9. Phase F: Remaining consistency, reporting, and documentation work

**Priority:** P2  
**Audit findings:** P2-2, P2-3, P2-4, P2-5  
**Objective:** Remove inconsistencies between implementation, reporting, and documentation.

This phase should be focused and conservative.

Do not use it to introduce unrelated features.

## 9.1 P2-2: Align security policy check documentation and implementation

### Problem description

The audit found that the security policy check says it checks:

- `SECURITY.md`
- `.github/SECURITY.md`

However, the implementation also searches:

- `docs/SECURITY.md`

### Required implementation

Inspect the actual implementation and decide whether all three locations are intentionally supported.

Then make the implementation, documentation, and report wording consistent.

Do not remove a supported location merely to make the documentation match.

Do not claim additional paths are checked if they are not.

### Tests

- `SECURITY.md`.
- `.github/SECURITY.md`.
- `docs/SECURITY.md`.
- No security policy.
- Multiple matching files.
- Unreadable candidate file.

## 9.2 P2-3: Correct the tree-truncation fallback documentation

### Problem description

The audit found that `api.config.ts` documents a tree-truncation fallback that may cost up to two requests.

However, the implementation does not contain that fallback.

### Required implementation

Inspect the current tree retrieval and request-budget implementation.

Determine whether the documented fallback was intended but never implemented, or whether the documentation is outdated.

For this remediation, correct the documentation to match the actual implementation unless there is a concrete, approved reason to implement the missing fallback.

Do not add additional API requests merely to make an old comment true.

Preserve the current request budget.

### Tests

If only documentation changes are necessary, verify the existing request-budget tests and relevant configuration expectations remain correct.

If code changes are justified, add tests for the exact fallback behaviour and request cost.

## 9.3 P2-4: Expose `advisoriesOmitted` as structured report data

### Problem description

The audit found that `advisoriesOmitted` currently reaches the report only as prose.

This makes the information harder for other parts of the application and consumers to use reliably.

### Required implementation

Inspect the existing report model.

Expose `advisoriesOmitted` as a structured field.

Preserve the existing user-facing explanation.

Avoid introducing a separate report structure.

Ensure the structured value and displayed prose cannot contradict each other.

If the report model is serialized, preserve compatibility or explicitly update the relevant consumers and tests.

### Tests

- No omitted advisories.
- One omitted advisory.
- Multiple omitted advisories.
- Partial OSV retrieval.
- Structured value matches the displayed explanation.
- Existing report consumers continue to work.

## 9.4 P2-5: Update NuGet verification metadata accurately

Review `VERIFIED_ECOSYSTEMS`.

The audit established that NuGet matching behaviour has been measured through OSV requests, but full live .NET SBOM ingestion was not verified.

The audit also found no .NET manifest parser in the current implementation.

Update the metadata only to reflect capabilities that are genuinely verified.

Do not use a successful isolated OSV request as proof of complete ecosystem support.

Keep these concepts separate:

- OSV query compatibility.
- SBOM ingestion support.
- Manifest parsing support.
- Resolved-version discovery.
- Complete dependency inventory support.

### Tests

- Verify existing verified ecosystem entries.
- Verify NuGet metadata matches the implemented support.
- Verify unsupported manifest parsing is not represented as verified.

## 9.5 P3 findings

The audit summary reports three P3 findings but does not provide their descriptions or supporting evidence.

Do not invent P3 remediation tasks.

Do not claim the P3 findings have been resolved.

If the full audit artifact is available in the repository or provided context, inspect it and include only the explicitly documented P3 findings.

Otherwise, record that the three P3 findings remain outside the available remediation scope because their details were not supplied.

## 9.6 Phase F acceptance criteria

- [ ] Security policy paths are consistent across implementation and documentation.
- [ ] Tree-truncation documentation accurately reflects actual behaviour.
- [ ] `advisoriesOmitted` is available as structured report data.
- [ ] Report prose and structured values agree.
- [ ] NuGet ecosystem metadata reflects only verified capabilities.
- [ ] No unsupported P3 details are invented.
- [ ] All affected tests pass.

---

# 10. Cross-phase requirements

The following requirements apply to every phase.

## 10.1 No silent loss of data

If information was discovered but could not be processed, the result must reflect that.

Examples:

- OSV confirms an advisory but detail retrieval fails.
- A lockfile exists but is malformed.
- A repository file cannot be fetched.
- A dependency version is declared but not resolved.
- A GitHub API request fails while another evidence source remains available.

Do not silently discard the information and present a complete result.

## 10.2 No invented certainty

Do not infer:

- That a repository has no dependencies because the GitHub graph is unavailable.
- That a repository has disabled dependency graph settings because the SBOM endpoint returned 404.
- That a project has a resolved package version because its manifest contains a version declaration.
- That a repository has no CI because the Actions API failed.
- That CodeQL is configured because a workflow is named CodeQL.
- That a repository is fully maintained because it was pushed to recently.
- That a repository is secure because it received a high score.

Use precise states and explanations.

## 10.3 No score improvements from missing evidence or newly discovered vulnerabilities

The scoring model must not reward missing data.

At fixed coverage:

- Adding findings must not increase the score.
- Adding deductions must not increase the score.
- Unknown information must not be interpreted as positive evidence.
- Unsupported information must not be counted as successfully evaluated.

Do not change scoring weights during these phases.

## 10.4 Preserve source provenance

Wherever possible, maintain the source of each piece of dependency information.

Examples:

- GitHub dependency graph.
- npm `package-lock.json`.
- NuGet SBOM.
- NuGet `packages.lock.json`.
- `.csproj` declaration.
- `Directory.Packages.props`.

The report should be able to distinguish information derived from these sources.

Do not merge different evidence types in a way that loses whether a version was declared or resolved.

## 10.5 Partial results must remain useful

Partial analysis should not automatically invalidate every successfully retrieved finding.

For example, if one of two OSV advisory details fails:

- Preserve the successfully retrieved advisory.
- Disclose the missing advisory.
- Mark the result incomplete.

Use existing partial-result mechanisms wherever possible.

## 10.6 Cancellation, timeouts, and resource limits

All new network and parsing operations must respect existing:

- Cancellation behaviour.
- Request timeouts.
- Response-size limits.
- Parsing limits.
- Concurrency limits.
- Request budgets.
- Error handling.

Do not add an unbounded queue of file requests.

Do not allow a repository containing thousands of candidate manifests to cause unlimited fetching or parsing.

If a configured limit is reached, report incomplete discovery rather than silently claiming a complete inventory.

---

# 11. Testing strategy

Testing is part of the implementation, not a final optional step.

## 11.1 Unit tests

Add focused tests for:

- OSV match and detail retrieval handling.
- Partial result propagation.
- Dependency discovery state mapping.
- npm lockfile parsing.
- NuGet project XML parsing.
- NuGet lockfile parsing.
- Declared versus resolved versions.
- Ecosystem mapping.
- Coverage calculations.
- Score ceiling behaviour.
- Maintenance metric descriptions.
- CI detection.
- Dependabot configuration recognition.
- CodeQL workflow verification.
- Security policy discovery.
- Structured report output.

Keep tests close to the existing test structure.

Do not reorganize the test suite unnecessarily.

## 11.2 Regression tests

Every audit finding must have a test that would have caught the original defect.

A test that only verifies the happy path is insufficient for a finding caused by failure handling.

For every affected feature, test both:

- Successful evidence retrieval.
- Missing, invalid, incomplete, or failed evidence.

## 11.3 Property and invariant tests

Add tests for important invariants.

At minimum:

### Scoring monotonicity

At fixed coverage, adding findings must never increase the score.

### Coverage correctness

Missing evidence must not increase coverage.

### Dependency version correctness

Declared versions must not be treated as resolved versions.

### Source-state correctness

An API failure must not be interpreted as confirmed absence.

### Partial-result correctness

A partial result must not be rendered as a complete clean result.

### Parsing safety

Malformed or oversized input must not cause unbounded work or an unhandled application failure.

## 11.4 Integration tests

Where the existing test architecture supports it, add integration tests covering:

- GitHub dependency graph unavailable, npm lockfile fallback successful.
- GitHub dependency graph unavailable, fallback unavailable.
- OSV querybatch successful, advisory detail retrieval partially failing.
- .NET manifest discovery with a resolved lockfile.
- .NET manifest discovery without a resolved lockfile.
- GitHub Actions API failure with readable tree evidence.
- CodeQL workflow content retrieval.

Use deterministic mocked responses.

Do not rely on live GitHub or OSV availability for normal automated test runs.

## 11.5 Build and test verification

After each phase, run:

- Focused unit tests.
- Relevant integration tests.
- Full test suite.
- Production build.

Run lint and type checking if supported by the existing repository scripts.

Do not modify existing scripts just to make the checks pass.

Record commands and actual results.

---

# 12. Explicit exclusions

The following are outside the scope of this remediation unless a specific audit finding makes a minimal change necessary:

- Full architecture redesign.
- Backend implementation.
- User accounts or authentication.
- Database introduction.
- New dashboard design.
- Broad UI redesign.
- New scoring categories.
- New scoring weights.
- Repository code execution.
- Dependency installation from scanned repositories.
- Build or test execution of scanned repositories.
- General MSBuild evaluation.
- Full support for every NuGet project format or MSBuild feature.
- Arbitrary source-code dependency discovery.
- Arbitrary repository file fetching.
- Replacing GitHub REST API integration.
- Replacing OSV.dev.
- Migrating to a different framework.
- Introducing Nx.
- Rewriting the pure analysis engine.
- Unrelated refactoring.
- New features not identified in the audit.

If you discover a separate issue while working, document it in the final report. Do not automatically expand the implementation scope.

---

# 13. Required phase completion reports

At the end of each phase, provide a concise report with the following structure.

## Phase report template

### Phase

Name and audit finding IDs.

### Findings addressed

List the exact findings resolved.

### Root cause

Explain the actual code-level cause.

### Implementation

Describe the changes made and why they are sufficient.

### Files changed

List every modified or created file and its purpose.

### Tests added

List the regression and edge-case tests.

### Verification

Report:

- Focused test result.
- Full test result.
- Build result.
- Type-check or lint result where available.

### Remaining limitations

List anything not fully supported or any known limitation.

### Scope confirmation

Confirm whether unrelated architecture or functionality was changed.

If a finding cannot be fixed safely, explain why. Do not mark it complete simply because code was changed.

---

# 14. Final acceptance criteria

The remediation is complete only when all applicable criteria below are satisfied.

## Correctness

- [ ] Confirmed OSV matches cannot disappear silently.
- [ ] Partial advisory retrieval is visible.
- [ ] Partial coverage caps apply consistently.
- [ ] Findings cannot increase scores.
- [ ] Missing evidence cannot improve scores.
- [ ] Dependency health coverage reflects actual evidence.
- [ ] Unknown activity is represented accurately.
- [ ] npm lockfiles can provide dependency inventory.
- [ ] NuGet declared and resolved versions remain distinct.
- [ ] NuGet OSV queries use only genuinely resolved versions.
- [ ] CI and security configuration checks reflect actual evidence.
- [ ] CodeQL verification matches its description.
- [ ] Report fields and prose are consistent.

## Security

- [ ] No repository code is executed.
- [ ] No arbitrary URLs are fetched.
- [ ] New file discovery uses explicit approved patterns.
- [ ] Candidate paths originate from the repository tree.
- [ ] XML parsing is safe.
- [ ] JSON and XML parsing are bounded.
- [ ] Resource limits remain effective.
- [ ] Request budgets remain respected.
- [ ] Cancellation and timeouts remain effective.
- [ ] No unsafe HTML rendering is introduced.
- [ ] No new XSS or prototype-pollution exposure is introduced.
- [ ] The expanded repository-file discovery boundary is documented and reviewed.

## Architecture

- [ ] The pure TypeScript engine remains independent of I/O and browser APIs.
- [ ] Angular services remain responsible for external communication.
- [ ] No unnecessary framework or dependency is introduced.
- [ ] No broad refactoring has occurred.
- [ ] Existing public interfaces remain compatible or are deliberately updated.
- [ ] No unrelated files or functionality have been modified.

## Quality

- [ ] Regression tests exist for all addressed findings.
- [ ] Relevant edge cases are covered.
- [ ] All existing tests pass.
- [ ] New tests pass.
- [ ] Production build passes.
- [ ] Type checking passes.
- [ ] Lint passes where supported.
- [ ] No test has been weakened or removed to conceal a regression.
- [ ] All six phase reports are available.

---

# 15. Final deliverables

When all six phases are complete, provide a final implementation report.

It must contain:

## A. Executive summary

Summarize what was corrected and the practical impact on DepGuard.

## B. Findings matrix

Include every audit finding addressed:

| Finding | Priority | Status | Implementation summary | Regression test |
| ------- | -------- | ------ | ---------------------- | --------------- |
| P0-1    | P0       |        |                        |                 |
| P1-1    | P1       |        |                        |                 |
| P1-2    | P1       |        |                        |                 |
| P1-3    | P1       |        |                        |                 |
| P1-4    | P1       |        |                        |                 |
| P1-5    | P1       |        |                        |                 |
| P1-6    | P1       |        |                        |                 |
| P1-7    | P1       |        |                        |                 |
| P1-8    | P1       |        |                        |                 |
| P1-9    | P1       |        |                        |                 |
| P1-10   | P1       |        |                        |                 |
| P1-11   | P1       |        |                        |                 |
| P2-1    | P2       |        |                        |                 |
| P2-2    | P2       |        |                        |                 |
| P2-3    | P2       |        |                        |                 |
| P2-4    | P2       |        |                        |                 |
| P2-5    | P2       |        |                        |                 |

Use only these status values:

- Resolved.
- Partially resolved.
- Not resolved.
- Not applicable.

Do not mark a finding resolved without evidence.

## C. Changed files

List all modified and created files, grouped by phase.

Explain why each was changed.

## D. Test results

Provide actual results for:

- Existing tests.
- New unit tests.
- Integration tests.
- Regression tests.
- Production build.
- Type checking.
- Lint.

Include commands where useful.

## E. Security review

Explain:

- How the new npm file-discovery mechanism is constrained.
- How NuGet XML parsing is protected.
- How untrusted repository content is handled.
- How resource limits are enforced.
- How arbitrary URL fetching is prevented.
- Whether the existing GitHub request budget remains unchanged.

## F. Dependency support matrix

Provide an accurate table describing the implemented support for:

- GitHub dependency graph/SBOM.
- npm lockfile v1.
- npm lockfile v2.
- npm lockfile v3.
- NuGet SBOM.
- `.csproj`.
- `.fsproj`.
- `.vbproj`.
- `Directory.Packages.props`.
- `Directory.Build.props`.
- `packages.lock.json`.
- `packages.config`.
- `.sln`.

For each, state whether it is:

- Supported and tested.
- Partially supported.
- Not supported.

Also distinguish declared dependency discovery from resolved dependency discovery.

Do not claim support simply because a file can be fetched or parsed.

## G. Known limitations

Document all remaining limitations, especially:

- Unsupported lockfile formats.
- Incomplete monorepo discovery.
- NuGet declarations without resolved versions.
- Unsupported MSBuild expressions.
- Missing transitive dependency information.
- Unavailable GitHub dependency graphs.
- OSV partial retrieval.
- Any remaining coverage uncertainty.

## H. Remaining audit findings

List anything not resolved.

Do not invent details for the three P3 findings if their descriptions were not available.

## I. Final scope confirmation

Explicitly state whether:

- The existing architecture was preserved.
- Any unrelated architecture was modified.
- Any new runtime dependency was introduced.
- Any scoring weights were changed.
- Any existing security boundary was widened.

If any of these occurred, explain exactly why and identify the relevant approval or evidence.

---

# 16. Final instructions

Work carefully and systematically.

The order of importance is:

1. Correctness.
2. Accurate uncertainty and partial-result handling.
3. Dependency discovery completeness.
4. Security.
5. Scoring integrity.
6. Reporting clarity.
7. Maintainability.

Do not optimize for the number of changed files or the amount of code written.

Do not turn a narrow fix into a broad abstraction.

Do not introduce a new architecture to solve a problem that can be fixed within the existing one.

Do not claim complete support when only partial support exists.

Do not hide errors to make the user interface appear cleaner.

The three rules that must guide every implementation decision are:

**1. No silent loss of data.**

**2. No invented certainty.**

**3. No score improvements from missing evidence or newly discovered vulnerabilities.**

Start with Phase A. Complete its tests and verification before moving to Phase B. Continue through all six phases in order, and provide the final report only after completing the implementation and verification work.

If a phase is blocked by an unresolved design decision, explain the exact issue and propose the smallest safe solution. Do not silently skip the requirement or make a speculative implementation.
