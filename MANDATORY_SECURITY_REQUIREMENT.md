# Mandatory Security Engineering Requirements

Security is a first-class requirement for DepGuard, not an optional hardening task.

The application processes untrusted GitHub repository metadata, SPDX SBOM documents, package identifiers, vulnerability records and external API responses. All of these must be treated as potentially malicious input.

The implementation must follow secure-by-default principles.

## A. Application Security

1. Prevent XSS through Angular's standard sanitisation and safe template bindings.
2. Never use `innerHTML`, `outerHTML`, `document.write`, `eval`, dynamically generated Angular templates or unsafe DOM manipulation.
3. Never bypass Angular sanitisation for repository or API-provided data.
4. Validate every externally supplied URL before rendering or navigating to it.
5. Allow only HTTPS external links from approved destinations.
6. Implement strict GitHub repository URL validation.
7. Accept only valid `github.com/{owner}/{repository}` repository URLs.
8. Reject arbitrary hosts, IP addresses, localhost, private network addresses, malformed URLs and credential-containing URLs.
9. Never allow repository data to control API destinations.
10. Do not execute repository content.
11. Do not execute package scripts or binaries.
12. Treat Markdown, descriptions, package names and vulnerability summaries as untrusted text.

## B. Content Security Policy

Investigate and implement an appropriate Content Security Policy for the actual production hosting platform.

Evaluate:

- `default-src`
- `script-src`
- `connect-src`
- `img-src`
- `object-src`
- `base-uri`
- `form-action`
- `frame-ancestors`

Restrict external connections to the approved application, GitHub and OSV API origins.

Do not add broad script permissions or `unsafe-eval` without documented justification.

Evaluate Trusted Types enforcement and Angular compatibility.

Verify actual production HTTP response headers. Do not assume that local configuration automatically becomes a production security header.

If GitHub Pages cannot provide the required response-header controls, document the limitation and recommend a suitable alternative hosting configuration.

## C. API and External Data Validation

1. Validate GitHub API responses.
2. Validate OSV API responses.
3. Use explicit runtime validation for untrusted response objects.
4. Handle missing and unexpected properties.
5. Reject malformed JSON safely.
6. Apply response-size limits.
7. Apply package-count limits.
8. Apply maximum string lengths.
9. Apply maximum JSON nesting depth.
10. Validate SPDX structure and package URL formats.
11. Validate vulnerability version ranges.
12. Handle malformed package identifiers.
13. Restrict redirect destinations to approved hosts.
14. Never dereference arbitrary URLs supplied by repository data.
15. Use request timeouts and cancellation.
16. Apply bounded concurrency and request chunking.
17. Prevent unbounded polling, retries and memory allocation.

The analysis engine must not crash or become unresponsive when processing malformed or malicious repository data.

## D. Denial of Service Protection

Protect against:

- Oversized SBOM documents.
- Excessive dependency counts.
- Excessive JSON nesting.
- Duplicate package entries.
- Malformed SPDX relationships.
- Expensive version comparisons.
- Catastrophic regular-expression backtracking.
- Excessive concurrent API requests.
- Repeated analysis requests.
- Infinite polling.
- Unbounded retries.
- Excessive memory allocation.

Use explicit, documented limits.

Test boundary values and malicious inputs.

## E. Dependency and Software Supply-Chain Security

1. Commit `package-lock.json`.
2. Use `npm ci` in CI.
3. Run `npm audit`.
4. Review high and critical vulnerabilities.
5. Enable Dependabot where available.
6. Monitor GitHub Actions dependencies.
7. Review new npm packages before installation.
8. Avoid unnecessary dependencies.
9. Review lifecycle scripts.
10. Verify package integrity and provenance where supported.
11. Scan for suspicious dependency changes.
12. Keep Angular, TypeScript and Node.js supported and patched.

## F. GitHub Repository Security

1. Protect the default branch.
2. Enable two-factor authentication on the GitHub account.
3. Review collaborators and access permissions.
4. Enable secret scanning where available.
5. Enable push protection where available.
6. Scan current source code and Git history for secrets.
7. Never commit real credentials.
8. Restrict repository administration.
9. Require CI checks before merging where practical.
10. Maintain a security policy.
11. Document vulnerability reporting procedures.

## G. GitHub Actions Security

1. Explicitly declare workflow permissions.
2. Use the minimum required `GITHUB_TOKEN` permissions.
3. Pin actions to verified full commit SHAs.
4. Review third-party action source code.
5. Never interpolate untrusted GitHub event values directly into shell commands.
6. Avoid unsafe `pull_request_target` usage.
7. Never expose deployment secrets to untrusted pull-request code.
8. Protect deployment workflows.
9. Deploy production only from approved branches.
10. Avoid unnecessary write permissions.
11. Run Zizmor against GitHub Actions workflows.
12. Review workflow cache and artifact poisoning risks.
13. Set `persist-credentials: false` on checkout steps when persistent credentials are unnecessary.

## H. Security Testing

Create automated tests for:

- XSS payloads.
- Malicious repository URLs.
- Malformed URLs.
- Unexpected API response types.
- Malformed SBOM files.
- Oversized SBOM files.
- Excessive JSON nesting.
- Excessive dependency counts.
- Invalid package URLs.
- Malicious metadata strings.
- Unexpected redirects.
- API timeouts.
- Request cancellation.
- Race conditions.
- Excessive concurrent requests.
- Report export handling.
- External link validation.

Add parser fuzz tests where practical.

Run security checks during CI.

Do not consider a security tool's successful execution equivalent to a secure application. Review and triage its findings.

## I. Production Security

Before release:

1. Verify HTTPS enforcement.
2. Inspect production security headers.
3. Verify CSP behaviour.
4. Verify external API destinations.
5. Check for exposed secrets.
6. Check production dependencies.
7. Verify no development-only code is deployed.
8. Verify no unsafe source maps or debug information are exposed.
9. Review browser console and network requests.
10. Perform manual security testing.

## J. Security Documentation

Create:

- `docs/SECURITY.md`
- `docs/SECURITY-TESTING.md`
- `docs/THREAT-MODEL.md`
- `docs/INCIDENT-RESPONSE.md`

The threat model must identify:

- Assets.
- Trust boundaries.
- External data sources.
- Entry points.
- Potential attackers.
- Attack scenarios.
- Mitigations.
- Residual risks.

## K. Security Acceptance Criteria

Do not approve the MVP release if any unresolved critical or high-severity application security issue remains.

All findings must be reviewed and documented.

Security testing must be repeatable through automated CI checks wherever practical.

Do not claim that DepGuard is fully secure or immune to attacks. Document residual risks and the limits of the security assessment.

Security requirements must be implemented throughout development, not postponed until the final phase.
