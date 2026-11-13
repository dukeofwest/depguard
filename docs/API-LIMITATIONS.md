# API limitations

What DepGuard cannot determine, and why. Every limitation here is surfaced in the report
rather than quietly worked around.

## Caused by analysing anonymously

DepGuard uses no authentication, which has three consequences.

### 1. Sixty requests per hour, per IP address

An analysis costs 8 requests, so roughly 7 scans per hour. The remaining budget is shown
in the header, and a scan will not start when fewer than 10 remain.

Users behind corporate NAT or a shared connection may arrive with the budget already
spent. There is nothing DepGuard can do about this without authentication.

### 2. GitHub feature status is invisible

DepGuard can see that a file exists. It cannot see whether the corresponding GitHub
feature is switched on.

| What DepGuard can say                                | What it cannot say                                              |
| ---------------------------------------------------- | --------------------------------------------------------------- |
| `.github/dependabot.yml` exists and declares updates | Whether Dependabot alerts or security updates are enabled       |
| A workflow referencing CodeQL exists                 | Whether it runs, passes, or whether anyone acts on its findings |
| A CI workflow exists                                 | Whether builds currently pass                                   |

Every such check states this limitation in its own evidence. A missing configuration file
is never reported as a confirmed vulnerability.

### 3. Private repositories are out of scope

GitHub returns 404 rather than 403 for repositories an anonymous caller cannot see, so
"does not exist" and "is private" are genuinely indistinguishable. The error message says
so instead of guessing.

## Caused by how dependency data is published

### Version ranges cannot be checked

This is the most significant limitation in the product.

GitHub's dependency graph reports versions **as the manifest declares them**. A project
without a committed lockfile declares ranges (`^1.2.1`), and a range does not identify
which version is installed. Advisory databases match exact versions, so such dependencies
cannot be checked at all.

Measured coverage:

| Repository          | Checkable | Lockfile committed |
| ------------------- | --------: | ------------------ |
| `npm/cli`           |     84.9% | Yes                |
| `expressjs/express` |     15.1% | No                 |
| `psf/requests`      |     10.0% | No                 |
| `request/request`   |    **0%** | No                 |

DepGuard never guesses a version. Where fewer than half the inventory can be checked, the
category reports insufficient data instead of a misleading clean result, and recommends
committing a lockfile.

### No dependency graph at all

GitHub provides an SBOM only for repositories with recognised manifest files. Two of the
six repositories tested in Phase 0 returned 404. Both dependency categories are then
excluded from scoring.

### Direct versus transitive is often unknowable

When no lockfile exists, every dependency edge originates from the repository root, so
"direct" would be true of everything and therefore mean nothing. The classification is
reported as `Unknown` rather than guessed.

## Caused by advisory data

### OSV does not cover everything

OSV aggregates many advisory sources, but not all. **No detected vulnerabilities is never
a guarantee of safety**, and the report says so in every case.

### Many advisories publish no severity

Every PYSEC record measured in Phase 0 (22 of 22) carried no severity rating and no CVSS
vector. These are reported as `Unknown` severity — never as low risk — and the category
summary states how many were scored that way.

### Only two ecosystems are verified

npm and PyPI were confirmed against live repository data. Maven, Go, crates.io, NuGet,
RubyGems and Packagist follow OSV's documented mapping but have not been demonstrated.
Reports using one carry an explicit notice.

GitHub Actions dependencies appear in SBOMs but are not an OSV package ecosystem in that
form, so they are excluded and counted rather than silently returning no results.

## Caused by not reading code

DepGuard examines observable repository signals. It does not read, parse or execute source
code, so it cannot find vulnerabilities in the repository's own code — only in its
declared dependencies.

"Test configuration detected" means exactly that: a test setup exists. It says nothing
about coverage, whether the tests pass, or whether they are meaningful.

## Caused by response size

Very large repositories return a **truncated** file list — `torvalds/linux` returns 71,474
entries with `truncated: true`. A path absent from a truncated list is not evidence the
file is missing, so affected checks report `Unknown` rather than `Not detected`, and no
recommendation is generated from them.

Processing caps: 16 MB per SBOM, 20,000 packages, 512 KB per file, 400 advisory detail
requests. Beyond these the excess is dropped and disclosed, never silently truncated.

## Not tested

- **Browsers other than Chrome.** The CORS, accessibility and workflow verification tools
  drive headless Chrome. Nothing relies on Chrome-specific behaviour, but Firefox and
  Safari have not been exercised.
- **GitHub Enterprise and other hosts.** Only `github.com` is supported.
