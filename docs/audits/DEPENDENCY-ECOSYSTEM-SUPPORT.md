# Dependency ecosystem support

**What DepGuard supports today.** Nothing is listed as supported unless the implementation
exists and its tests pass (§12, constraint 13 / §2.2 constraint 18).

Read this as the honest answer to "does DepGuard work for my project?"

Last updated: November 2026, after the audit remediation. Superseded the pre-remediation
version, in which the answer to every row below but the first was "no".

---

## 1. Two sources, in order of preference

1. **GitHub's dependency graph**, as SPDX JSON from
   `GET /repos/{owner}/{repo}/dependency-graph/sbom`. Preferred where available: already
   normalised, covers ecosystems DepGuard cannot parse, and costs a request already spent.
2. **The repository's own manifests and lockfiles**, read from `raw.githubusercontent.com`
   at paths taken from the file tree. Used when the dependency graph is unavailable.

The fallback matters because GitHub has no dependency graph for every repository.
Measured: `dukeofwest/depguard` returns 404 from the SBOM endpoint even with an
authenticated token, while committing a `package-lock.json` with 587 packages, every one at
an exact resolved version. The report said "no dependency inventory was available", which
was true of GitHub and false of the repository.

When the fallback is used, the report says so, names the files it read, and states what
they cannot tell you.

---

## 2. Support matrix

**Resolved** means the source states the version actually installed, so it can be checked
against OSV. **Declared** means the source states a constraint — a minimum, a range, or a
property — which cannot be checked without guessing (see §4).

| Ecosystem | OSV id      | Via SBOM | Manifest parsing | Resolved versions       | OSV matching verified |
| --------- | ----------- | -------- | ---------------- | ----------------------- | --------------------- |
| npm       | `npm`       | Yes      | **Yes**          | **Yes**                 | **Yes** — live        |
| NuGet     | `NuGet`     | Yes      | **Yes**          | **From lockfiles only** | **Yes** — live        |
| PyPI      | `PyPI`      | Yes      | No               | Via SBOM only           | **Yes** — live        |
| Maven     | `Maven`     | Mapped   | No               | Via SBOM only           | No                    |
| Go        | `Go`        | Mapped   | No               | Via SBOM only           | No                    |
| crates.io | `crates.io` | Mapped   | No               | Via SBOM only           | No                    |
| RubyGems  | `RubyGems`  | Mapped   | No               | Via SBOM only           | No                    |
| Packagist | `Packagist` | Mapped   | No               | Via SBOM only           | No                    |

`VERIFIED_ECOSYSTEMS` is `['npm', 'PyPI', 'NuGet']`. That list records **OSV query
compatibility only** — four separate questions are deliberately kept apart, because
conflating them is how a tool comes to claim more than it does:

1. OSV query compatibility — the list above.
2. SBOM ingestion — every mapped ecosystem.
3. Manifest parsing — npm and NuGet only.
4. Resolved-version discovery — npm always; NuGet only from a lockfile.

**Deliberately unmapped:** purl types `githubactions` and `github`. Both appear in real
GitHub SBOMs — 17 and 1 in `npm/cli` — and neither is an OSV package ecosystem in that
form, so packages carrying them are reported as `unsupported-ecosystem` rather than queried
and silently returning nothing.

---

## 3. npm

| File                   | Status                | Direct | Transitive | Resolved versions |
| ---------------------- | --------------------- | ------ | ---------- | ----------------- |
| `package-lock.json` v3 | **Supported, tested** | Yes    | **Full**   | Yes               |
| `package-lock.json` v2 | **Supported, tested** | Yes    | **Full**   | Yes               |
| `package-lock.json` v1 | **Supported, tested** | Yes    | **Full**   | Yes               |
| `npm-shrinkwrap.json`  | **Supported, tested** | Yes    | **Full**   | Yes               |
| `package.json` alone   | Not supported         | —      | —          | —                 |
| `yarn.lock`            | Not supported         | —      | —          | —                 |
| `pnpm-lock.yaml`       | Not supported         | —      | —          | —                 |

**v2 and v3** are read from the flat `packages` map, which states each entry's resolved
version and `dev` flag directly. **v1** is read from the nested `dependencies` tree, where
nesting expresses the install tree, so top-level entries are direct and everything below
them is transitive. For a v2 lockfile, which carries both, the flat map wins — reading the
legacy tree would discard the dev flags.

Verified against DepGuard's own lockfile as a committed fixture: 587 packages, 587 with
exact resolved versions, 581 development / 6 production, 17 direct.

### Handling

- **Duplicates within a file** are kept in the inventory and collapsed before querying.
  npm genuinely installs one package at one version in several places, and a count that
  disagrees with the lockfile is worse than one including real repetition.
- **Duplicates across files** (monorepos) are merged: the same package at the same version
  in two workspaces is one dependency. Where a package is direct in one workspace and
  transitive in another, `direct` wins; where it is production in one and development in
  another, `production` wins. Neither merge can downgrade what is known.
- **Workspace `link: true` entries** are excluded. They reference directories in the
  repository, not published packages, so they have no registry identity to check.
- **Aliases** (`npm:other@1.0.0`), `file:` and `git:` specifiers are kept in the inventory
  and are not queryable.
- **Unsupported `lockfileVersion`** is reported by number, never guessed at.

### Not supported, and why

`yarn.lock` (Berry v2+) and `pnpm-lock.yaml` are YAML. ADR-0005 declined a YAML parser for
untrusted input, and a purpose-built reader for each format is a larger piece of work than
it looks. They are reported as recognised-but-unsupported rather than ignored, so a user
with one is told DepGuard cannot read it instead of being shown an empty inventory.

---

## 4. NuGet / .NET

| File                       | Status                | Direct  | Transitive | Versions                    |
| -------------------------- | --------------------- | ------- | ---------- | --------------------------- |
| `packages.lock.json`       | **Supported, tested** | Yes     | **Full**   | **Resolved**                |
| `packages.config`          | **Supported, tested** | Unknown | None       | **Resolved**                |
| `.csproj`                  | **Supported, tested** | Yes     | **None**   | Declared                    |
| `.vbproj`                  | **Supported, tested** | Yes     | **None**   | Declared                    |
| `.fsproj`                  | **Supported, tested** | Yes     | **None**   | Declared                    |
| `Directory.Packages.props` | **Supported, tested** | —       | —          | Supplies declared versions  |
| `Directory.Build.props`    | **Supported, tested** | —       | —          | Supplies literal properties |
| `.sln`                     | Not supported         | —       | —          | —                           |

`.sln` is not parsed and does not need to be: the repository tree already enumerates every
project file without it.

### The rule that governs all of this

> `<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />` does **not** say that
> 13.0.1 is installed. A bare NuGet version is shorthand for `[13.0.1, )` — a **minimum**.

NuGet resolves it to the lowest available version satisfying the constraint, which is
usually 13.0.1 and is not guaranteed to be; transitive resolution can lift it higher. A
parser that treats the string as resolved produces **false positives**: if 13.0.1 carries
an advisory fixed in 13.0.2 and the project restored 13.0.3, DepGuard reports a
vulnerability on a project that does not have one.

So each declared form gets its own classification, and only one of them may be queried:

| Declared                        | Means                    | Classified         | Queried |
| ------------------------------- | ------------------------ | ------------------ | ------- |
| `Version="13.0.1"`              | `[13.0.1, )` — a minimum | `declared-minimum` | **No**  |
| `Version="[13.0.1]"`            | exactly 13.0.1           | `resolved`         | **Yes** |
| `Version="[1.0,2.0)"`           | a range                  | `declared-range`   | No      |
| `Version="13.0.*"`              | a floating version       | `declared-range`   | No      |
| `Version="$(Prop)"`             | unknown without MSBuild  | `unresolved`       | No      |
| no version, no CPM              | unknown                  | `absent`           | No      |
| `packages.lock.json` `resolved` | installed                | `resolved`         | **Yes** |
| `packages.config` `version`     | installed                | `resolved`         | **Yes** |

**Consequence to be clear about:** a .NET repository with no `packages.lock.json` will
usually have **no queryable dependencies**, and Dependency Security will report insufficient
data rather than a score. That is the correct answer, and the report says what to do about
it — commit a lockfile. It is the same answer DepGuard already gives for an npm repository
with no lockfile.

This is not a rare case. `dotnet/machinelearning` has 83 `.csproj` files, one
`Directory.Packages.props`, and **zero** `packages.lock.json`: NuGet lockfiles are opt-in
(`RestorePackagesWithLockFile`) and largely absent in practice.

### Central Package Management

`Directory.Packages.props` supplies a version to any `PackageReference` that omits one. A
project-level `VersionOverride` beats the central value. `Directory.Build.props` is read
only for `PropertyGroup` literals, which is what lets `Version="$(SerilogVersion)"` resolve
when the property is a literal.

Inheriting a version does not change what it means: a centrally-managed `13.0.1` is still a
minimum.

### MSBuild

Never executed (constraint 7). Imports are not followed. Conditions are not evaluated — a
conditional `PackageReference` is listed, with the uncertainty recorded, rather than
resolved by picking a branch. A `$(Property)` is substituted only when every reference in
the string resolves to a literal already parsed; a partial substitution yields `unresolved`,
because "13..0" is not a version.

### OSV matching, measured

`POST https://api.osv.dev/v1/querybatch`, 14 November 2026:

| Query                                        | Result                |
| -------------------------------------------- | --------------------- |
| `Newtonsoft.Json` @ `9.0.1`                  | `GHSA-5crp-9r3c-p9vr` |
| `newtonsoft.json` @ `9.0.1`                  | same                  |
| `NEWTONSOFT.JSON` @ `9.0.1`                  | same                  |
| `Newtonsoft.Json` @ `9.0.1.0` (4-part)       | same                  |
| `System.Text.Encodings.Web` @ `4.5.0`        | `GHSA-ghhp-997w-qr28` |
| `System.Text.Encodings.Web` @ `4.5` (2-part) | same                  |
| `Newtonsoft.Json` @ `13.0.3`                 | none                  |

**OSV matches NuGet ids case-insensitively and normalises 2-, 3- and 4-part versions.** So
DepGuard performs no normalisation of its own — adding any would be speculative. Canonical
casing is preserved for display. This is measured behaviour, not a documented contract, so
it is covered by regression tests that would catch a change.

---

## 5. Version handling, all ecosystems

Only a single concrete version may be sent to OSV (ADR-0002), and `resolution` must be
`resolved`:

| Input                                                               | Shape     | Queried                            |
| ------------------------------------------------------------------- | --------- | ---------------------------------- |
| `4.17.21`, `v1.2.3`, `1.0.0-beta.1`, `13.0.1.0`                     | `exact`   | Only if `resolution` is `resolved` |
| `^4.17.15`, `~1.2`, `>=1.0,<2.0`, `1.x`, `*`, `latest`, `[1.0,2.0)` | `range`   | No                                 |
| absent or empty                                                     | `missing` | No                                 |

`versionKind` describes the _shape_ of a string; `resolution` describes what it _means_.
A NuGet declared minimum is shaped exactly like an exact version and is not one, which is
why shape alone cannot decide whether a version is safe to query.

The rule exists because of a measurement: querying `lodash@^4.17.15` returned 4 advisories
where the exact `4.17.15` returned 5. OSV does not reject a range supplied where a version
belongs — it answers a different question, just as confidently.

---

## 6. Transitive dependencies

| Source                              | Direct                             | Transitive                          |
| ----------------------------------- | ---------------------------------- | ----------------------------------- |
| GitHub SBOM with `relationships`    | From the root's `DEPENDS_ON`       | Everything else, fully resolved     |
| GitHub SBOM without `relationships` | `unknown`                          | `unknown`                           |
| `package-lock.json` (any version)   | Root manifest sections / top level | **Full**                            |
| `packages.lock.json`                | NuGet's `Direct` type              | **Full**, NuGet's `Transitive` type |
| `packages.config`                   | `unknown` — the file is flat       | None                                |
| `.csproj` / `.vbproj` / `.fsproj`   | Yes — a reference is a declaration | **None**                            |

A merged inventory reports `full` only when every contributing source could express the
graph, `none` only when none could, and `partial` otherwise. So a repository with one
`packages.lock.json` and 80 `.csproj` files is reported as partial — not full, which would
overstate it, and not none, which would discard what the lockfile did supply.

---

## 7. Discovery limits

`raw.githubusercontent.com` costs no GitHub API quota, which is what makes this affordable
— but it is not free, and a hostile repository could otherwise ship thousands of candidate
files.

| Limit                              | Value                        |
| ---------------------------------- | ---------------------------- |
| Lockfiles and props files per scan | 8                            |
| .NET project files per scan        | 24                           |
| Bytes per file                     | 512 KB                       |
| Total manifest bytes per scan      | 4 MB                         |
| Entries per lockfile               | 20,000                       |
| v1 lockfile tree depth             | 64                           |
| XML depth / nodes / attributes     | 64 / 50,000 / 64 per element |
| **Additional GitHub API requests** | **0**                        |

Reaching any limit is reported as incomplete discovery. It is never absorbed silently.

Candidate paths come only from the GitHub file tree, and only files whose basename or
extension matches a compiled allowlist are fetched. A path found _inside_ a file is never
fetched. See [SECURITY-REVIEW.md](SECURITY-REVIEW.md) §2.

---

## 8. Known limitations

1. **No dependency graph and no supported lockfile means no inventory.** A Go, Rust, Java,
   Ruby, PHP or Python repository without a GitHub dependency graph gets no dependency
   analysis.
2. **A .NET repository without `packages.lock.json` has no queryable dependencies.** Its
   declarations are listed and the limitation is stated; vulnerabilities cannot be matched.
3. **`yarn.lock` and `pnpm-lock.yaml` are not read** — reported as unsupported.
4. **Five of eight ecosystems have never had their OSV matching exercised** against live
   data.
5. **No version freshness or deprecation detection** for any ecosystem; no reliable free
   data source. Dependency Health reports 1 of 3 intended dimensions.
6. **Transitive dependencies of a `.csproj` are invisible.** Not approximated.
7. **MSBuild is not evaluated.** Conditions and non-literal properties stay unresolved.
8. **Only the default branch is analysed.**
9. **Private repositories are unsupported** — no credentials in v1.0, by design.
10. **A truncated file tree** means manifests may exist that DepGuard never saw; reported
    as `cannot-determine` rather than as absence.
11. **OSV is not exhaustive.** No findings is not evidence of safety.

---

## 9. Updating this document

Add a format here only when a parser exists, its tests pass against a committed fixture,
and the report states the provenance of what it found. Until then it belongs in
[DEPGUARD-IMPLEMENTATION-PLAN.md](DEPGUARD-IMPLEMENTATION-PLAN.md), not here.
