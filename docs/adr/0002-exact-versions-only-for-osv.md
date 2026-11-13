# ADR-0002: Query OSV only for packages with exact versions

- **Status:** Proposed (Phase 0)
- **Date:** 2026-11-13

## Context

GitHub's SBOM reports `versionInfo` straight from the manifest. When a repository does not
commit a lockfile, this is a **semver range**, not a resolved version:

```json
{
  "name": "range-parser",
  "versionInfo": "^1.2.1",
  "externalRefs": [{ "referenceType": "purl", "referenceLocator": "pkg:npm/range-parser@%5E1.2.1" }]
}
```

OSV's `version` field expects a single concrete version.

## Decision

A package is submitted to OSV **only** when its version string parses as an exact version
for its ecosystem. Packages with ranges, missing versions, missing purls, or ecosystems
outside the verified mapping are excluded from vulnerability querying, counted, and
reported to the user with the reason they were skipped.

## Evidence

OSV does **not** reject a range — it silently returns a different, wrong answer:

| Query             | Vulnerabilities returned       |
| ----------------- | ------------------------------ |
| `lodash@4.17.15`  | 5                              |
| `lodash@4.17.21`  | 2                              |
| `lodash@^4.17.15` | **4 — a third, incorrect set** |

Silent wrongness is the worst possible failure mode for a tool whose entire value is
trustworthy findings.

Measured consequence for coverage:

| Repository           | Packages | Queryable | Coverage |
| -------------------- | -------: | --------: | -------: |
| `npm/cli` (lockfile) |    1,208 |     1,026 |    84.9% |
| `expressjs/express`  |       54 |         8 |    14.8% |
| `psf/requests`       |       30 |         3 |    10.0% |
| `request/request`    |       41 |         0 | **0.0%** |

## Consequences

**Positive**

- Every vulnerability DepGuard reports is matched against a real installed version.
- The skip reasons are themselves a useful, honest finding, and produce a recommendation
  no competing tool surfaces this way: _commit a lockfile so your tree can be analysed_.

**Negative**

- Vulnerability coverage is low for the many repositories that do not commit lockfiles,
  and zero for some. This is mitigated, not solved, by ADR-0003's coverage floor: below
  50% queryable, Dependency Security reports `Insufficient data` and is excluded from the
  overall score rather than reporting a misleading clean result.

## Rejected alternatives

- **Resolve ranges to a concrete version** via registry metadata. Rejected: requires a
  registry integration per ecosystem (out of MVP scope per §5.2), and the resolved version
  would be _a_ satisfying version, not the one actually installed — inventing data the
  specification forbids.
- **Query the range anyway and caveat the result.** Rejected: demonstrably returns wrong
  advisories, and a caveat does not make a wrong finding right.
