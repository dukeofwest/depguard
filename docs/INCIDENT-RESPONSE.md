# Incident response

What to do when something goes wrong, written before it does.

This is scaled to what DepGuard actually is: a static browser application, maintained by
one person, with no backend, no accounts, no stored user data and no credentials. A plan
borrowed from a company with an on-call rota would be theatre. What follows is small
enough to be followed under pressure.

**The single most useful fact in an incident:** DepGuard holds nothing. There is no
database to contain a breach, no sessions to revoke, no tokens to rotate and no user
records to notify about. The realistic worst case is that visitors were served bad code
or shown a wrong report — both fixed by correcting and redeploying.

---

## 1. What counts as an incident

| Severity     | Definition                                                                                                                                                       | Response starts |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| **Critical** | Script execution in the DepGuard origin; the published bundle altered by anyone other than the maintainer; the GitHub account compromised                        | Immediately     |
| **High**     | A report can be made to show a false clean result for a vulnerable repository; a request can be directed to an unintended host; a credential is exposed anywhere | Same day        |
| **Medium**   | A hang or crash from hostile input; a wrong finding that overstates health; CSP not enforced in production                                                       | Within days     |
| **Low**      | Scanner output with no demonstrated impact; a cosmetic or documentation defect                                                                                   | Normal backlog  |

**A false clean result is treated as High, not Medium.** It is the specific failure this
product exists to prevent, and it does more damage than a crash: a crash is visible, and a
wrong green badge is not.

Not incidents: GitHub or OSV being down or slow; the 60-request hourly limit being
exhausted; a repository being private or unanalysable. These are documented behaviours and
the application reports them as such.

---

## 2. First thirty minutes

In this order. Do not skip step 1 for a critical.

1. **Write it down.** Open a private draft advisory at
   `github.com/dukeofwest/depguard/security/advisories` and record what is known: time,
   symptom, reporter, and the repository URL or input that triggers it. Memory degrades
   fast during an incident, and this becomes the timeline later.
2. **Confirm it.** Reproduce it. For anything input-driven, the reproduction is a URL or a
   captured API response. Capture the response body — it is the evidence, and the API may
   not return the same thing tomorrow.
3. **Judge severity** against the table above. When unsure between two levels, take the
   higher one.
4. **Decide whether to contain now or fix now.** See below — for DepGuard, containment is
   usually faster than a fix, and unusually cheap.

---

## 3. Containment

Containment options, cheapest first.

### Revert the deployment

The strongest and fastest action. The site is a static bundle built from `main`:

```bash
git revert <bad-commit>      # a revert, not a force-push: history stays auditable
git push origin main         # deploy.yml republishes automatically
```

Verify afterwards that the live site serves the reverted bundle, and that the deploy
workflow actually succeeded — a failed deploy leaves the bad version live.

### Take the site down

If a fix is not immediate and the risk is active, disable Pages:
**Settings → Pages → Source → None.** An unavailable product is better than one serving
script execution. This is reversible in a minute.

### If the GitHub account is compromised

This is the worst case, because it is the one where the maintainer is no longer in control.

1. Change the password and revoke all sessions.
2. Reset two-factor authentication and review recovery codes.
3. Revoke every personal access token, OAuth app and SSH key.
4. Review **Settings → Security log** for what was done.
5. Check whether any commit, tag, release or Pages deployment was made by anyone else, and
   whether any workflow file was altered.
6. Only then revert code.

DepGuard itself holds no credential, so there is nothing to rotate on the application
side. That is the entire reason the no-authentication decision was taken for v1.0.

### If a dependency is compromised

1. `npm audit` and identify the affected package and path.
2. If runtime (`@angular/*`, `rxjs`, `tslib`): take the site down or revert to a bundle
   built before the compromised version entered the lockfile. These ship to visitors.
3. If build-only: no published bundle is affected unless a build ran with the compromised
   version. Check whether one did, and republish from a clean build if so.
4. Pin the lockfile to a known-good version and rebuild.

### If a GitHub Action is compromised

Every action is pinned to a full commit SHA, so a repointed tag does not affect this
repository — which is the point of the pins. If the pinned SHA itself is malicious:
replace it, review the Actions run history for what ran, and treat any run after the
compromise as untrusted. No deployment secret is available to CI jobs, and checkouts use
`persist-credentials: false`, which bounds what such a run could have reached.

---

## 4. Fixing

1. Branch from `main`.
2. **Write a failing test first.** This is not a process nicety here: the test is how
   anyone later knows the problem was real, what it was, and that it stays fixed. Put it
   where a reader would look for it — see [SECURITY-TESTING.md](SECURITY-TESTING.md).
3. Fix it.
4. Run the full gate:
   ```bash
   npm run lint && npm run typecheck && npm run test:ci && npm run check:docs
   npm run build -- --configuration github-pages && npm run check:security
   ```
5. Review the fix for the same class of problem elsewhere. One `innerHTML` is rarely the
   only one; one unbounded string is rarely the only one.
6. Merge and let `deploy.yml` publish.
7. Verify on the live site, not just locally.

---

## 5. After it is fixed

1. **Publish the advisory** if visitors were exposed. Via GitHub Security Advisories, with
   a CVE request if warranted. State what was affected, for how long, and what to do.
2. **Credit the reporter** unless they prefer otherwise.
3. **Update the documents this incident proved wrong.** If the threat model did not
   anticipate it, that is a finding about the threat model —
   [THREAT-MODEL.md](THREAT-MODEL.md) gains a scenario, or a residual risk is reclassified.
   If the testing should have caught it, [SECURITY-TESTING.md](SECURITY-TESTING.md) gains
   a row.
4. **Record it** in the table in [SECURITY.md](SECURITY.md), so the history is visible to
   anyone evaluating whether to trust this project.
5. **Write down what would have caught it earlier**, and do that thing if it is cheap.

No blameless-postmortem ceremony for a one-maintainer project. But the question "what
would have caught this?" is asked every time, and answered in writing.

---

## 6. Receiving a report

The reporting process for others is in the root [SECURITY.md](../SECURITY.md). From the
maintainer's side:

- **Acknowledge within 72 hours**, even if only to say it is being looked at.
- **Work in a private advisory** until a fix is deployed. Not to be secretive, but because
  a public issue on a browser-only application is an exploit notice for every visitor.
- **Target 90 days** to a fix and disclosure, faster for anything critical.
- **Say so if it is not a vulnerability**, with the reasoning. "Not reproducible" and "out
  of scope" are legitimate answers, and the scope is written down in advance so the
  conversation is about facts rather than preferences.
- **Do not argue a finding down on reachability alone.** The vitest advisory in
  [SECURITY.md](SECURITY.md) was unreachable in this project and was fixed anyway, because
  "it cannot be reached from here" is an argument that is right until the day it is wrong.

---

## 7. Contacts and access

| What              | Where                                                                      |
| ----------------- | -------------------------------------------------------------------------- |
| Private reports   | `github.com/dukeofwest/depguard/security/advisories/new`                   |
| Repository and CI | GitHub, maintainer account only                                            |
| Hosting           | GitHub Pages, from the `main` branch; no other deployment target exists    |
| Dependencies      | npm public registry; `package-lock.json` is the authority                  |
| External services | `api.github.com`, `raw.githubusercontent.com`, `api.osv.dev` — no accounts |

There is no hosting provider to contact, no DNS registrar, no CDN and no third-party
service with an account. If GitHub is unavailable, DepGuard is unavailable, and there is
no failover — an accepted consequence of a free static site, recorded in
[THREAT-MODEL.md](THREAT-MODEL.md) §6.8.

---

## 8. Incident log

No incidents to date. New entries go here with date, severity, summary, resolution and
what changed as a result.

| Date | Severity | Summary       | Resolution | Follow-up |
| ---- | -------- | ------------- | ---------- | --------- |
| —    | —        | None recorded | —          | —         |
