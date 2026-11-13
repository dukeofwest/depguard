# Privacy

DepGuard has no backend, no accounts and no analytics. This page describes exactly what
happens when you analyse a repository.

## What happens when you enter a URL

1. The URL is validated **in your browser**. An invalid URL never reaches the network.
2. Your browser requests public data about that repository directly from
   `api.github.com` and `raw.githubusercontent.com`.
3. The names and versions of its dependencies are sent to `api.osv.dev` to check for
   known vulnerabilities.
4. The report is assembled in your browser and displayed.

No DepGuard server is involved at any point, because there is not one. The application is
static files served from GitHub Pages.

## What is sent, and to whom

| Recipient | Receives                                                                           |
| --------- | ---------------------------------------------------------------------------------- |
| GitHub    | The owner and repository name you entered, as part of ordinary public API requests |
| OSV.dev   | The names and versions of that repository's dependencies                           |

Both receive your IP address and browser user-agent, as they would for any web request.
Their handling of that is governed by their own policies:
[GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement),
[OSV.dev](https://policies.google.com/privacy).

Nothing else is transmitted anywhere.

## What is stored

**Nothing persists.** Analysis results are held in memory for the session and discarded
when you close or reload the tab.

DepGuard does not use `localStorage`, `sessionStorage`, IndexedDB or cookies. This is
enforced by a lint rule and verified by test, not left to convention — a stale cached
report surviving a reload would be worse than spending the API quota again.

There are no analytics, no telemetry, no error reporting service and no third-party
scripts of any kind.

## No accounts, no tokens

DepGuard analyses public repositories anonymously. It never asks for a GitHub token,
password or account, and has no way to accept one.

This is a deliberate v1.0 decision: asking people to hand credentials to a new application
is a significant trust request, and public repository analysis is enough to make the
product useful. The cost is GitHub's anonymous rate limit of 60 requests per hour per IP
address, which the interface shows you at all times.

Because no credential exists, none can be leaked, logged, or included in an exported
report.

## Exported reports

The JSON export contains only the analysis: repository metadata, the dependency inventory,
vulnerability findings, check results, scores and recommendations. It contains no
credentials by construction, and the file is generated and downloaded entirely within your
browser — it is never uploaded.

## What DepGuard does not do

- It does not execute repository code or package scripts.
- It does not download arbitrary files. Only four specific configuration file paths are
  ever fetched, and never a path discovered inside repository content.
- It does not follow links found in repository or advisory text.
- It does not contact any host other than the three named above.
- It does not track which repositories you analyse.

## Verifying this yourself

Open your browser's developer tools, switch to the Network tab, and run an analysis. Every
request will be to `api.github.com`, `raw.githubusercontent.com` or `api.osv.dev`.

The source is public: the allowlist is in
[`api.config.ts`](../src/app/core/config/api.config.ts), and a request to any other origin
is rejected before it is sent.
