# Contributing

Thanks for considering a contribution.

## The one rule that matters

**A report must never claim more than the evidence supports.**

DepGuard is a tool people might act on. A finding that overstates what was actually
observed is worse than no finding, because it is believed. Several design decisions that
look overly cautious exist for this reason:

- Dependencies declared as version ranges are **not** checked, because OSV silently
  returns wrong results for them.
- A category that could not be assessed reports _insufficient data_, never a score — and
  the types make a zero unrepresentable.
- A check that could not be performed is `Unknown`, never `Not detected`, and generates no
  recommendation.
- "Configured" means a configuration file exists, never that a GitHub feature is enabled.

A change that makes DepGuard say something it cannot support will not be merged, even if
it improves the numbers.

## Getting set up

Requires Node 20.19+, 22.12+ or 24+.

```bash
npm install
npm start          # http://localhost:4200
```

On Windows PowerShell, use `npm.cmd` if the execution policy blocks `npm.ps1`.

## Before opening a pull request

```bash
npm run lint
npm run typecheck
npm run test:ci
npm run build -- --configuration github-pages
```

CI runs all four. If you touched the interface, also run:

```bash
node tools/a11y-test.mjs dist/depguard/browser
```

It exits non-zero on a contrast regression and costs no API quota.

## House rules

**No `any`, no `@ts-ignore`, no non-null assertions, no `$any()` in templates.** All are
lint errors. `$any()` disables template type checking, which is where the honesty
guarantees above are enforced at render time.

**The engine stays pure.** `src/app/engine/` may not import Angular, touch the DOM,
perform I/O, read the clock or use randomness. Enforced by both ESLint and
`engine-purity.spec.ts`; it has caught real violations that review missed. Type-only
imports from `core/models` are fine.

**Third-party data is untrusted.** Package names, advisory text and repository metadata
are attacker-controllable. Render through interpolation only — never `innerHTML`, never
`bypassSecurityTrust*`. Do not sanitise names away either: hiding a package would hide a
real dependency.

**Severity is never communicated by colour alone.** Every indicator carries a word and a
distinct glyph shape.

## Tests

Prefer **real fixtures over invented ones**. The SBOM and advisory fixtures in
`src/app/engine/__fixtures__/` are unmodified captures from live APIs, which is what makes
the coverage numbers in the tests meaningful rather than circular.

Live tests (`DEPGUARD_LIVE=1`) hit the real GitHub and OSV APIs and spend the shared quota
of 60 requests per hour, so they are opt-in and excluded from CI. Assert invariants and
relationships, never exact counts — a test that fails because a new CVE was published is
noise.

## API quota

Anonymous GitHub access allows 60 requests per hour per IP. An analysis costs 8, and
`tools/workflow-test.mjs` costs the same each run. It is easy to exhaust the budget while
developing; the tool checks first and tells you rather than producing misleading output.

## Changing the scoring model

Scoring constants live in one place,
[`weights.ts`](src/app/engine/scoring/weights.ts), and are documented in
[`docs/SCORING.md`](docs/SCORING.md) with worked examples asserted by tests.

If you change them, update the documentation and the worked examples in the same pull
request, and explain the reasoning. The current weights were set by measuring which
signals are reliably available, not by intuition.

## Architecture decisions

Significant decisions are recorded in [`docs/adr/`](docs/adr/). If you are proposing a
change to one, add a new ADR rather than editing the old one — the reasoning at the time,
including what was measured, is the useful part.
