# ADR-0005: Toolchain choices for the Angular foundation

- **Status:** Accepted (Phase 1)
- **Date:** 2026-11-13

## Context

Phase 1 establishes the application foundation. Several choices were not fully determined
by the specification, and one was forced by a defect in the surrounding tooling.

## Decisions

### 1. Angular 21, not Angular 22

The specification mandates Angular 21 (§4.1). At the time of scaffolding, **Angular 22.2.7
is `latest`** and 21 has moved to LTS (`v21-lts: 21.2.30`). Installed: CLI 21.2.30,
framework 21.2.26.

Built on 21 as specified rather than silently taking the newer major (Rule 3: do not
silently change scope). Angular 21 LTS is supported and nothing in the MVP needs a v22
feature. Worth revisiting before release, since a portfolio project benefits from being
current, and the upgrade path is `ng update`.

### 2. Vitest, not Jest — pinned to 4.0.8

The specification allows "Jest or Angular's supported native test runner, after verifying
compatibility with Angular 21" (§4.1). Angular 21's `ng new` defaults to `vitest` via the
`@angular/build:unit-test` builder, which is the supported native path and needs no extra
configuration or adapter. Jest would add dependencies and a transform setup to reach the
same place.

**Vitest is pinned to an exact `4.0.8`, deliberately.** Installing the scaffolded range
`^4.0.8` resolves to 4.1.12 and crashes npm 10.9.9:

```
npm error Cannot read properties of null (reading 'edgesOut')
    at #loadPeerSet (.../@npmcli/arborist/lib/arborist/build-ideal-tree.js:1289:38)
```

This is an arborist peer-resolution defect triggered by vitest 4.1.x's optional peers
(`@vitest/browser-playwright`, `@napi-rs/canvas`), not a cache problem — `npm cache verify`
does not fix it, and 4.0.8 installs cleanly in 43 s.

The pin is therefore load-bearing: **relaxing it back to a caret range will break
`npm install` for anyone on npm 10.9.9**, including a clean CI checkout. Revisit when npm
is upgraded (npm 11+) or vitest 4.1.x's peer metadata changes, and verify with a clean
`npm ci` before loosening.

### 3. No Angular Router

The specification says to use the Router "only if the application genuinely needs routing"
(§4.1). DepGuard has two views — input and report — and the report is held in memory for
the session. A deep link to a report could not restore it without re-running the scan, at
a cost of ~9 of the 60 hourly requests (ADR-0004).

View state is therefore a signal in the scan store. This also removes the GitHub Pages SPA
problem, where a project page returns 404 for client-side routes unless a `404.html`
fallback is added. `@angular/router` is removed from dependencies.

Revisit if shareable report URLs are implemented, which §16 lists as a future feature.

### 4. No `@angular/forms`

The landing page needs one text input. A signal plus a native `(input)` handler covers it.
Removed rather than carried unused (§4.3: no unnecessary libraries).

### 5. Engine purity enforced twice

§4.4 and the Phase 3 acceptance criteria require the engine to be free of Angular, DOM and
I/O dependencies. This is enforced by an ESLint rule _and_ by
`src/app/engine/engine-purity.spec.ts`, which also forbids `Date.now()` and `Math.random()`
so that identical input yields identical output (§6.5).

Belt and braces is deliberate: lint and tests run as separate CI steps, and an inline
`eslint-disable` can silence a rule. Both guardrails were verified to fire by committing a
deliberate violation and observing each one fail, then removing it.

Type-only imports from `core/models` are permitted — they are erased at compile time, so
the engine shares the domain vocabulary without a runtime dependency. Value imports are
rejected.
