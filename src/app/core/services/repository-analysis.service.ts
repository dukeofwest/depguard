import { Injectable, inject } from '@angular/core';
import { Observable, concatMap, defer, map, of } from 'rxjs';

import { OsvApiService } from '../api/osv-api.service';
import { RepositoryDataService } from './repository-data.service';
import { DependencyDiscoveryService, type DiscoveryResult } from './dependency-discovery.service';
import type { SbomRetrieval } from './repository-data.service';
import { RESPONSE_LIMITS } from '../config/api.config';
import type { RepositoryRef, RepositorySnapshot } from '../models/repository.model';
import type { DependencyCoverage, NormalizedPackage } from '../models/dependency.model';
import type { HealthReport } from '../models/health-report.model';
import type { VulnerabilityResult } from '../models/vulnerability.model';
import { parseSbom, queryablePackages } from '../../engine/sbom/spdx-parser';
import { processVulnerabilities } from '../../engine/security/vulnerability-processor';
import { buildReport } from '../../engine/report/report-builder';

/**
 * Orchestrates a full analysis: fetch, parse, query, score, report.
 *
 * This is the only place where the Angular layer and the pure engine meet. All I/O
 * happens here; all decisions happen in the engine.
 *
 * Progress stages are emitted as work actually completes, never on a timer — §11.3
 * forbids artificial progress.
 */

/** Analysis stages, in order. Mirrors the state machine in ADR-0001. */
export type AnalysisStage =
  | 'validating'
  | 'fetching-repository'
  | 'fetching-sbom'
  | 'discovering-dependencies'
  | 'analysing-dependencies'
  | 'querying-vulnerabilities'
  | 'fetching-advisories'
  | 'evaluating'
  | 'completed';

export const STAGE_LABELS: Readonly<Record<AnalysisStage, string>> = {
  validating: 'Validating repository',
  'fetching-repository': 'Retrieving repository information',
  'fetching-sbom': 'Retrieving dependency inventory',
  'discovering-dependencies': 'Looking for a lockfile in the repository',
  'analysing-dependencies': 'Analysing dependencies',
  'querying-vulnerabilities': 'Checking known vulnerabilities',
  'fetching-advisories': 'Retrieving advisory details',
  evaluating: 'Calculating repository health',
  completed: 'Analysis complete',
};

export type AnalysisProgress =
  | { readonly kind: 'progress'; readonly stage: AnalysisStage; readonly detail?: string }
  | { readonly kind: 'report'; readonly report: HealthReport };

@Injectable({ providedIn: 'root' })
export class RepositoryAnalysisService {
  private readonly data = inject(RepositoryDataService);
  private readonly osv = inject(OsvApiService);
  private readonly discovery = inject(DependencyDiscoveryService);

  /**
   * Runs the analysis, emitting progress and finally the report.
   *
   * Unsubscribing cancels every in-flight request, which is what makes starting a new
   * scan safe — a stale response can never overwrite a current result (§10.4).
   */
  analyse(ref: RepositoryRef, now: () => Date = () => new Date()): Observable<AnalysisProgress> {
    return defer(() => {
      return new Observable<AnalysisProgress>((subscriber) => {
        const emit = (stage: AnalysisStage, detail?: string): void => {
          subscriber.next(
            detail === undefined
              ? { kind: 'progress', stage }
              : { kind: 'progress', stage, detail },
          );
        };

        emit('fetching-repository');

        const subscription = this.data
          .loadSnapshot(ref)
          .pipe(
            concatMap((snapshot) => {
              emit('fetching-sbom');
              return this.data.loadSbom(ref).pipe(map((sbom) => ({ snapshot, sbom })));
            }),
            concatMap(({ snapshot, sbom }) => {
              emit('analysing-dependencies');
              return this.analyseDependencies(snapshot, sbom, emit, now);
            }),
          )
          .subscribe({
            next: (report) => {
              emit('completed');
              subscriber.next({ kind: 'report', report });
              subscriber.complete();
            },
            error: (error: unknown) => subscriber.error(error),
          });

        return () => subscription.unsubscribe();
      });
    });
  }

  private analyseDependencies(
    snapshot: RepositorySnapshot,
    sbom: SbomRetrieval,
    emit: (stage: AnalysisStage, detail?: string) => void,
    now: () => Date,
  ): Observable<HealthReport> {
    const parsed = parseSbom(sbom.body, RESPONSE_LIMITS.maxPackages);

    if (parsed.kind !== 'parsed') {
      // GitHub has no usable dependency graph. Before reporting no inventory, look for a
      // lockfile in the repository itself: measured on `dukeofwest/depguard`, that is the
      // difference between "no dependency inventory was available" and 587 packages at
      // exact resolved versions (P1-1).
      emit('discovering-dependencies');

      // The reason the graph is unavailable comes from the retrieval state, not from the
      // parser's default sentence: a rate limit, a 403 and a genuine 404 are different
      // facts and only one of them is "GitHub has no dependency graph" (P1-2).
      const graphReason =
        parsed.kind === 'invalid'
          ? parsed.reason
          : sbom.state.kind === 'unavailable'
            ? sbom.state.detail
            : parsed.reason;

      return this.discovery
        .discover(snapshot.metadata.ref, snapshot)
        .pipe(
          concatMap((discovered) =>
            this.continueWithInventory(snapshot, discovered, graphReason, emit, now),
          ),
        );
    }

    return this.queryAndBuild(snapshot, parsed.packages, parsed.coverage, null, emit, now);
  }

  /**
   * Continues the analysis with whatever the fallback found.
   *
   * Each discovery outcome produces a *different* report, because they are not the same
   * situation: a repository with no lockfile, one whose lockfile could not be parsed, and
   * one whose file list could not be read all warrant different statements (§4.5).
   */
  private continueWithInventory(
    snapshot: RepositorySnapshot,
    discovered: DiscoveryResult,
    graphReason: string,
    emit: (stage: AnalysisStage, detail?: string) => void,
    now: () => Date,
  ): Observable<HealthReport> {
    if (discovered.kind === 'discovered') {
      emit('analysing-dependencies', `${discovered.packages.length} dependencies`);
      return this.queryAndBuild(
        snapshot,
        discovered.packages,
        discovered.coverage,
        describeFallback(graphReason, discovered),
        emit,
        now,
      );
    }

    // Nothing usable. The report still gets built, with both dependency categories
    // reporting insufficient data and a reason that says what was actually true rather
    // than asserting the repository has no dependencies (§10.2).
    emit('evaluating');
    const reason = `${graphReason} ${discoveryFailureReason(discovered)}`;
    return of(
      buildReport({
        snapshot,
        packages: [],
        dependencyCoverage: null,
        vulnerabilities: { kind: 'unavailable', reason },
        sbomUnavailableReason: reason,
        now: now(),
      }),
    );
  }

  /** Queries OSV for a resolved inventory and builds the report. */
  private queryAndBuild(
    snapshot: RepositorySnapshot,
    packages: readonly NormalizedPackage[],
    coverage: DependencyCoverage,
    inventoryNotice: string | null,
    emit: (stage: AnalysisStage, detail?: string) => void,
    now: () => Date,
  ): Observable<HealthReport> {
    const parsed = { packages, coverage };
    const toQuery = queryablePackages(parsed.packages);

    if (toQuery.length === 0) {
      // The request/request case: an inventory exists, but nothing in it can be checked.
      // This is explicitly NOT "no vulnerabilities found" (ADR-0002).
      emit('evaluating');
      return of(
        buildReport({
          snapshot,
          packages: parsed.packages,
          dependencyCoverage: parsed.coverage,
          vulnerabilities: {
            kind: 'not-applicable',
            reason:
              'No dependency had an exact version that could be checked against vulnerability databases.',
          },
          sbomUnavailableReason: inventoryNotice,
          now: now(),
        }),
      );
    }

    emit('querying-vulnerabilities', `${toQuery.length} dependencies`);

    return this.osv.queryPackages(toQuery).pipe(
      map((osvResult) => {
        emit('evaluating');

        const findings = processVulnerabilities(osvResult.records, osvResult.matches);

        // A lost advisory detail makes the result partial even when every batch
        // succeeded: `querybatch` confirmed the vulnerability, so reporting `completed`
        // here would present a known finding as a clean scan (P0-1).
        const incomplete =
          osvResult.packagesFailed > 0 ||
          osvResult.failureReason !== null ||
          osvResult.advisoriesUnretrieved.length > 0 ||
          osvResult.advisoriesOmitted > 0;

        const vulnerabilities: VulnerabilityResult = incomplete
          ? {
              kind: 'partial',
              findings,
              packagesChecked: osvResult.packagesChecked,
              packagesFailed: osvResult.packagesFailed,
              advisoriesUnretrieved: osvResult.advisoriesUnretrieved,
              advisoriesOmitted: osvResult.advisoriesOmitted,
              reason:
                osvResult.failureReason ??
                `${osvResult.packagesFailed} dependencies could not be checked.`,
            }
          : { kind: 'completed', findings, packagesChecked: osvResult.packagesChecked };

        return buildReport({
          snapshot,
          packages: parsed.packages,
          dependencyCoverage: parsed.coverage,
          vulnerabilities,
          sbomUnavailableReason: inventoryNotice,
          now: now(),
        });
      }),
    );
  }
}

/**
 * Explains that the inventory came from the repository, not from GitHub's graph.
 *
 * Both halves matter: the dependency graph was unavailable (and why), and a lockfile was
 * read instead (and which). A reader who sees only the second could reasonably assume
 * GitHub's graph agreed.
 */
function describeFallback(
  graphReason: string,
  discovered: Extract<DiscoveryResult, { kind: 'discovered' }>,
): string {
  const sources = discovered.sources.join(', ');
  const base =
    `${graphReason} DepGuard read the repository's own lockfile instead: ${sources}. ` +
    'Versions recorded in a lockfile are the versions actually installed.';

  return discovered.partial ? `${base} This inventory is incomplete — see the notes below.` : base;
}

/** The reason text for a discovery attempt that produced no inventory. */
function discoveryFailureReason(
  discovered: Exclude<DiscoveryResult, { kind: 'discovered' }>,
): string {
  switch (discovered.kind) {
    case 'no-manifest':
    case 'cannot-determine':
      return discovered.reason;
    case 'unsupported':
    case 'parse-failed':
      // A lockfile that exists and cannot be read is emphatically not an empty
      // inventory: something is there and DepGuard could not use it (§6.1).
      return `${discovered.reason} A dependency inventory may well exist; DepGuard could not read it.`;
  }
}
