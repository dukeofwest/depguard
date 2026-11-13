import { Injectable, inject } from '@angular/core';
import { Observable, concatMap, defer, map, of } from 'rxjs';

import { OsvApiService } from '../api/osv-api.service';
import { RepositoryDataService } from './repository-data.service';
import { RESPONSE_LIMITS } from '../config/api.config';
import type { RepositoryRef, RepositorySnapshot } from '../models/repository.model';
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
  | 'analysing-dependencies'
  | 'querying-vulnerabilities'
  | 'fetching-advisories'
  | 'evaluating'
  | 'completed';

export const STAGE_LABELS: Readonly<Record<AnalysisStage, string>> = {
  validating: 'Validating repository',
  'fetching-repository': 'Retrieving repository information',
  'fetching-sbom': 'Retrieving dependency inventory',
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
    sbom: unknown,
    emit: (stage: AnalysisStage, detail?: string) => void,
    now: () => Date,
  ): Observable<HealthReport> {
    const parsed = parseSbom(sbom, RESPONSE_LIMITS.maxPackages);

    if (parsed.kind !== 'parsed') {
      // No inventory: the report is still built, with both dependency categories
      // reporting insufficient data rather than a score (§6.2).
      emit('evaluating');
      return of(
        buildReport({
          snapshot,
          packages: [],
          dependencyCoverage: null,
          vulnerabilities: {
            kind: 'unavailable',
            reason: parsed.reason,
          },
          sbomUnavailableReason: parsed.reason,
          now: now(),
        }),
      );
    }

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
          sbomUnavailableReason: null,
          now: now(),
        }),
      );
    }

    emit('querying-vulnerabilities', `${toQuery.length} dependencies`);

    return this.osv.queryPackages(toQuery).pipe(
      map((osvResult) => {
        emit('evaluating');

        const findings = processVulnerabilities(osvResult.records, osvResult.matches);

        const vulnerabilities: VulnerabilityResult =
          osvResult.packagesFailed > 0 || osvResult.failureReason !== null
            ? {
                kind: 'partial',
                findings,
                packagesChecked: osvResult.packagesChecked,
                packagesFailed: osvResult.packagesFailed,
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
          sbomUnavailableReason: null,
          now: now(),
        });
      }),
    );
  }
}
