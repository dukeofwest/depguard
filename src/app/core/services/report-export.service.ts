import { Injectable } from '@angular/core';

import type { HealthReport } from '../models/health-report.model';

/**
 * JSON report export (§7.3).
 *
 * The report is already a plain, versioned, credential-free structure by construction —
 * the application holds no credentials to leak (§9.1) — so export is a serialisation
 * step, not a redaction step. Nothing is stripped here, because nothing sensitive is ever
 * put in.
 */
@Injectable({ providedIn: 'root' })
export class ReportExportService {
  /** Pretty-printed so the file is readable and diffable, not just machine-parsable. */
  serialise(report: HealthReport): string {
    return JSON.stringify(report, null, 2);
  }

  /** `depguard-owner-repo-2026-11-13.json` */
  fileName(report: HealthReport): string {
    const { owner, repo } = report.repository.ref;
    const date = report.generatedAt.slice(0, 10);
    const safe = (value: string): string => value.replace(/[^A-Za-z0-9._-]/g, '-');
    return `depguard-${safe(owner)}-${safe(repo)}-${date}.json`;
  }

  /**
   * Triggers a browser download.
   *
   * Uses an object URL rather than a `data:` URI, which keeps large reports off the URL
   * and out of browser history. The URL is revoked immediately afterwards so the blob is
   * not retained for the life of the page.
   */
  download(report: HealthReport): void {
    const blob = new Blob([this.serialise(report)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    try {
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = this.fileName(report);
      anchor.rel = 'noopener';
      anchor.click();
    } finally {
      URL.revokeObjectURL(url);
    }
  }
}
