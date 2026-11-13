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
  /**
   * Pretty-printed so the file is readable and diffable, not just machine-parsable.
   *
   * Characters that are harmless in JSON but dangerous outside it are emitted as unicode
   * escapes. `JSON.stringify` leaves `<`, `>` and `&` as they are, which is correct JSON,
   * and the download is a Blob of type `application/json` that no browser renders — so
   * nothing here is exploitable today. But an exported report is a file people forward,
   * commit and paste into wikis and ticket systems, and a package name of
   * `<script>alert(1)</script>` becomes live markup the moment something serves it as
   * HTML. The escapes cost nothing: `JSON.parse` returns the identical string, so a
   * consumer still sees exactly the value DepGuard found.
   *
   * U+2028 and U+2029 are escaped for a different reason. They are valid inside a JSON
   * string but are line terminators in JavaScript, so an unescaped one breaks any
   * consumer that embeds the report in a script.
   */
  serialise(report: HealthReport): string {
    return JSON.stringify(report, null, 2).replace(
      /[<>&\u2028\u2029]/g,
      (character) => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'),
    );
  }

  /** `depguard-owner-repo-2026-11-13.json` */
  fileName(report: HealthReport): string {
    const { owner, repo } = report.repository.ref;
    const date = report.generatedAt.slice(0, 10);
    // Anything outside this set becomes a hyphen, and a run of dots collapses to one: a
    // repository named `..` would otherwise put `..` in the file name. Browsers sanitise
    // a download name themselves, so this is belt and braces — but an exported file name
    // also gets pasted into shell commands and scripts.
    const safe = (value: string): string =>
      value.replace(/[^A-Za-z0-9._-]/g, '-').replace(/\.{2,}/g, '.');
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
