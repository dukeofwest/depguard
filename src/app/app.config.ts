import {
  ApplicationConfig,
  provideBrowserGlobalErrorListeners,
  provideZonelessChangeDetection,
} from '@angular/core';
import { provideHttpClient, withFetch } from '@angular/common/http';

/**
 * Application providers.
 *
 * Zoneless change detection: the application's state is held in signals (§4.3), so
 * zone.js is not needed and is not a dependency.
 *
 * `withFetch()` backs HttpClient with the Fetch API. Phase 0 verified every required
 * request works from a browser under CORS, including OSV's preflighted POST — see
 * docs/phase-0/BROWSER-CORS-PROOF.md.
 */
export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideZonelessChangeDetection(),
    provideHttpClient(withFetch()),
  ],
};
