/**
 * Maintenance activity thresholds.
 *
 * The specification (§5.4) requires that these live in exactly one place and are never
 * scattered through components and services. This is that place.
 *
 * The boundaries are judgement calls, documented so they can be argued with. They are
 * deliberately generous: §5.4 warns that a low commit count is not evidence of poor
 * quality, because a mature project may legitimately need very few changes.
 */

export const ACTIVITY_THRESHOLDS = {
  /** Pushed within this many days → "Recently active". */
  recentlyActiveDays: 30,
  /** Pushed within this many days → "Active". */
  activeDays: 90,
  /** Pushed within this many days → "Limited activity"; beyond it → "Potentially stale". */
  limitedActivityDays: 365,
} as const;

/**
 * A release older than this is reported as ageing.
 *
 * Reported as an observation only. Many healthy projects release rarely, so this never
 * drives a classification on its own.
 */
export const RELEASE_AGE_NOTICE_DAYS = 730;

/** Milliseconds per day, for date arithmetic in the engine. */
export const MS_PER_DAY = 86_400_000;

/**
 * Whole days between two instants, or null when the input is unusable.
 *
 * Returns null rather than 0 for missing or unparseable dates, so "we do not know when
 * this was last pushed" cannot be mistaken for "it was pushed today".
 */
export function daysBetween(fromIso: string | null, to: Date): number | null {
  if (fromIso === null) {
    return null;
  }
  const from = Date.parse(fromIso);
  if (Number.isNaN(from)) {
    return null;
  }
  return Math.floor((to.getTime() - from) / MS_PER_DAY);
}
