import type {
  ActivityClassification,
  MaintenanceSignals,
} from '../../core/models/health-report.model';
import type { RepositorySnapshot } from '../../core/models/repository.model';
import { ACTIVITY_THRESHOLDS, daysBetween } from './thresholds';

/**
 * Repository maintenance and activity analysis (§5.4).
 *
 * `now` is a parameter, never read from the clock, so the engine stays deterministic:
 * the same snapshot and the same instant always produce the same result (§6.5).
 *
 * The specification is explicit that low activity is not evidence of poor quality — a
 * mature project may legitimately need very few changes — so this classifies observable
 * activity and leaves interpretation to the reader.
 */
export function analyseMaintenance(snapshot: RepositorySnapshot, now: Date): MaintenanceSignals {
  const { metadata } = snapshot;

  const daysSinceLastPush = daysBetween(metadata.pushedAt, now);
  const daysSinceLastRelease = daysBetween(snapshot.latestRelease?.publishedAt ?? null, now);

  const commitsLast52Weeks =
    snapshot.weeklyCommits === null
      ? null
      : snapshot.weeklyCommits.reduce((total, week) => total + week, 0);

  return {
    classification: classifyActivity(metadata.isArchived, daysSinceLastPush),
    daysSinceLastPush,
    daysSinceLastRelease,
    commitsLast52Weeks,
    contributorCount: snapshot.contributorCount,
    isArchived: metadata.isArchived,
  };
}

/**
 * Classifies activity from the last push date.
 *
 * Archived takes precedence over everything: GitHub archiving is an explicit statement by
 * the owner that the repository is no longer maintained, which is stronger evidence than
 * any inference from dates.
 *
 * A missing or unusable date yields `Insufficient data` rather than a guess — "we do not
 * know" must never collapse into "stale".
 */
export function classifyActivity(
  isArchived: boolean,
  daysSinceLastPush: number | null,
): ActivityClassification {
  if (isArchived) {
    return 'Archived';
  }
  if (daysSinceLastPush === null) {
    return 'Insufficient data';
  }
  // A future-dated push means the clock or the data is wrong; claiming freshness from it
  // would be unjustified.
  if (daysSinceLastPush < 0) {
    return 'Insufficient data';
  }
  if (daysSinceLastPush <= ACTIVITY_THRESHOLDS.recentlyActiveDays) {
    return 'Recently active';
  }
  if (daysSinceLastPush <= ACTIVITY_THRESHOLDS.activeDays) {
    return 'Active';
  }
  if (daysSinceLastPush <= ACTIVITY_THRESHOLDS.limitedActivityDays) {
    return 'Limited activity';
  }
  return 'Potentially stale';
}

/** A short, factual sentence describing activity, for the dashboard. */
export function describeMaintenance(signals: MaintenanceSignals): string {
  if (signals.isArchived) {
    return 'The owner has archived this repository, meaning it is no longer maintained.';
  }
  if (signals.daysSinceLastPush === null) {
    return 'DepGuard could not determine when this repository was last updated.';
  }
  if (signals.daysSinceLastPush <= ACTIVITY_THRESHOLDS.recentlyActiveDays) {
    return `Last updated ${formatDays(signals.daysSinceLastPush)}.`;
  }
  if (signals.daysSinceLastPush > ACTIVITY_THRESHOLDS.limitedActivityDays) {
    return `Last updated ${formatDays(signals.daysSinceLastPush)}. Some mature projects need few changes, so this is not necessarily a problem.`;
  }
  return `Last updated ${formatDays(signals.daysSinceLastPush)}.`;
}

function formatDays(days: number): string {
  if (days <= 0) {
    return 'today';
  }
  if (days === 1) {
    return 'yesterday';
  }
  if (days < 30) {
    return `${days} days ago`;
  }
  if (days < 365) {
    const months = Math.round(days / 30);
    return `${months} month${months === 1 ? '' : 's'} ago`;
  }
  const years = Math.floor(days / 365);
  return `over ${years} year${years === 1 ? '' : 's'} ago`;
}
