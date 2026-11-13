import { describe, expect, it } from 'vitest';

import { classifyActivity, describeMaintenance } from './maintenance-analyzer';
import { ACTIVITY_THRESHOLDS, daysBetween } from './thresholds';
import type { MaintenanceSignals } from '../../core/models/health-report.model';

describe('daysBetween', () => {
  const now = new Date('2026-11-13T12:00:00.000Z');

  it('counts whole days', () => {
    expect(daysBetween('2026-11-03T12:00:00.000Z', now)).toBe(10);
    expect(daysBetween('2026-11-13T12:00:00.000Z', now)).toBe(0);
  });

  it('returns null rather than 0 for missing or unusable dates', () => {
    // The distinction that matters: "we do not know when this was last pushed" must
    // never be mistaken for "it was pushed today".
    expect(daysBetween(null, now)).toBeNull();
    expect(daysBetween('not-a-date', now)).toBeNull();
    expect(daysBetween('', now)).toBeNull();
  });
});

describe('classifyActivity', () => {
  it('puts archived above every other signal', () => {
    // Archiving is an explicit statement by the owner, stronger than any date inference.
    expect(classifyActivity(true, 0)).toBe('Archived');
    expect(classifyActivity(true, 5000)).toBe('Archived');
    expect(classifyActivity(true, null)).toBe('Archived');
  });

  it('classifies at the documented thresholds', () => {
    const { recentlyActiveDays, activeDays, limitedActivityDays } = ACTIVITY_THRESHOLDS;

    expect(classifyActivity(false, 0)).toBe('Recently active');
    expect(classifyActivity(false, recentlyActiveDays)).toBe('Recently active');
    expect(classifyActivity(false, recentlyActiveDays + 1)).toBe('Active');
    expect(classifyActivity(false, activeDays)).toBe('Active');
    expect(classifyActivity(false, activeDays + 1)).toBe('Limited activity');
    expect(classifyActivity(false, limitedActivityDays)).toBe('Limited activity');
    expect(classifyActivity(false, limitedActivityDays + 1)).toBe('Potentially stale');
  });

  it('reports insufficient data when the date is unknown', () => {
    expect(classifyActivity(false, null)).toBe('Insufficient data');
  });

  it('refuses to infer freshness from a future-dated push', () => {
    // A negative age means the clock or the data is wrong; claiming "recently active"
    // from it would be unjustified.
    expect(classifyActivity(false, -5)).toBe('Insufficient data');
  });
});

describe('describeMaintenance', () => {
  function signals(partial: Partial<MaintenanceSignals> = {}): MaintenanceSignals {
    return {
      classification: 'Recently active',
      daysSinceLastPush: 3,
      daysSinceLastRelease: 30,
      commitsLast52Weeks: 50,
      contributorCount: 5,
      isArchived: false,
      ...partial,
    };
  }

  it('states archiving plainly', () => {
    expect(describeMaintenance(signals({ isArchived: true }))).toContain('archived');
  });

  it('says it does not know rather than guessing', () => {
    expect(describeMaintenance(signals({ daysSinceLastPush: null }))).toContain(
      'could not determine',
    );
  });

  it('qualifies staleness instead of calling it a defect', () => {
    // §5.4: a low commit count is not evidence of poor quality — a mature project may
    // legitimately need very few changes.
    const text = describeMaintenance(signals({ daysSinceLastPush: 800 }));
    expect(text).toContain('not necessarily a problem');
  });

  it('formats recent activity readably', () => {
    expect(describeMaintenance(signals({ daysSinceLastPush: 0 }))).toContain('today');
    expect(describeMaintenance(signals({ daysSinceLastPush: 1 }))).toContain('yesterday');
    expect(describeMaintenance(signals({ daysSinceLastPush: 10 }))).toContain('10 days ago');
  });
});
