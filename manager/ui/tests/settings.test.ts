import { describe, expect, it } from 'vitest';
import { thresholdProblems } from '../src/pages/SettingsPage';
import { toApiTs } from '../src/pages/AuditPage';

const ok = {
  'disk_high.warn_pct': '85', 'disk_high.crit_pct': '95', 'storage_runway.warn_days': '7', 'storage_runway.crit_days': '2', 'mem_low.available_pct': '10', 'mem_low.for_min': '10',
  'cpu_high.pct': '90', 'cpu_high.avg_min': '15', 'probe_push_lag.warn_s': '120', 'probe_push_lag.crit_s': '600', 'probe_spool.pct': '50', 'crash_loop.restarts': '3',
  'crash_loop.window_min': '15', 'version_drift.minutes': '10', 'clock.offset_ms': '1000', 'iface_errors.pct': '0.1', 'iface_errors.window_min': '15',
};

describe('fleet thresholds form', () => {
  it('accepts the defaults', () => {
    expect(thresholdProblems(ok)).toEqual({});
  });
  it('rejects out-of-range, non-integer and mis-ordered values', () => {
    expect(thresholdProblems({ ...ok, 'disk_high.warn_pct': '120' })['disk_high.warn_pct']).toBeTruthy();
    expect(thresholdProblems({ ...ok, 'crash_loop.restarts': '2.5' })['crash_loop.restarts']).toBeTruthy();
    expect(thresholdProblems({ ...ok, 'cpu_high.pct': '' })['cpu_high.pct']).toBeTruthy();
    expect(thresholdProblems({ ...ok, 'disk_high.warn_pct': '96' })['disk_high.crit_pct']).toMatch(/not be below/);
    expect(thresholdProblems({ ...ok, 'storage_runway.crit_days': '9' })['storage_runway.crit_days']).toMatch(/not be above/);
  });
});

describe('audit filters', () => {
  it('turns a local datetime into the API timestamp (UTC, Z suffix, no milliseconds)', () => {
    expect(toApiTs('')).toBeUndefined();
    expect(toApiTs('garbage')).toBeUndefined();
    expect(toApiTs('2026-11-18T12:30')).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00Z$/);
  });
});
