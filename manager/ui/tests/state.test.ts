import { describe, expect, it } from 'vitest';
import { backoffMs, diskSeverity, freshnessLevel, hostPresence, runwaySeverity, worstHealth } from '../src/lib/state';

const now = Date.parse('2026-11-18T12:00:00Z');
const seen = (s: number) => new Date(now - s * 1000).toISOString();

describe('freshness indicator', () => {
  it('turns amber after 90 s and red after 5 min', () => {
    expect(freshnessLevel(0)).toBe('ok');
    expect(freshnessLevel(89)).toBe('ok');
    expect(freshnessLevel(90)).toBe('amber');
    expect(freshnessLevel(299)).toBe('amber');
    expect(freshnessLevel(300)).toBe('red');
    expect(freshnessLevel(null)).toBe('red');
  });
});

describe('backoff', () => {
  it('doubles from the poll interval and caps at 5 min', () => {
    expect(backoffMs(0)).toBe(30_000);
    expect(backoffMs(1)).toBe(60_000);
    expect(backoffMs(2)).toBe(120_000);
    expect(backoffMs(3)).toBe(240_000);
    expect(backoffMs(4)).toBe(300_000);
    expect(backoffMs(50)).toBe(300_000);
  });
});

describe('host presence', () => {
  it('trusts the server state while our copy is fresh', () => {
    expect(hostPresence({ state: 'enrolled', last_seen: seen(30) }, now, 5_000)).toBe('online');
    expect(hostPresence({ state: 'stale', last_seen: seen(300) }, now, 5_000)).toBe('stale');
    expect(hostPresence({ state: 'enrolled', stale: true, last_seen: seen(300) }, now, 5_000)).toBe('stale');
    expect(hostPresence({ state: 'offline', last_seen: seen(3600) }, now, 5_000)).toBe('offline');
    expect(hostPresence({ state: 'pending', last_seen: null }, now, 5_000)).toBe('pending');
  });
  it('never shows a host as current from an old copy of the data', () => {
    // Our copy is 4 min old (polling failing) and the host had reported 1 min before that: 5 min ago now.
    expect(hostPresence({ state: 'enrolled', last_seen: seen(300) }, now, 240_000)).toBe('stale');
    expect(hostPresence({ state: 'enrolled', last_seen: seen(700) }, now, 240_000)).toBe('offline');
    expect(hostPresence({ state: 'stale', last_seen: seen(700) }, now, 240_000)).toBe('offline');
  });
  it('uses the host status interval for the 3 x rule', () => {
    expect(hostPresence({ state: 'enrolled', last_seen: seen(200) }, now, 120_000, 120)).toBe('online');
    expect(hostPresence({ state: 'enrolled', last_seen: seen(200) }, now, 120_000, 60)).toBe('stale');
  });
});

describe('thresholds', () => {
  it('disk amber at 85 and red at 95', () => {
    expect(diskSeverity(84.9)).toBe('ok');
    expect(diskSeverity(85)).toBe('warn');
    expect(diskSeverity(94.9)).toBe('warn');
    expect(diskSeverity(95)).toBe('fail');
    expect(diskSeverity(null)).toBe('unknown');
  });
  it('runway warns below 7 days and fails below 2', () => {
    expect(runwaySeverity(10)).toBe('ok');
    expect(runwaySeverity(6.9)).toBe('warn');
    expect(runwaySeverity(1.9)).toBe('fail');
    expect(runwaySeverity(null)).toBe('ok');
  });
  it('worst health', () => {
    expect(worstHealth(['ok', 'degraded', 'ok'])).toBe('degraded');
    expect(worstHealth(['ok', 'fail', 'degraded'])).toBe('fail');
    expect(worstHealth([])).toBe('unknown');
  });
});
