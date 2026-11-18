import { describe, expect, it } from 'vitest';
import * as f from '../src/lib/format';

describe('formatting rules (11-manager-ui.md section 6)', () => {
  it('rates use SI suffixes for pps', () => {
    expect(f.formatPps(41_200)).toBe('41.2k pps');
    expect(f.formatPps(412)).toBe('412 pps');
    expect(f.formatPps(4.25)).toBe('4.3 pps');
    expect(f.formatPps(1_500_000)).toBe('1.5M pps');
    expect(f.formatPps(null)).toBe('—');
  });
  it('bit rates in kb/s, Mb/s, Gb/s', () => {
    expect(f.formatBps(4_705_433)).toBe('4.7 Mb/s');
    expect(f.formatBps(459_725)).toBe('0.46 Mb/s');
    expect(f.formatBps(2_000_000_000)).toBe('2 Gb/s');
    expect(f.formatBps(8_000)).toBe('8 kb/s');
    expect(f.formatMbps(459_725)).toBe('0.46 Mb/s');
    expect(f.formatMbps(12_300_000)).toBe('12 Mb/s');
  });
  it('bytes use binary units', () => {
    expect(f.formatBytes(1024)).toBe('1 KiB');
    expect(f.formatBytes(5 * 1024 ** 3)).toBe('5 GiB');
    expect(f.formatBytes(1536)).toBe('1.5 KiB');
    expect(f.formatGiB(437)).toBe('437 GiB');
    expect(f.formatMiB(32000)).toBe('31 GiB');
  });
  it('percentages are whole numbers, one decimal under 10', () => {
    expect(f.formatPct(45.1)).toBe('45%');
    expect(f.formatPct(9.44)).toBe('9.4%');
    expect(f.formatPct(0)).toBe('0.0%');
    expect(f.formatPct(99.6)).toBe('100%');
    expect(f.formatPct(undefined)).toBe('—');
  });
  it('durations', () => {
    expect(f.formatDuration(45)).toBe('45 s');
    expect(f.formatDuration(12 * 60)).toBe('12 min');
    expect(f.formatDuration(4 * 3600 + 12 * 60)).toBe('4 h 12 min');
    expect(f.formatDuration(4 * 3600)).toBe('4 h');
    expect(f.formatDuration(12 * 86400 + 4 * 3600)).toBe('12 d 4 h');
    expect(f.formatDuration(-1)).toBe('—');
  });
  it('relative and absolute times', () => {
    const now = Date.parse('2026-11-18T12:00:00Z');
    expect(f.formatAgo('2026-11-18T11:59:15Z', now)).toBe('45 s ago');
    expect(f.formatAgo('2026-11-18T11:48:00Z', now)).toBe('12 min ago');
    expect(f.formatAgo('2026-11-18T11:59:59Z', now)).toBe('just now');
    expect(f.formatAgo(null, now)).toBe('—');
    const abs = f.formatAbsolute('2026-11-18T12:00:00Z', 'America/Chicago');
    expect(abs).toContain('06:00:00');
    expect(abs).toContain('12:00:00');
    expect(abs).toContain('UTC');
  });
  it('survives an invalid timezone from untrusted data', () => {
    expect(f.formatAbsolute('2026-11-18T12:00:00Z', 'Not/AZone')).toContain('12:00:00');
  });
  it('days to full', () => {
    expect(f.formatDaysToFull(2)).toBe('2 days to full');
    expect(f.formatDaysToFull(0.5)).toBe('12 h to full');
    expect(f.formatDaysToFull(40.4)).toBe('40 days to full');
    expect(f.formatDaysToFull(null)).toBe('no growth');
  });
});
