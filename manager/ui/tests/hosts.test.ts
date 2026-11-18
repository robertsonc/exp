import { describe, expect, it } from 'vitest';
import type { FleetHostRow } from '../src/api/types';
import { applyFilters, hostsCsv, parseFilters, parseSort, sortViews, toViews } from '../src/lib/hosts';
import { csvCell, toCsv } from '../src/lib/csv';

const now = Date.parse('2026-11-18T12:00:00Z');
const row = (o: Partial<FleetHostRow> & { name: string }): FleetHostRow => ({
  host_id: `h_${o.name}`, site: 'hall-b', shapes: ['probe'], state: 'enrolled', stale: false, health: 'ok', open_issues: 0,
  last_seen: new Date(now - 20_000).toISOString(), agent_version: '0.1.1', desired_version: 4, applied_version: 4, ...o,
});
const rows = [
  row({ name: 'b-probe', cpu_pct: 50 }), row({ name: 'a-probe', cpu_pct: 10 }), row({ name: 'c-col', shapes: ['collector'], site: 'hall-c', cpu_pct: null, health: 'fail' }),
  row({ name: 'd-old', state: 'stale', stale: true, cpu_pct: 90, applied_version: 3 }),
];
const views = toViews(rows, now, 1000);

describe('hosts table logic', () => {
  it('filters by site, shape, health, state, drift and free text', () => {
    const q = (s: string) => applyFilters(views, parseFilters(new URLSearchParams(s))).map((v) => v.row.name);
    expect(q('site=hall-c')).toEqual(['c-col']);
    expect(q('shape=collector')).toEqual(['c-col']);
    expect(q('health=fail')).toEqual(['c-col']);
    expect(q('state=stale')).toEqual(['d-old']);
    expect(q('drift=1')).toEqual(['d-old']);
    expect(q('q=A-PR')).toEqual(['a-probe']);
    expect(q('site=hall-b&state=online')).toEqual(['b-probe', 'a-probe']);
  });
  it('sorts ascending and descending with missing values last', () => {
    const s = (k: string, d: 'asc' | 'desc') => sortViews(views, k, d).map((v) => v.row.name);
    expect(s('cpu', 'asc')).toEqual(['a-probe', 'b-probe', 'd-old', 'c-col']);
    expect(s('cpu', 'desc')).toEqual(['d-old', 'b-probe', 'a-probe', 'c-col']);
    expect(s('name', 'desc')).toEqual(['d-old', 'c-col', 'b-probe', 'a-probe']);
  });
  it('parses sort from the query string and rejects unknown keys', () => {
    expect(parseSort('-cpu')).toEqual({ key: 'cpu', dir: 'desc' });
    expect(parseSort('disk')).toEqual({ key: 'disk', dir: 'asc' });
    expect(parseSort('__proto__')).toEqual({ key: 'name', dir: 'asc' });
    expect(parseSort(null)).toEqual({ key: 'name', dir: 'asc' });
  });
  it('sorts 500 rows well under 100 ms', () => {
    const big = toViews(Array.from({ length: 500 }, (_, i) => row({ name: `host-${i}`, cpu_pct: (i * 37) % 100 })), now, 0);
    const t = performance.now();
    sortViews(applyFilters(big, parseFilters(new URLSearchParams('site=hall-b'))), 'cpu', 'desc');
    expect(performance.now() - t).toBeLessThan(100);
  });
  it('exports CSV of the current view', () => {
    const csv = hostsCsv(views.slice(0, 2));
    const lines = csv.trim().split('\r\n');
    expect(lines).toHaveLength(3);
    expect(lines[0]).toContain('name,host_id,mgmt_ip');
    expect(lines[1]).toContain('b-probe');
  });
});

describe('csv', () => {
  it('neutralises spreadsheet formulas in untrusted text', () => {
    expect(csvCell('=HYPERLINK("http://evil")')).toBe('"\'=HYPERLINK(""http://evil"")"');
    expect(csvCell('+1')).toBe("'+1");
    expect(csvCell('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(csvCell('-2+3')).toBe("'-2+3");
    expect(csvCell('plain')).toBe('plain');
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell(null)).toBe('');
    expect(toCsv(['x'], [['=1']])).toBe("x\r\n'=1\r\n");
  });
});
