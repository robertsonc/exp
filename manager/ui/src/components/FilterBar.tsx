import type { ComponentChildren, JSX } from 'preact';

export interface FilterDef { id: string; label: string; value: string; options: { value: string; label: string }[] }

/** Filter chips: one labelled select per dimension, values live in the URL query string. */
export function FilterBar({ filters, onChange, onClear, children }: {
  filters: FilterDef[]; onChange: (id: string, value: string) => void; onClear?: () => void; children?: ComponentChildren;
}): JSX.Element {
  const active = filters.some((f) => f.value);
  return (
    <div class="filterbar" role="group" aria-label="Filters">
      {filters.map((f) => (
        <label key={f.id} class={`chip${f.value ? ' chip-on' : ''}`}>
          <span class="chip-label">{f.label}</span>
          <select value={f.value} aria-label={f.label} onChange={(e) => onChange(f.id, (e.currentTarget as HTMLSelectElement).value)}>
            <option value="">All</option>
            {f.options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </label>
      ))}
      {children}
      {active && onClear ? <button type="button" class="btn btn-sm btn-ghost" onClick={onClear}>Clear filters</button> : null}
    </div>
  );
}
