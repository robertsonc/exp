import type { ComponentChildren, JSX } from 'preact';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Glyph } from './Icon';

export interface Column<T> {
  id: string;
  header: string;
  /** CSS width, e.g. "9rem". */
  width?: string;
  sortable?: boolean;
  align?: 'right';
  cell: (row: T) => ComponentChildren;
}

export interface SortState { key: string; dir: 'asc' | 'desc' }

/** Which rows to render for a scroll position (pure; unit tested). */
export function visibleRange(scrollTop: number, viewH: number, rowH: number, total: number, overscan = 6): [number, number] {
  if (total <= 0 || rowH <= 0) return [0, 0];
  const last = Math.min(total, Math.ceil((scrollTop + viewH) / rowH) + overscan);
  const first = Math.min(last, Math.max(0, Math.floor(scrollTop / rowH) - overscan));
  return [first, last];
}

export function useMedia(query: string): boolean {
  const get = () => {
    try {
      return window.matchMedia(query).matches;
    } catch {
      return false;
    }
  };
  const [m, setM] = useState(get);
  useEffect(() => {
    let mq: MediaQueryList;
    try {
      mq = window.matchMedia(query);
    } catch {
      return undefined;
    }
    const l = () => setM(mq.matches);
    mq.addEventListener('change', l);
    l();
    return () => mq.removeEventListener('change', l);
  }, [query]);
  return m;
}

interface Props<T> {
  rows: readonly T[];
  columns: readonly Column<T>[];
  rowKey: (r: T) => string;
  label: string;
  sort?: SortState;
  onSort?: (key: string) => void;
  rowClass?: (r: T) => string;
  rowHeight?: number;
  cardHeight?: number;
  viewHeight?: number;
  card?: (r: T) => ComponentChildren;
  /** Below this width (px) render the card list. */
  cardBelow?: number;
  onActivate?: (r: T) => void;
  empty?: ComponentChildren;
}

/** Virtualised data table with sortable headers and keyboard navigation; below 768 px a card list. */
export function VirtualTable<T>(p: Props<T>): JSX.Element {
  const { rows, columns, rowKey, label, sort, onSort, rowClass, card, onActivate } = p;
  const cards = useMedia(`(max-width: ${(p.cardBelow ?? 768) - 1}px)`) && !!card;
  const rowH = cards ? (p.cardHeight ?? 128) : (p.rowHeight ?? 44);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewH, setViewH] = useState(p.viewHeight ?? 560);
  const [cursor, setCursor] = useState(-1);
  const box = useRef<HTMLDivElement>(null);
  const raf = useRef(0);

  useLayoutEffect(() => {
    const el = box.current;
    if (!el) return undefined;
    const measure = () => setViewH(el.clientHeight || p.viewHeight || 560);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [cards, p.viewHeight]);

  const onScroll = () => {
    if (raf.current) return;
    raf.current = requestAnimationFrame(() => {
      raf.current = 0;
      if (box.current) setScrollTop(box.current.scrollTop);
    });
  };

  const [first, last] = useMemo(() => visibleRange(scrollTop, viewH, rowH, rows.length), [scrollTop, viewH, rowH, rows.length]);

  const headH = cards ? 0 : 38;
  const reveal = (i: number) => {
    const el = box.current;
    if (!el) return;
    const top = i * rowH;
    if (top < el.scrollTop) el.scrollTop = top;
    else if (top + rowH > el.scrollTop + viewH - headH) el.scrollTop = top + rowH - viewH + headH;
    setScrollTop(el.scrollTop);
  };

  const onKey = (e: KeyboardEvent) => {
    if ((e.target as HTMLElement).closest('button, input, select, textarea')) return;
    const page = Math.max(1, Math.floor(viewH / rowH) - 1);
    let n = cursor;
    if (e.key === 'ArrowDown') n = Math.min(rows.length - 1, cursor + 1);
    else if (e.key === 'ArrowUp') n = Math.max(0, cursor - 1);
    else if (e.key === 'PageDown') n = Math.min(rows.length - 1, cursor + page);
    else if (e.key === 'PageUp') n = Math.max(0, cursor - page);
    else if (e.key === 'Home') n = 0;
    else if (e.key === 'End') n = rows.length - 1;
    else if (e.key === 'Enter' && cursor >= 0 && onActivate && e.target === box.current) {
      const r = rows[cursor];
      if (r) onActivate(r);
      return;
    } else return;
    if (e.target !== box.current && !(e.target as HTMLElement).closest('a')) return;
    e.preventDefault();
    setCursor(n);
    reveal(n);
    box.current?.focus({ preventScroll: true });
  };

  useEffect(() => {
    if (cursor >= rows.length) setCursor(rows.length - 1);
  }, [rows.length, cursor]);

  if (rows.length === 0) return <div class="vt-empty">{p.empty ?? 'Nothing to show.'}</div>;

  const slice = rows.slice(first, last);
  const topPad = first * rowH;
  const botPad = Math.max(0, (rows.length - last) * rowH);
  const hintId = `vt-hint-${label.replace(/\W+/g, '-')}`;

  return (
    <div class="vt">
      <div
        ref={box} class={`vt-scroll${cards ? ' vt-cards' : ''}`} tabIndex={0} onScroll={onScroll} onKeyDown={onKey}
        role="region" aria-label={label} aria-describedby={hintId} data-rows={rows.length} data-rendered={slice.length}
        style={{ maxHeight: `${p.viewHeight ?? 600}px` }}
      >
        <span id={hintId} class="sr-only">{rows.length} rows. Use the arrow keys to move between rows and Enter to open one.</span>
        {cards ? (
          <ul class="card-list" style={{ paddingTop: `${topPad}px`, paddingBottom: `${botPad}px` }}>
            {slice.map((r, i) => (
              <li key={rowKey(r)} class={`vt-card${rowClass ? ` ${rowClass(r)}` : ''}${first + i === cursor ? ' vt-cursor' : ''}`} style={{ height: `${rowH}px` }}>
                {card?.(r)}
              </li>
            ))}
          </ul>
        ) : (
          <table class="vt-table" aria-rowcount={rows.length + 1}>
            <thead>
              <tr>
                {columns.map((c) => {
                  const sorted = sort?.key === c.id;
                  const ariaSort = sorted ? (sort?.dir === 'asc' ? 'ascending' : 'descending') : c.sortable ? 'none' : undefined;
                  return (
                    <th key={c.id} scope="col" aria-sort={ariaSort} class={c.align === 'right' ? 'num' : ''} style={c.width ? { width: c.width } : undefined}>
                      {c.sortable && onSort ? (
                        <button type="button" class="th-btn" onClick={() => onSort(c.id)}>
                          {c.header}
                          {sorted ? <Glyph name={sort?.dir === 'asc' ? 'sortUp' : 'sortDown'} size={12} /> : null}
                        </button>
                      ) : c.header}
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {topPad > 0 ? <tr aria-hidden="true" class="vt-pad" style={{ height: `${topPad}px` }}><td colSpan={columns.length} /></tr> : null}
              {slice.map((r, i) => (
                <tr key={rowKey(r)} aria-rowindex={first + i + 2} class={`${rowClass ? rowClass(r) : ''}${first + i === cursor ? ' vt-cursor' : ''}`} style={{ height: `${rowH}px` }}
                  aria-current={first + i === cursor ? 'true' : undefined} onClick={() => setCursor(first + i)}>
                  {columns.map((c) => <td key={c.id} class={c.align === 'right' ? 'num' : ''}>{c.cell(r)}</td>)}
                </tr>
              ))}
              {botPad > 0 ? <tr aria-hidden="true" class="vt-pad" style={{ height: `${botPad}px` }}><td colSpan={columns.length} /></tr> : null}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
