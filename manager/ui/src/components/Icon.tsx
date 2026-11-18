import type { JSX } from 'preact';
import { own } from '../lib/own';

// Shared icons (shared/ui/icons/*.svg) are drawn as CSS masks over currentColor, so no markup is ever
// injected: the SVG files are bundled as URLs by Vite and set as `mask-image`.
const files = import.meta.glob('@shared/icons/*.svg', { query: '?url', import: 'default', eager: true }) as Record<string, string>;
const urls: Record<string, string> = {};
for (const [p, u] of Object.entries(files)) {
  const name = /([^/]+)\.svg$/.exec(p)?.[1];
  if (name) urls[name] = u;
}

export type IconName =
  | 'network' | 'dhcp' | 'dns' | 'internet' | 'apps' | 'wifi' | 'path' | 'probe' | 'collector' | 'dashboard'
  | 'runner' | 'host' | 'site' | 'alert' | 'check' | 'x' | 'clock' | 'rewind' | 'settings' | 'user' | 'key'
  | 'release' | 'drill' | 'link';

export function Icon({ name, size = 16, label }: { name: IconName; size?: number; label?: string }): JSX.Element {
  const u = urls[name];
  const style: JSX.CSSProperties = { width: `${size}px`, height: `${size}px` };
  if (u) {
    style.maskImage = `url("${u}")`;
    style.webkitMaskImage = `url("${u}")`;
  }
  return <span class="icon" style={style} role={label ? 'img' : undefined} aria-label={label} aria-hidden={label ? undefined : 'true'} />;
}

// UI-only glyphs that the shared set does not contain (24x24, stroke currentColor).
const GLYPHS: Record<string, string[]> = {
  search: ['M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z', 'M20 20l-4-4'],
  sun: ['M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z', 'M12 2v2M12 20v2M4 12H2M22 12h-2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19'],
  moon: ['M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z'],
  menu: ['M4 6h16M4 12h16M4 18h16'],
  chevron: ['M6 9l6 6 6-6'],
  chevronRight: ['M9 6l6 6-6 6'],
  download: ['M12 4v11M7 11l5 5 5-5', 'M5 20h14'],
  copy: ['M9 9h10v11H9z', 'M5 15V4h10'],
  bookmark: ['M6 3h12v18l-6-4-6 4z'],
  columns: ['M4 4h16v16H4z', 'M9 4v16M15 4v16'],
  sortUp: ['M7 14l5-5 5 5'],
  sortDown: ['M7 10l5 5 5-5'],
  external: ['M14 4h6v6', 'M20 4l-9 9', 'M18 14v6H4V6h6'],
  refresh: ['M20 11a8 8 0 1 0-2.3 5.7', 'M20 4v7h-7'],
};

export function Glyph({ name, size = 16 }: { name: keyof typeof GLYPHS | string; size?: number }): JSX.Element {
  const paths = own(GLYPHS, name) ?? [];
  return (
    <svg class="glyph" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
      stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      {paths.map((d) => <path key={d} d={d} />)}
    </svg>
  );
}
