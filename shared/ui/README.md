# shared/ui - exp design tokens

HPE design language (derived from `reference/netvitals/DESIGN.md`): cool charcoal ground, flat panels,
HPE green `#01A982` only for OK state and primary actions, amber/red for faults. No gradients, glass blur,
violet accents or emoji icons. No external fonts or CDNs: system font stacks only, so on-prem dashboards
work offline.

## Files
- `tokens.css` - CSS custom properties on `:root` (all prefixed `--exp-`). Load first.
- `base.css` - small reset; body background/foreground from tokens; `:focus-visible` ring; reduced motion.
- `icons/*.svg` - 24x24 stroke icons using `currentColor`: network dhcp dns internet apps wifi path probe
  collector dashboard runner host site alert check x clock rewind settings user key release drill link.

## Themes
Dark follows the OS (`prefers-color-scheme`). Force with `<html data-theme="dark">` or `data-theme="light"`.
The dashboard (wall screen) defaults to dark.

## Token groups
| Group | Tokens |
|---|---|
| Surfaces | `--exp-bg`, `--exp-bg-elev`, `--exp-surface`, `--exp-surface-2`, `--exp-stroke` |
| Text | `--exp-text`, `--exp-text-dim`, `--exp-text-faint` |
| Brand | `--exp-accent` (primary action), `--exp-accent-hi`, `--exp-on-accent` (text on accent), `--exp-green*` |
| State | `--exp-ok`, `--exp-warn`, `--exp-fail`, `--exp-unknown` plus `*-bg` tints. Never rely on color alone: pair with an icon (`check`, `alert`, `x`, `clock`) or label. |
| Lines | `--exp-line-network|dhcp|dns|internet|apps|wifi` (chart series / line identity) |
| Type | `--exp-font-ui`, `--exp-font-mono`, compact `--exp-text-xs..xl`, wall-screen `--exp-wall-label|body|title|meter` |
| Space/shape | `--exp-space-1..7`, `--exp-radius-sm|md|pill`, `--exp-shadow-1|2` |
| Focus/motion | `--exp-focus-ring`, `--exp-ease`, `--exp-dur-fast|dur|dur-slow` (0ms under reduced motion) |

## Usage
```html
<link rel="stylesheet" href="tokens.css"><link rel="stylesheet" href="base.css">
<button style="background:var(--exp-accent);color:var(--exp-on-accent);border-radius:var(--exp-radius-sm)">Deploy</button>
<span style="color:var(--exp-ok)">OK</span>
```
- Dashboard (stdlib-served, offline): copy/inline these files into its static assets at build time; use the
  `--exp-wall-*` sizes for room-readable meters and labels.
- Manager UI: import `tokens.css` and `base.css` in the app entry; inline icons by fetching/bundling the SVGs
  (they inherit `color` via `currentColor`; set size with CSS `width`/`height`).
- Primary button: green fill, dark text (`--exp-on-accent`). Secondary: flat `--exp-surface` + `--exp-stroke`.
