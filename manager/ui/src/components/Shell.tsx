import type { ComponentChildren, JSX } from 'preact';
import { useCallback, useEffect, useRef, useState } from 'preact/hooks';
import { Icon, Glyph, type IconName } from './Icon';
import { Drawer } from './atoms';
import { Link } from './viz';
import { ep } from '../api/endpoints';
import type { FleetHostRow, FleetSummary, Me, Overview, Settings } from '../api/types';
import { getStore, useConn, useNow, useResource } from '../data/hooks';
import { freshnessLevel } from '../lib/state';
import { formatDuration } from '../lib/format';
import { searchIndex } from '../lib/search';
import { navigate } from '../router';
import { toggleTheme, useTheme } from '../lib/theme';

interface NavDef { to: string; label: string; icon: IconName; match: string[] }
const NAV: NavDef[] = [
  { to: '/fleet', label: 'Fleet', icon: 'network', match: ['/fleet', '/'] },
  { to: '/ops', label: 'Ops', icon: 'wifi', match: ['/ops'] },
  { to: '/issues', label: 'Issues', icon: 'alert', match: ['/issues'] },
  { to: '/hosts', label: 'Hosts', icon: 'host', match: ['/hosts'] },
  { to: '/sites', label: 'Sites', icon: 'site', match: ['/sites'] },
  { to: '/speedtest', label: 'Speedtest', icon: 'internet', match: ['/speedtest'] },
  { to: '/releases', label: 'Releases', icon: 'release', match: ['/releases'] },
  { to: '/dashboards', label: 'Dashboards', icon: 'dashboard', match: ['/dashboards'] },
  { to: '/drills', label: 'Drills', icon: 'drill', match: ['/drills'] },
  { to: '/audit', label: 'Audit', icon: 'rewind', match: ['/audit'] },
  { to: '/settings', label: 'Settings', icon: 'settings', match: ['/settings'] },
];

function isActive(n: NavDef, path: string): boolean {
  return n.match.some((m) => (m === '/' ? path === '/' : path === m || path.startsWith(`${m}/`)));
}

export function NavItem({ item, path, badge, onNavigate }: { item: NavDef; path: string; badge?: number; onNavigate?: () => void }): JSX.Element {
  const active = isActive(item, path);
  return (
    <li>
      <Link to={item.to} class={`nav-item${active ? ' nav-active' : ''}`} aria-current={active ? 'page' : undefined}>
        <span onClick={onNavigate} class="nav-inner">
          <Icon name={item.icon} size={18} />
          <span class="nav-label">{item.label}</span>
          {badge ? <span class="nav-badge" aria-label={`${badge} open`}>{badge}</span> : null}
        </span>
      </Link>
    </li>
  );
}

function NavList({ path, badge, onNavigate }: { path: string; badge: number; onNavigate?: () => void }): JSX.Element {
  return (
    <nav aria-label="Main">
      <ul class="nav-list">
        {NAV.map((n) => <NavItem key={n.to} item={n} path={path} badge={n.to === '/issues' ? badge : undefined} onNavigate={onNavigate} />)}
      </ul>
    </nav>
  );
}

/** "Updated 12 s ago": amber after 90 s, red after 5 min without a successful refresh. */
export function FreshnessIndicator(): JSX.Element {
  const now = useNow();
  useConn();
  const store = getStore();
  const lastOk = store.conn().lastOk;
  const age = lastOk === null ? null : Math.max(0, Math.round((store.clientNow() - lastOk) / 1000));
  const level = freshnessLevel(age);
  const text = age === null ? 'Loading…' : `Updated ${formatDuration(age)} ago`;
  const announce = age === null ? '' : level === 'ok' ? 'Data is current' : level === 'amber' ? 'Data is getting old' : 'Data is out of date';
  void now;
  return (
    <span class={`fresh fresh-${age === null ? 'ok' : level}`} data-level={age === null ? 'loading' : level}>
      <button type="button" class="fresh-btn" onClick={() => void getStore().refreshAll()} aria-label={`${text}. Refresh now`} title="Refresh now">
        <Glyph name="refresh" size={14} />
        <span class="fresh-text" aria-hidden="true">{text}</span>
      </button>
      <span class="sr-only" role="status" aria-live="polite">{announce}</span>
    </span>
  );
}

/** Banners for auth problems and an unreachable manager. */
export function ConnectionBanner(): JSX.Element | null {
  useNow();
  const conn = useConn();
  const store = getStore();
  if (conn.auth === 'unauthorized') {
    return (
      <div class="banner banner-fail conn-banner" role="alert" data-kind="unauthorized">
        <Icon name="key" />
        <span><strong>Your Cloudflare Access session expired.</strong> Reload the page to sign in again; nothing on screen has been lost.</span>
        <button type="button" class="btn btn-sm btn-primary" onClick={() => window.location.reload()}>Reload</button>
      </div>
    );
  }
  if (conn.auth === 'forbidden') {
    return (
      <div class="banner banner-fail conn-banner" role="alert" data-kind="forbidden">
        <Icon name="user" />
        <span><strong>Your account is not an admin of this manager.</strong> Ask an owner to add your email under Settings, then reload.</span>
      </div>
    );
  }
  if (conn.failures > 0) {
    const age = conn.lastOk === null ? null : Math.round((store.clientNow() - conn.lastOk) / 1000);
    const red = freshnessLevel(age) === 'red';
    const retry = conn.nextRetryAt === null ? null : Math.max(0, Math.round((conn.nextRetryAt - store.clientNow()) / 1000));
    return (
      <div class={`banner ${red ? 'banner-fail' : 'banner-warn'} conn-banner`} role="alert" data-kind={red ? 'down' : 'retrying'}>
        <Icon name="alert" />
        <span>
          <strong>Can&rsquo;t reach the manager.</strong>{' '}
          {age === null ? 'No data loaded yet.' : `Showing data from ${formatDuration(age)} ago; it may be out of date.`}
          {retry !== null ? ` Retrying in ${formatDuration(retry)}.` : ''}
        </span>
        <button type="button" class="btn btn-sm" onClick={() => void store.refreshAll()}>Retry now</button>
      </div>
    );
  }
  return null;
}

function GlobalSearch(): JSX.Element {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const wanted = open || q.length > 0;
  const hosts = useResource<{ items: FleetHostRow[] }>(wanted ? ep.hosts : null, { paged: true });
  const ov = useResource<Overview>(wanted ? ep.overview : null);
  const hits = searchIndex(q, hosts.data?.items, ov.data);
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);
  const go = (to: string) => {
    setOpen(false);
    setQ('');
    navigate(to);
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((a) => Math.min(hits.length - 1, a + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(0, a - 1));
    } else if (e.key === 'Enter') {
      const h = hits[active];
      if (h) go(h.to);
    } else if (e.key === 'Escape') {
      setOpen(false);
    }
  };
  const showList = open && q.trim().length > 0;
  return (
    <div class="search" ref={root} role="search">
      <Glyph name="search" size={16} />
      <input
        type="search" class="search-input" placeholder="Search hosts, sites, components" aria-label="Search hosts, sites, components, IPs and ids"
        role="combobox" aria-expanded={showList} aria-controls="search-results" aria-autocomplete="list"
        aria-activedescendant={showList && hits[active] ? `sr-${active}` : undefined}
        value={q} autocomplete="off" spellcheck={false}
        onInput={(e) => { setQ((e.currentTarget as HTMLInputElement).value); setOpen(true); setActive(0); }}
        onFocus={() => setOpen(true)} onKeyDown={onKey}
      />
      {showList ? (
        <ul id="search-results" class="search-results" role="listbox" aria-label="Search results">
          {hits.length === 0 ? <li class="search-none" role="option" aria-selected="false" aria-disabled="true">{hosts.loading ? 'Searching…' : 'No matches'}</li> : null}
          {hits.map((h, i) => (
            <li key={h.to} id={`sr-${i}`} role="option" aria-selected={i === active} class={`search-hit${i === active ? ' search-hit-active' : ''}`}
              onMouseDown={(e) => { e.preventDefault(); go(h.to); }} onMouseEnter={() => setActive(i)}>
              <span class="hit-kind">{h.kind}</span>
              <span class="hit-label">{h.label}</span>
              <span class="hit-detail">{h.detail}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function UserMenu(): JSX.Element {
  const me = useResource<Me>(ep.me);
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return undefined;
    const h = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false);
    };
    const k = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', h);
    window.addEventListener('keydown', k);
    return () => {
      document.removeEventListener('mousedown', h);
      window.removeEventListener('keydown', k);
    };
  }, [open]);
  const email = me.data?.email ?? '…';
  return (
    <div class="usermenu" ref={root}>
      <button type="button" class="btn btn-ghost" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Icon name="user" size={16} /> <span class="user-email">{email}</span> <Glyph name="chevron" size={12} />
      </button>
      {open ? (
        <div class="menu" role="menu" aria-label="Account">
          <div class="menu-info" role="presentation"><strong>{email}</strong><br /><span class="dim">role: {me.data?.role ?? 'unknown'}</span></div>
          <a role="menuitem" class="menu-item" href="/cdn-cgi/access/logout">Sign out</a>
        </div>
      ) : null}
    </div>
  );
}

export function ThemeToggle(): JSX.Element {
  const t = useTheme();
  return (
    <button type="button" class="btn btn-ghost btn-icon" onClick={toggleTheme} aria-label={`Switch to ${t === 'dark' ? 'light' : 'dark'} theme`} title="Toggle theme">
      <Glyph name={t === 'dark' ? 'sun' : 'moon'} size={16} />
    </button>
  );
}

export function AppShell({ path, children }: { path: string; children: ComponentChildren }): JSX.Element {
  const summary = useResource<FleetSummary>(ep.summary);
  const settings = useResource<Settings>(ep.settings);
  const [drawer, setDrawer] = useState(false);
  const closeDrawer = useCallback(() => setDrawer(false), []);
  useEffect(() => setDrawer(false), [path]);
  const open = summary.data ? summary.data.open_issues.warn + summary.data.open_issues.crit : 0;
  const org = typeof settings.data?.org_name === 'string' ? settings.data.org_name : '';
  return (
    <div class="shell">
      <a class="skip" href="#main">Skip to content</a>
      <header class="topbar">
        <button type="button" class="btn btn-ghost btn-icon menu-btn" aria-label="Open navigation" onClick={() => setDrawer(true)}><Glyph name="menu" size={18} /></button>
        <Link to="/fleet" class="brand" aria-label="HPE EXP fleet overview">
          <span class="brand-mark" aria-hidden="true" />
          <span class="brand-name">HPE EXP</span>
        </Link>
        <span class="org" title="Organisation">{org}</span>
        <GlobalSearch />
        <div class="topbar-right">
          <FreshnessIndicator />
          <ThemeToggle />
          <UserMenu />
        </div>
      </header>
      <aside class="sidebar"><NavList path={path} badge={open} /></aside>
      <Drawer open={drawer} onClose={closeDrawer} label="Navigation"><NavList path={path} badge={open} onNavigate={closeDrawer} /></Drawer>
      <main id="main" class="main" tabIndex={-1}>
        <ConnectionBanner />
        {children}
      </main>
    </div>
  );
}
