import { useEffect, useState } from 'preact/hooks';
import { readString, writeString } from './storage';

export type ThemePref = 'system' | 'light' | 'dark';
const KEY = 'exp.ui.theme';
const listeners = new Set<() => void>();

export function getPref(): ThemePref {
  const v = readString(KEY);
  return v === 'light' || v === 'dark' ? v : 'system';
}

export function resolveTheme(pref: ThemePref = getPref()): 'light' | 'dark' {
  if (pref !== 'system') return pref;
  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  } catch {
    return 'light';
  }
}

export function applyTheme(pref: ThemePref = getPref()): void {
  const root = document.documentElement;
  if (pref === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', pref);
  listeners.forEach((l) => l());
}

export function setPref(p: ThemePref): void {
  writeString(KEY, p);
  applyTheme(p);
}

/** Toggle between light and dark based on what is currently shown. */
export function toggleTheme(): void {
  setPref(resolveTheme() === 'dark' ? 'light' : 'dark');
}

export function useTheme(): 'light' | 'dark' {
  const [t, setT] = useState(resolveTheme());
  useEffect(() => {
    const l = () => setT(resolveTheme());
    listeners.add(l);
    let mq: MediaQueryList | null = null;
    try {
      mq = window.matchMedia('(prefers-color-scheme: dark)');
      mq.addEventListener('change', l);
    } catch {
      mq = null;
    }
    return () => {
      listeners.delete(l);
      mq?.removeEventListener('change', l);
    };
  }, []);
  return t;
}
