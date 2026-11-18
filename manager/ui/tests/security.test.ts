import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// Untrusted text (host names, facts, probe labels, error strings) must only ever be rendered as text.
// This grep-based guard fails the build if any source file uses an HTML-injection or code-eval sink.
const src = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const FORBIDDEN: [string, RegExp][] = [
  ['innerHTML', /innerHTML/],
  ['outerHTML', /outerHTML/],
  ['dangerouslySetInnerHTML', /dangerouslySetInnerHTML/],
  ['insertAdjacentHTML', /insertAdjacentHTML/],
  ['document.write', /document\s*\.\s*write/],
  ['eval(', /(^|[^\w.])eval\s*\(/],
  ['new Function', /new\s+Function\s*\(/],
  ['Function(', /(^|[^\w.])Function\s*\(\s*['"`]/],
  ['setTimeout with a string', /set(Timeout|Interval)\s*\(\s*['"`]/],
  ['javascript: URL', /javascript:/i],
  ['createContextualFragment', /createContextualFragment/],
  ['DOMParser', /DOMParser/],
];

function walk(d: string): string[] {
  return readdirSync(d).flatMap((n) => {
    const p = join(d, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

describe('no HTML injection or eval sinks in src', () => {
  const files = walk(src).filter((f) => /\.(ts|tsx|js|jsx|html)$/.test(f));
  it('finds the source files', () => {
    expect(files.length).toBeGreaterThan(20);
  });
  for (const [name, re] of FORBIDDEN) {
    it(`never uses ${name}`, () => {
      const hits = files.filter((f) => re.test(readFileSync(f, 'utf8')));
      expect(hits).toEqual([]);
    });
  }
});
