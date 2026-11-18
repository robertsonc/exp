// UTC ISO-8601 with ms and Z (01-contracts.md section 1). `now` is injectable for tests via setClock.
let clock: () => number = () => Date.now();

export function setClock(fn: (() => number) | null): void {
  clock = fn ?? (() => Date.now());
}
export const nowMs = (): number => clock();
export const isoNow = (): string => new Date(clock()).toISOString();
export const isoAt = (ms: number): string => new Date(ms).toISOString();
export const isoPlusSeconds = (s: number): string => new Date(clock() + s * 1000).toISOString();
