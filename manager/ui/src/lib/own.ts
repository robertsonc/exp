// Safe own-property lookup: keys that come from the network (issue kinds, shapes, sort keys) must never
// resolve through Object.prototype ("__proto__", "constructor", ...).
export function own<T>(map: Record<string, T>, key: string): T | undefined {
  return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : undefined;
}
