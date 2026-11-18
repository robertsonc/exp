// Opaque cursors: base64url(JSON), bounded and validated on the way in.
import { invalidRequest } from "../errors";

export function encodeCursor(o: unknown): string {
  return btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function decodeCursor<T>(c: string | undefined): T | null {
  if (!c) return null;
  if (c.length > 1024 || !/^[A-Za-z0-9_-]+$/.test(c)) throw invalidRequest("invalid cursor");
  try {
    const pad = c.length % 4 === 0 ? "" : "=".repeat(4 - (c.length % 4));
    return JSON.parse(atob(c.replace(/-/g, "+").replace(/_/g, "/") + pad)) as T;
  } catch {
    throw invalidRequest("invalid cursor");
  }
}

