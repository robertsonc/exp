// Workers Rate Limiting bindings (05-manager.md section 1). Fails open only if the binding is absent
// (local dev without the binding); in production the bindings always exist.
import type { RateLimiter } from "./env";
import { rateLimited } from "./errors";

export async function enforce(rl: RateLimiter | undefined, key: string, retryAfter = 60): Promise<void> {
  if (!rl) return;
  const { success } = await rl.limit({ key });
  if (!success) throw rateLimited(retryAfter);
}

/** Non-throwing variant: true when the request is allowed. */
export async function allowed(rl: RateLimiter | undefined, key: string): Promise<boolean> {
  if (!rl) return true;
  return (await rl.limit({ key })).success;
}
