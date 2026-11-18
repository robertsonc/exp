import { nowMs as clockNow } from "./time";
// Prefixed ULIDs (01-contracts.md section 1): 26 chars, Crockford base32, time-ordered.
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

let lastMs = -1;
let lastRand: number[] = [];

function randomDigits(): number[] {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b & 31);
}

export function newUlid(nowMs: number = clockNow()): string {
  let rand: number[];
  if (nowMs > lastMs) {
    rand = randomDigits();
  } else {
    // same millisecond (or clock stepped back): increment so ids stay strictly monotonic per isolate
    rand = lastRand.slice();
    for (let i = rand.length - 1; i >= 0; i--) {
      if ((rand[i] as number) < 31) {
        rand[i] = (rand[i] as number) + 1;
        break;
      }
      rand[i] = 0;
    }
    nowMs = lastMs;
  }
  lastMs = nowMs;
  lastRand = rand;
  let t = "";
  let ms = nowMs;
  for (let i = 0; i < 10; i++) {
    t = CROCKFORD[ms % 32] + t;
    ms = Math.floor(ms / 32);
  }
  return t + rand.map((d) => CROCKFORD[d]).join("");
}

export const ID_PREFIXES = ["h_", "cmp_", "rel_", "art_", "usr_", "noc_", "drl_", "run_", "evt_", "act_", "wh_", "sec_", "iss_"] as const;
export type IdPrefix = (typeof ID_PREFIXES)[number];

export function newId(prefix: IdPrefix): string {
  return prefix + newUlid();
}

export const HOST_ID_RE = /^h_[0-9A-HJKMNP-TV-Z]{26}$/;
export const COMPONENT_ID_RE = /^cmp_[0-9A-HJKMNP-TV-Z]{26}$/;
export const ARTIFACT_ID_RE = /^art_[0-9A-HJKMNP-TV-Z]{26}$/;
export const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
export const SEMVER_RE = /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$/;
export const ISSUE_ID_RE = /^iss_[0-9A-HJKMNP-TV-Z]{26}$/;
export const REL_ID_RE = /^rel_[0-9A-HJKMNP-TV-Z]{26}$/;
export const USR_ID_RE = /^usr_[0-9A-HJKMNP-TV-Z]{26}$/;
export const NOC_ID_RE = /^noc_[0-9A-HJKMNP-TV-Z]{26}$/;

/** Milliseconds encoded in the first 10 Crockford characters of a prefixed ULID (null when malformed). */
export function ulidTimeMs(id: string): number | null {
  const body = id.includes("_") ? id.slice(id.indexOf("_") + 1) : id;
  if (body.length !== 26) return null;
  let ms = 0;
  for (let i = 0; i < 10; i++) {
    const v = CROCKFORD.indexOf(body[i] as string);
    if (v < 0) return null;
    ms = ms * 32 + v;
  }
  return ms;
}
