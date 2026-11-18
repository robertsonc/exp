import { ApiError, invalidRequest } from "../errors";

/** Reads a request body with a hard byte cap (header check first, then the actual stream). */
export async function readLimited(req: Request, maxBytes: number): Promise<Uint8Array> {
  const cl = req.headers.get("content-length");
  if (cl !== null && (!/^\d+$/.test(cl) || Number(cl) > maxBytes)) {
    throw new ApiError(413, "payload_too_large", `body exceeds ${maxBytes} bytes`);
  }
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new ApiError(413, "payload_too_large", `body exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

export async function readJson(req: Request, maxBytes: number): Promise<unknown> {
  const bytes = await readLimited(req, maxBytes);
  if (bytes.length === 0) return undefined;
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    throw invalidRequest("body is not valid JSON");
  }
}
