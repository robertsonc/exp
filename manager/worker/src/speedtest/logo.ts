// Logo checks (admin.yaml uploadSpeedtestLogo): size bound, magic number against the declared type, and for SVG a
// strict "no active content, no foreign reference" scan. The logo is later served by the speedtest box as an image;
// the page uses it in an <img> (never inlined), but a hostile SVG must not even be stored.

export const LOGO_MAX_BYTES = 256 * 1024;

const PNG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const startsWith = (b: Uint8Array, magic: number[]): boolean => magic.every((m, i) => b[i] === m);

/** null = acceptable, else a refusal reason. */
export function checkLogo(contentType: string, bytes: Uint8Array): string | null {
  if (bytes.length > LOGO_MAX_BYTES) return "the logo exceeds 256 KiB";
  if (contentType === "image/png") return startsWith(bytes, PNG) ? null : "the body is not a PNG image";
  if (contentType === "image/jpeg") return bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff ? null : "the body is not a JPEG image";
  if (contentType === "image/svg+xml") return checkSvg(bytes);
  return "unsupported image type";
}

/** Tags that carry or load active/foreign content. */
const FORBIDDEN_TAG = /<\s*(script|foreignobject|iframe|embed|object|audio|video|link|meta|base|set|animate|animatemotion|animatetransform|handler|listener|a)\b/i;

export function checkSvg(bytes: Uint8Array): string | null {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    return "the SVG is not valid UTF-8";
  }
  if (text.includes("\u0000")) return "the SVG contains a NUL byte";
  const head = text.replace(/^﻿/, "").trimStart();
  if (!/^(<\?xml[^>]*\?>\s*)?(<!--[\s\S]*?-->\s*)*<svg[\s/>]/i.test(head)) return "the body is not an SVG document (it must start with an <svg> element)";
  if (/<!\s*(DOCTYPE|ENTITY)/i.test(text)) return "the SVG must not contain a DOCTYPE or entity declarations";
  if (/<!\[CDATA\[/i.test(text) && /<\s*style/i.test(text)) return "the SVG must not combine CDATA and style";
  if (FORBIDDEN_TAG.test(text)) return "the SVG contains active or foreign content (script, foreignObject, link, animation, ...)";
  if (/\son[a-z]+\s*=/i.test(text)) return "the SVG contains an event handler attribute";
  if (/javascript\s*:|vbscript\s*:|\bdata\s*:/i.test(text)) return "the SVG contains a script or data URL";
  if (/@import/i.test(text)) return "the SVG imports an external stylesheet";
  // the only URL-ish thing allowed is the XML namespace declaration; everything else must stay inside the document
  const withoutNs = text.replace(/\sxmlns(:[A-Za-z][\w.-]*)?\s*=\s*("[^"]*"|'[^']*')/g, "");
  if (/(https?:)?\/\/[A-Za-z0-9[]/.test(withoutNs)) return "the SVG references an external resource";
  for (const m of withoutNs.matchAll(/(?:xlink:)?href\s*=\s*("([^"]*)"|'([^']*)')/gi)) {
    const v = (m[2] ?? m[3] ?? "").trim();
    if (!v.startsWith("#")) return "the SVG has a non-local href";
  }
  for (const m of withoutNs.matchAll(/url\(\s*([^)]*)\)/gi)) {
    const v = (m[1] ?? "").trim().replace(/^["']|["']$/g, "");
    if (!v.startsWith("#")) return "the SVG has a non-local url()";
  }
  return null;
}
