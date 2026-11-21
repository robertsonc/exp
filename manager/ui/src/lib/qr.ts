// QR codes for the per-zone signage are generated in the browser with `qrcode-generator` 1.4.4 (MIT, Kazuhiko Arase,
// published 2019, pinned with its npm integrity hash in package-lock.json). Decision (CR-m6-manager): a vetted, tiny,
// widely deployed encoder beats a hand-written one that no decoder in this repo could verify. Dev-time dependency of
// the UI bundle only; nothing is fetched at runtime and no server renders an image.
import qrcode from 'qrcode-generator';

export interface QrMatrix { size: number; dark: (r: number, c: number) => boolean }

/** Byte-mode, error-correction level M, smallest version that fits. Throws for text that cannot be encoded. */
export function qrMatrix(text: string): QrMatrix {
  // eslint-disable-next-line no-control-regex
  if (text.length === 0 || text.length > 500 || /[^\x20-\x7e]/.test(text)) throw new Error('QR text must be 1 to 500 printable ASCII characters');
  const qr = qrcode(0, 'M');
  qr.addData(text, 'Byte');
  qr.make();
  return { size: qr.getModuleCount(), dark: (r, c) => qr.isDark(r, c) };
}

/** One SVG path (rectangles per dark run) and the viewBox side, with a 4-module quiet zone. */
export function qrPath(text: string, quiet = 4): { d: string; side: number } {
  const m = qrMatrix(text);
  let d = '';
  for (let r = 0; r < m.size; r += 1) {
    let c = 0;
    while (c < m.size) {
      if (!m.dark(r, c)) { c += 1; continue; }
      let e = c;
      while (e < m.size && m.dark(r, e)) e += 1;
      d += `M${c + quiet} ${r + quiet}h${e - c}v1h${-(e - c)}z`;
      c = e;
    }
  }
  return { d, side: m.size + 2 * quiet };
}
