// Regenerates public/favicon.ico from the same geometry as public/favicon.svg.
//
//   node tools/make-favicon.mjs
//
// ## Why this exists rather than an image library
//
// The .ico is only needed because browsers probe `/favicon.ico` directly, ignoring the
// `<link rel="icon">` that points at the SVG. Keeping it in step with the SVG by hand
// would guarantee they drift, and adding a rasteriser to devDependencies to draw three
// shapes would be a poor trade: a new dependency processing nothing untrusted, for one
// 4 KB file that changes when the brand does.
//
// So the geometry below is declared once, rasterised with supersampled coverage, and
// encoded as PNG-in-ICO using only `node:zlib`. If the SVG changes, change the constants
// here to match and re-run. The shapes are simple enough that this stays honest; anything
// more elaborate belongs in a real design tool, exported as a bitmap.

import { deflateSync } from 'node:zlib';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// ---- Geometry, on the SVG's 32-unit grid --------------------------------

const BACKGROUND = [0x0b, 0x11, 0x20];
const ACCENT = [0x60, 0xa5, 0xfa];

/** Corner radius of the full-bleed background, in grid units. */
const CORNER_RADIUS = 7;

/** The shield outline, as the SVG path's points plus sampled bottom curves. */
function shieldPolygon() {
  const points = [
    [16, 4],
    [26.5, 7.8],
    [26.5, 16.2],
  ];

  // Right flank: cubic from (26.5,16.2) to (16,28.8), matching the SVG's curve.
  const right = cubic([26.5, 16.2], [26.5, 23.2], [22.2, 26.9], [16, 28.8]);
  points.push(...right);

  // The shield is symmetric, so the left flank is the right one mirrored about x=16,
  // walked back up. Mirroring rather than restating it is what keeps the two sides
  // identical when the curve is adjusted.
  for (let i = right.length - 1; i >= 0; i -= 1) {
    const [x, y] = right[i];
    points.push([32 - x, y]);
  }
  points.push([5.5, 16.2], [5.5, 7.8]);

  return points;
}

function cubic(p0, p1, p2, p3, steps = 24) {
  const out = [];
  for (let i = 1; i <= steps; i += 1) {
    const t = i / steps;
    const u = 1 - t;
    out.push([
      u * u * u * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * p3[0],
      u * u * u * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * p3[1],
    ]);
  }
  return out;
}

/** The check mark, as two round-capped segments and a half-width. */
const CHECK = {
  segments: [
    [
      [11.1, 16.3],
      [14.5, 19.8],
    ],
    [
      [14.5, 19.8],
      [21.1, 12.6],
    ],
  ],
  halfWidth: 3.1 / 2,
};

// ---- Rasterising -------------------------------------------------------

function insidePolygon(polygon, x, y) {
  let inside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i, i += 1) {
    const [xi, yi] = polygon[i];
    const [xj, yj] = polygon[j];
    if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) {
      inside = !inside;
    }
  }
  return inside;
}

/** Distance from a point to a segment, which is what gives round caps for free. */
function distanceToSegment([[x1, y1], [x2, y2]], x, y) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const lengthSquared = dx * dx + dy * dy;
  const t =
    lengthSquared === 0
      ? 0
      : Math.max(0, Math.min(1, ((x - x1) * dx + (y - y1) * dy) / lengthSquared));
  return Math.hypot(x - (x1 + t * dx), y - (y1 + t * dy));
}

/** Inside the rounded square that forms the background. */
function insideRoundedSquare(x, y, size, radius) {
  if (x < 0 || y < 0 || x > size || y > size) return false;
  const cx = Math.min(Math.max(x, radius), size - radius);
  const cy = Math.min(Math.max(y, radius), size - radius);
  return Math.hypot(x - cx, y - cy) <= radius || (x === cx && y === cy);
}

/**
 * Renders one square icon as RGBA.
 *
 * Coverage is supersampled rather than computed analytically: 4x4 samples per pixel is
 * enough for shapes this simple, and the alternative is a scanline rasteriser nobody
 * needs to maintain for a favicon.
 */
function render(size) {
  const shield = shieldPolygon();
  const scale = 32 / size;
  const samples = 4;
  const pixels = Buffer.alloc(size * size * 4);

  for (let py = 0; py < size; py += 1) {
    for (let px = 0; px < size; px += 1) {
      let background = 0;
      let shieldCoverage = 0;
      let checkCoverage = 0;

      for (let sy = 0; sy < samples; sy += 1) {
        for (let sx = 0; sx < samples; sx += 1) {
          const x = (px + (sx + 0.5) / samples) * scale;
          const y = (py + (sy + 0.5) / samples) * scale;

          if (insideRoundedSquare(x, y, 32, CORNER_RADIUS)) background += 1;
          if (insidePolygon(shield, x, y)) shieldCoverage += 1;
          if (CHECK.segments.some((s) => distanceToSegment(s, x, y) <= CHECK.halfWidth)) {
            checkCoverage += 1;
          }
        }
      }

      const total = samples * samples;
      const alpha = background / total;
      // Composited in the SVG's order: background, shield, then the check knocked back
      // out of it in the background colour.
      const shieldAmount = Math.max(0, shieldCoverage - checkCoverage) / total;
      const colour = [0, 1, 2].map((c) =>
        Math.round(BACKGROUND[c] * (1 - shieldAmount) + ACCENT[c] * shieldAmount),
      );

      const offset = (py * size + px) * 4;
      pixels[offset] = colour[0];
      pixels[offset + 1] = colour[1];
      pixels[offset + 2] = colour[2];
      pixels[offset + 3] = Math.round(alpha * 255);
    }
  }

  return pixels;
}

// ---- PNG and ICO encoding ----------------------------------------------

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c;
  }
  return table;
})();

function crc32(buffer) {
  let c = 0xffffffff;
  for (const byte of buffer) {
    c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}

function png(size, pixels) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // colour type: RGBA
  // 10..12: deflate, adaptive filtering, no interlace — all zero.

  // One filter byte per scanline. Filter 0 (none): these are tiny and the deflate pass
  // does the work.
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y += 1) {
    raw[y * (size * 4 + 1)] = 0;
    pixels.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/** ICO carrying PNG images, which every browser still in use understands. */
function ico(images) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // type: icon
  header.writeUInt16LE(images.length, 4);

  let offset = 6 + images.length * 16;
  const entries = [];
  for (const { size, data } of images) {
    const entry = Buffer.alloc(16);
    entry[0] = size === 256 ? 0 : size;
    entry[1] = size === 256 ? 0 : size;
    entry[2] = 0; // palette size
    entry[3] = 0; // reserved
    entry.writeUInt16LE(1, 4); // colour planes
    entry.writeUInt16LE(32, 6); // bits per pixel
    entry.writeUInt32LE(data.length, 8);
    entry.writeUInt32LE(offset, 12);
    entries.push(entry);
    offset += data.length;
  }

  return Buffer.concat([header, ...entries, ...images.map((i) => i.data)]);
}

// ---- Main --------------------------------------------------------------

const sizes = [16, 32, 48];
const images = sizes.map((size) => ({ size, data: png(size, render(size)) }));
const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'favicon.ico');

writeFileSync(out, ico(images));
console.log(`favicon.ico written: ${sizes.join(', ')} px, ${ico(images).length} bytes`);
