// Build carp-panel-brief.pptx out of NATIVE PowerPoint objects.
//
//   node build-brief-pptx.mjs            -> carp-panel-brief.pptx
//   node build-brief-pptx.mjs --preview  -> also slides-preview/*.png
//
// Every box, arrow and word is a real PowerPoint shape, so the deck is editable
// in PowerPoint / Google Slides / Keynote. Nothing is a screenshot. (Contrast
// build-pptx.mjs, which renders markdown to JPGs — only useful for mermaid.)
//
// One SPEC drives two emitters: the .pptx, and an HTML preview rendered at
// 120px/inch. The preview exists so layout can be checked without opening
// PowerPoint — if a box hangs off the slide, it hangs off the PNG too.
import PptxGenJS from 'pptxgenjs';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

// ------------------------------------------------------------------- palette

const INK = '12161F';
const MUTED = '5B6472';
const FAINT = '9AA2B0';
const ACCENT = '1A56DB';
const RULE = 'DDE2EA';
const SOFT = 'F5F7FA';
const WASH = 'EDF2FD';
const GO = '157F4A';
const GO_BG = 'E9F5EE';
const WARN = 'B45309';
const WARN_BG = 'FDF4E6';
const STOP = 'B42318';
const STOP_BG = 'FCEDEB';
const WHITE = 'FFFFFF';

const FONT = 'Segoe UI';
const MONO = 'Consolas';

// ------------------------------------------------------------------- canvas

const W = 13.333;
const H = 7.5;
const M = 0.62;            // side margin
const CW = W - 2 * M;      // content width
const FOOT = 0.1;          // accent rule at the bottom

// ---------------------------------------------------------------- spec model
// Elements are plain objects so both emitters read the same numbers.

const slides = [];
function deck(fn) {
  const els = [];
  const s = {
    rect: (o) => (els.push({ k: 'rect', ...o }), s),
    box: (o) => (els.push({ k: 'box', r: 0.07, ...o }), s),
    pill: (o) => (els.push({ k: 'box', r: 0.5, ...o }), s),
    line: (o) => (els.push({ k: 'line', ...o }), s),
    t: (str, o) => (els.push({ k: 'text', str, ...o }), s),
    list: (items, o) => (els.push({ k: 'list', items, ...o }), s),
  };
  fn(s);
  slides.push(els);
}

// Standard title block. Returns the y where content may start.
function head(s, title, kicker) {
  s.t(kicker.toUpperCase(), {
    x: M, y: 0.44, w: CW, h: 0.22, size: 9, bold: true, color: ACCENT, track: 1.6,
  });
  s.t(title, { x: M, y: 0.7, w: CW, h: 0.46, size: 23, bold: true, color: INK });
  return 1.34;
}

// ============================================== slide 1 — system of systems
// Three bands: what is yours, what CERTEN runs, what the ledgers hold. The
// point of the picture is that CERTEN holds no seat and touches no contract.

deck((s) => {
  const y0 = head(s, 'Four systems, one escrow', 'the whole picture');

  const railW = 1.18;             // band label rail
  const bx = M + railW + 0.22;    // where the boxes start
  const bandW = W - M - bx;
  const bh = 1.46;
  const gap = 0.32;
  const bandY = [y0 + 0.26, y0 + 0.26 + bh + gap, y0 + 0.26 + 2 * (bh + gap)];

  // band label rail
  [
    ['YOURS', 'operator + agents', GO],
    ['CERTEN', 'proof + panel', ACCENT],
    ['LEDGERS', 'public record', MUTED],
  ].forEach(([t, d, c], i) => {
    s.rect({ x: M, y: bandY[i], w: 0.05, h: bh, fill: c });
    s.t(t, { x: M + 0.16, y: bandY[i] + 0.3, w: railW, h: 0.3, size: 11, bold: true, color: c, track: 1.4 });
    s.t(d, { x: M + 0.16, y: bandY[i] + 0.62, w: railW, h: 0.44, size: 10, color: MUTED, valign: 'top' });
  });

  // a card inside a band
  const cell = (x, y, w, title, sub, fill, line, color) => {
    s.box({ x, y, w, h: bh, fill, line });
    s.t(title, { x: x + 0.22, y: y + 0.3, w: w - 0.44, h: 0.36, size: 15, bold: true, color });
    s.t(sub, { x: x + 0.22, y: y + 0.74, w: w - 0.44, h: 0.44, size: 11, color: MUTED, valign: 'top' });
  };

  // band 1 — the operator's own things
  const g1 = 0.28;
  const w1 = (bandW - 2 * g1) / 3;
  const col = [bx, bx + w1 + g1, bx + 2 * (w1 + g1)];
  cell(col[0], bandY[0], w1, 'Bryan', 'page-1 key, encrypted on his laptop', GO_BG, GO, GO);
  cell(col[1], bandY[0], w1, 'policy engine + signer', 'page-2 seat · his infra · his key', GO_BG, GO, GO);
  cell(col[2], bandY[0], w1, 'CARP agents', 'DID  →  certen_adi', GO_BG, GO, GO);

  // band 2 — CERTEN
  cell(col[0], bandY[1], w1, 'gateway', 'intent in, proof out', WASH, ACCENT, ACCENT);
  cell(col[1], bandY[1], w1, 'validator fleet', '7 nodes · quorum signs', WASH, ACCENT, ACCENT);
  cell(col[2], bandY[1], w1, 'the panel', 'one book · page 1 / page 2', WASH, ACCENT, ACCENT);

  // band 3 — the two chains
  const g3 = 0.28;
  const w3 = (bandW - g3) / 2;
  cell(bx, bandY[2], w3, 'Accumulate  ·  Kermit', 'ADIs, key book, the pages themselves', SOFT, RULE, INK);
  cell(bx + w3 + g3, bandY[2], w3, 'Ethereum Sepolia', 'escrobot — untouched, admin = the panel', SOFT, RULE, INK);

  // flow between the bands
  col.forEach((x) => {
    s.line({ x: x + w1 / 2, y: bandY[0] + bh + 0.04, dy: gap - 0.08, color: MUTED, width: 1.75, arrow: 'end' });
  });
  s.line({ x: col[0] + w1 / 2, y: bandY[1] + bh + 0.04, dy: gap - 0.08, color: MUTED, width: 1.75, arrow: 'end' });
  s.line({ x: col[2] + w1 / 2, y: bandY[1] + bh + 0.04, dy: gap - 0.08, color: MUTED, width: 1.75, arrow: 'end' });

  s.t('intents + signatures', {
    x: bx, y: bandY[0] + bh + 0.02, w: bandW, h: gap - 0.04, size: 10, color: MUTED, align: 'right', valign: 'middle',
  });
  s.t('proof, then execution', {
    x: bx, y: bandY[1] + bh + 0.02, w: bandW, h: gap - 0.04, size: 10, color: MUTED, align: 'right', valign: 'middle',
  });

  s.t('CERTEN holds no seat on either page, and never touches your contract.', {
    x: M, y: H - FOOT - 0.7, w: CW, h: 0.36, size: 14, bold: true, color: ACCENT, align: 'center',
  });
});

// ================================================================== slide 2

deck((s) => {
  const y0 = head(s, 'The Admin Key Is Gone', 'escrobot × CERTEN  ·  live on Ethereum Sepolia');

  // four cards across: three untouched, one moved
  const gap = 0.2;
  const cw = (CW - 3 * gap) / 4;
  const ch = 1.32;
  const cy = y0 + 0.22;

  ['The escrow contract', 'forceResolve logic', 'isAdmin'].forEach((label, i) => {
    const x = M + i * (cw + gap);
    s.box({ x, y: cy, w: cw, h: ch, fill: SOFT, line: RULE });
    s.t(label, { x: x + 0.2, y: cy + 0.26, w: cw - 0.4, h: 0.32, size: 13.5, bold: true });
    s.t('UNTOUCHED', { x: x + 0.2, y: cy + 0.74, w: cw - 0.4, h: 0.26, size: 9.5, bold: true, color: GO, track: 1.2 });
  });

  const mx = M + 3 * (cw + gap);
  s.box({ x: mx, y: cy, w: cw, h: ch, fill: WASH, line: ACCENT });
  s.t('The admin address', { x: mx + 0.2, y: cy + 0.26, w: cw - 0.4, h: 0.32, size: 13.5, bold: true, color: ACCENT });
  s.t('MOVED', { x: mx + 0.2, y: cy + 0.74, w: cw - 0.4, h: 0.26, size: 9.5, bold: true, color: ACCENT, track: 1.2 });

  s.line({ x: mx + cw / 2, y: cy + ch + 0.06, dy: 0.5, color: ACCENT, width: 2, arrow: 'end' });

  // the panel it now points at
  const py = cy + ch + 0.64;
  s.box({ x: M, y: py, w: CW, h: 0.98, fill: WHITE, line: ACCENT });
  s.rect({ x: M, y: py, w: 0.06, h: 0.98, fill: ACCENT });
  s.t('escrobot.admin()  =  0x895b28715FA81F6F4d6994cDda4e5323cC07F9f3', {
    x: M + 0.3, y: py, w: CW - 0.6, h: 0.98, size: 13.5, bold: true, color: ACCENT, face: MONO, valign: 'middle',
  });

  // two seats behind it
  const sy = py + 1.28;
  const sw = (CW - 0.34) / 2;
  s.line({ x: M + sw / 2, y: py + 1.02, dy: 0.2, color: ACCENT, width: 1.5, arrow: 'end' });
  s.line({ x: M + sw + 0.34 + sw / 2, y: py + 1.02, dy: 0.2, color: ACCENT, width: 1.5, arrow: 'end' });

  s.box({ x: M, y: sy, w: sw, h: 1.34, fill: WASH, line: ACCENT });
  s.t('PAGE 1', { x: M + 0.28, y: sy + 0.2, w: 2, h: 0.28, size: 10, bold: true, color: ACCENT, track: 1.4 });
  s.t('you', { x: M + 0.28, y: sy + 0.58, w: 2.4, h: 0.5, size: 24, bold: true });
  s.t('escalation only', { x: M + sw - 2.5, y: sy + 0.58, w: 2.22, h: 0.5, size: 13, color: MUTED, align: 'right', valign: 'middle' });

  const bx = M + sw + 0.34;
  s.box({ x: bx, y: sy, w: sw, h: 1.34, fill: SOFT, line: RULE });
  s.t('PAGE 2', { x: bx + 0.28, y: sy + 0.2, w: 2, h: 0.28, size: 10, bold: true, color: MUTED, track: 1.4 });
  s.t('agent + policy', { x: bx + 0.28, y: sy + 0.58, w: 3.6, h: 0.5, size: 24, bold: true });
  s.t('routine settlement', { x: bx + sw - 2.5, y: sy + 0.58, w: 2.22, h: 0.5, size: 13, color: MUTED, align: 'right', valign: 'middle' });

  s.t('One address. Two levels of authority.', {
    x: M, y: sy + 1.56, w: CW, h: 0.34, size: 14, color: MUTED, align: 'center',
  });
});

// ================================================================== slide 3

deck((s) => {
  const y0 = head(s, 'Routine below. You above.', 'the shape');

  const bx = M + 0.24;          // pages start right of the book spine
  const bw = 7.5;
  const ph = 1.85;
  const p1y = y0 + 0.5;
  const p2y = p1y + ph + 0.78;

  s.rect({ x: M, y: p1y, w: 0.07, h: p2y + ph - p1y, fill: ACCENT });
  s.t('acc://panel.acme/book', { x: M, y: p1y - 0.34, w: 4, h: 0.26, size: 10.5, bold: true, color: ACCENT, face: MONO });

  // PAGE 1
  s.box({ x: bx, y: p1y, w: bw, h: ph, fill: WASH, line: ACCENT });
  s.t('PAGE 1', { x: bx + 0.3, y: p1y + 0.24, w: 1.2, h: 0.28, size: 10.5, bold: true, color: ACCENT, track: 1.4 });
  s.pill({ x: bx + 1.56, y: p1y + 0.2, w: 1.6, h: 0.32, fill: ACCENT, line: ACCENT });
  s.t('HIGHER PRIORITY', { x: bx + 1.56, y: p1y + 0.2, w: 1.6, h: 0.32, size: 8.5, bold: true, color: WHITE, align: 'center', valign: 'middle' });
  s.t('you', { x: bx + 0.3, y: p1y + 0.76, w: 2.4, h: 0.56, size: 27, bold: true });
  s.t('1-of-1  ·  escalation only', { x: bx + 0.3, y: p1y + 1.42, w: 3.6, h: 0.3, size: 12.5, color: MUTED });

  // PAGE 2
  s.box({ x: bx, y: p2y, w: bw, h: ph, fill: SOFT, line: RULE });
  s.t('PAGE 2', { x: bx + 0.3, y: p2y + 0.24, w: 1.2, h: 0.28, size: 10.5, bold: true, color: MUTED, track: 1.4 });
  s.pill({ x: bx + 1.56, y: p2y + 0.2, w: 1.6, h: 0.32, fill: WHITE, line: MUTED });
  s.t('LOWER PRIORITY', { x: bx + 1.56, y: p2y + 0.2, w: 1.6, h: 0.32, size: 8.5, bold: true, color: MUTED, align: 'center', valign: 'middle' });
  s.t('agent + policy', { x: bx + 0.3, y: p2y + 0.76, w: 4.2, h: 0.56, size: 27, bold: true });
  s.t('2-of-2  ·  routine settlement', { x: bx + 0.3, y: p2y + 1.42, w: 3.6, h: 0.3, size: 12.5, color: MUTED });

  // the one-way relationship, drawn in the gap between the pages
  const gy = p1y + ph;
  const ax = bx + 4.7;
  s.line({ x: ax, y: gy + 0.14, dy: 0.57, color: GO, width: 2, arrow: 'end' });
  s.t('rewrites', { x: ax + 0.14, y: gy + 0.26, w: 1.2, h: 0.32, size: 11, bold: true, color: GO, valign: 'middle' });

  const nx = bx + 6.7;
  s.line({ x: nx, y: gy + 0.14, dy: 0.57, color: STOP, width: 2, dash: 'dash', arrow: 'start' });
  s.t('cannot', { x: nx - 1.5, y: gy + 0.26, w: 1.34, h: 0.32, size: 11, bold: true, color: STOP, align: 'right', valign: 'middle' });

  // right rail
  const rx = bx + bw + 0.5;
  const rw = W - rx - M;
  [
    ['Either page acts alone', 'authority sits at book level'],
    ['Priority runs one way', 'only equal-or-higher may modify'],
    ['A bad seat is replaceable', 'it can never replace you'],
  ].forEach(([t, d], i) => {
    const y = p1y + 0.1 + i * 1.62;
    s.rect({ x: rx, y, w: 0.05, h: 1.06, fill: ACCENT });
    s.t(t, { x: rx + 0.2, y, w: rw - 0.2, h: 0.34, size: 14, bold: true });
    s.t(d, { x: rx + 0.2, y: y + 0.38, w: rw - 0.2, h: 0.6, size: 12, color: MUTED, valign: 'top' });
  });

  s.t('You are never in the routine path.', {
    x: M, y: H - FOOT - 0.66, w: CW, h: 0.36, size: 15, bold: true, color: ACCENT, align: 'center',
  });
});

// ================================================================== slide 4

deck((s) => {
  const y0 = head(s, 'Routine — settled without you', 'act i');

  // left-to-right flow
  const fy = y0 + 0.3;
  const fh = 1.5;
  const arrowW = 0.42;
  const widths = [2.5, 3.2, 2.5, 2.5];
  const totalArrows = arrowW * (widths.length - 1) + 0.28 * (widths.length - 1);
  const scale = (CW - totalArrows) / widths.reduce((a, b) => a + b, 0);
  const boxes = [
    { t: 'your agent', d: 'proposes', fill: SOFT, line: RULE, color: INK },
    { t: 'your policy engine', d: 'your rules · its own key', fill: WASH, line: ACCENT, color: ACCENT },
    { t: 'page 2', d: '2-of-2 satisfied', fill: GO_BG, line: GO, color: GO },
    { t: 'escrobot', d: 'status 5', fill: SOFT, line: RULE, color: INK },
  ];
  let x = M;
  boxes.forEach((b, i) => {
    const w = widths[i] * scale;
    s.box({ x, y: fy, w, h: fh, fill: b.fill, line: b.line });
    s.t(b.t, { x: x + 0.2, y: fy + 0.34, w: w - 0.4, h: 0.38, size: 16, bold: true, color: b.color });
    s.t(b.d, { x: x + 0.2, y: fy + 0.8, w: w - 0.4, h: 0.44, size: 11.5, color: MUTED, valign: 'top' });
    x += w;
    if (i < boxes.length - 1) {
      s.line({ x: x + 0.14, y: fy + fh / 2, dx: arrowW, color: MUTED, width: 1.75, arrow: 'end' });
      x += arrowW + 0.28;
    }
  });

  // three outcomes
  const oy = fy + fh + 0.62;
  const oh = 2.32;
  const og = 0.26;
  const ow = (CW - 2 * og) / 3;
  [
    { t: 'ROUTINE', v: 'approve', r: 'Settles. You are never told.', c: GO, bg: GO_BG },
    { t: 'OUT OF POLICY', v: 'pending', r: 'Stops. Comes to you.', c: WARN, bg: WARN_BG },
    { t: 'ENGINE OFFLINE', v: 'no answer', r: 'Stops. Silence is not consent.', c: STOP, bg: STOP_BG },
  ].forEach((o, i) => {
    const ox = M + i * (ow + og);
    s.box({ x: ox, y: oy, w: ow, h: oh, fill: o.bg, line: o.c });
    s.t(o.t, { x: ox + 0.24, y: oy + 0.24, w: ow - 0.48, h: 0.28, size: 9.5, bold: true, color: o.c, track: 1.2 });
    s.t(o.v, { x: ox + 0.24, y: oy + 0.72, w: ow - 0.48, h: 0.5, size: 22, bold: true, color: o.c, face: MONO });
    s.t(o.r, { x: ox + 0.24, y: oy + 1.42, w: ow - 0.48, h: 0.7, size: 14, valign: 'top' });
  });

  s.pill({ x: M, y: H - FOOT - 0.62, w: CW, h: 0.44, fill: WASH, line: ACCENT });
  s.t('PROVEN LIVE   ·   0x7ba2eab4…  →  status 5, signed by agent + policy, both on page 2', {
    x: M + 0.32, y: H - FOOT - 0.62, w: CW - 0.64, h: 0.44, size: 11.5, bold: true, color: ACCENT, valign: 'middle',
  });
});

// ================================================================== slide 5

deck((s) => {
  const y0 = head(s, 'Escalation — the only time you appear', 'act ii');

  const my = y0 + 0.3;
  const mh = 2.24;
  const gap = 0.7;
  const cw = (CW - gap) / 2;

  // page 2, stalled at one of two
  s.box({ x: M, y: my, w: cw, h: mh, fill: SOFT, line: WARN, dash: 'dash' });
  s.t('PAGE 2  ·  NEEDS 2', { x: M + 0.26, y: my + 0.22, w: cw - 0.52, h: 0.28, size: 10, bold: true, color: MUTED, track: 1.2 });
  const sw = (cw - 0.74) / 2;
  s.box({ x: M + 0.26, y: my + 0.68, w: sw, h: 0.8, fill: WASH, line: ACCENT });
  s.t('agent  ✓', { x: M + 0.26, y: my + 0.68, w: sw, h: 0.8, size: 14, bold: true, color: ACCENT, align: 'center', valign: 'middle' });
  s.box({ x: M + 0.52 + sw, y: my + 0.68, w: sw, h: 0.8, fill: null, line: FAINT, dash: 'dash' });
  s.t('policy  —', { x: M + 0.52 + sw, y: my + 0.68, w: sw, h: 0.8, size: 14, bold: true, color: FAINT, align: 'center', valign: 'middle' });
  s.t('Half of two. Nothing happens.', { x: M + 0.26, y: my + 1.64, w: cw - 0.52, h: 0.36, size: 14, bold: true, color: WARN });

  // page 1, one signature closes it
  const rx = M + cw + gap;
  s.line({ x: M + cw + 0.12, y: my + mh / 2, dx: gap - 0.24, color: ACCENT, width: 2, arrow: 'end' });
  s.box({ x: rx, y: my, w: cw, h: mh, fill: WASH, line: ACCENT });
  s.t('PAGE 1  ·  NEEDS 1', { x: rx + 0.26, y: my + 0.22, w: cw - 0.52, h: 0.28, size: 10, bold: true, color: ACCENT, track: 1.2 });
  s.box({ x: rx + 0.26, y: my + 0.68, w: sw, h: 0.8, fill: ACCENT, line: ACCENT });
  s.t('you  ✓', { x: rx + 0.26, y: my + 0.68, w: sw, h: 0.8, size: 14, bold: true, color: WHITE, align: 'center', valign: 'middle' });
  s.t('satisfies the book alone', { x: rx + 0.52 + sw, y: my + 0.68, w: sw, h: 0.8, size: 13, color: MUTED, valign: 'middle' });
  s.t('One signature. Status 5.', { x: rx + 0.26, y: my + 1.64, w: cw - 0.52, h: 0.36, size: 14, bold: true, color: ACCENT });

  // the two commands
  const cy = my + mh + 0.52;
  [
    ['certen-approve list', 'what is waiting'],
    ['certen-approve sign <tx>', 'your key, your passphrase'],
  ].forEach(([c, d], i) => {
    const x = M + i * (cw + gap);
    s.box({ x, y: cy, w: cw, h: 1.06, fill: SOFT, line: RULE });
    s.t(c, { x: x + 0.26, y: cy + 0.22, w: cw - 0.52, h: 0.36, size: 16, bold: true, color: ACCENT, face: MONO });
    s.t(d, { x: x + 0.26, y: cy + 0.64, w: cw - 0.52, h: 0.28, size: 12, color: MUTED });
  });

  // fail-closed property
  const gy = cy + 1.06 + 0.34;
  s.box({ x: M, y: gy, w: CW, h: 0.68, fill: GO_BG, line: GO });
  s.t('Encrypted at rest. No daemon holds it — nothing signs for you while you are away.', {
    x: M + 0.3, y: gy, w: CW - 0.6, h: 0.68, size: 13, bold: true, color: GO, valign: 'middle',
  });

  s.pill({ x: M, y: H - FOOT - 0.62, w: CW, h: 0.44, fill: WASH, line: ACCENT });
  s.t('PROVEN LIVE   ·   0xf62eefea…  →  status 5.  Record: you on book/1, agent on book/2', {
    x: M + 0.32, y: H - FOOT - 0.62, w: CW - 0.64, h: 0.44, size: 11.5, bold: true, color: ACCENT, valign: 'middle',
  });
});

// ================================================================== slide 6

deck((s) => {
  const y0 = head(s, 'What this is — and what it isn’t', 'scope');

  const gap = 0.4;
  const cw = (CW - gap) / 2;
  const cy = y0 + 0.3;
  const ch = 3.16;

  s.box({ x: M, y: cy, w: cw, h: ch, fill: GO_BG, line: GO });
  s.t('IS', { x: M + 0.3, y: cy + 0.24, w: 2, h: 0.28, size: 11, bold: true, color: GO, track: 2 });
  s.list([
    'live on Sepolia, panel as admin',
    'routine settled by seats you control',
    'escalation by a key only you hold',
    'a policy engine that fails closed',
    'membership recoverable from above',
    're-checkable on Etherscan',
  ], { x: M + 0.3, y: cy + 0.66, w: cw - 0.6, h: ch - 0.86, size: 13.5, color: INK, bullet: '✓', bulletColor: GO });

  const ix = M + cw + gap;
  s.box({ x: ix, y: cy, w: cw, h: ch, fill: SOFT, line: RULE });
  s.t('ISN’T', { x: ix + 0.3, y: cy + 0.24, w: 2, h: 0.28, size: 11, bold: true, color: MUTED, track: 2 });
  s.list([
    'on mainnet',
    'a change to your contract',
    'a fee path — conservation still holds',
    'a cut for your agent',
  ], { x: ix + 0.3, y: cy + 0.66, w: cw - 0.6, h: ch - 0.86, size: 13.5, color: MUTED, bullet: '×', bulletColor: FAINT });

  // the single trade-off
  const ty = cy + ch + 0.42;
  const th = 1.5;
  s.box({ x: M, y: ty, w: CW, h: th, fill: WASH, line: ACCENT });
  s.rect({ x: M, y: ty, w: 0.06, h: th, fill: ACCENT });
  s.t('ONE PROPERTY TO WEIGH', { x: M + 0.34, y: ty + 0.22, w: CW - 0.68, h: 0.26, size: 9.5, bold: true, color: ACCENT, track: 1.4 });
  s.t('Two compromised seats on page 2 could settle without you.', {
    x: M + 0.34, y: ty + 0.58, w: CW - 0.68, h: 0.36, size: 16, bold: true,
  });
  s.t('Guards: your policy rules, and your power to rewrite page 2.', {
    x: M + 0.34, y: ty + 1.0, w: CW - 0.68, h: 0.34, size: 12.5, color: MUTED,
  });
});

// ============================================================ emitter: PPTX

function emitPptx() {
  const pptx = new PptxGenJS();
  // NOT 'LAYOUT_16x9' — that one is 10 x 5.625in, so 13.333in coordinates land
  // a third of the way off the slide. LAYOUT_WIDE is the 13.333 x 7.5in 16:9
  // that PowerPoint and Google Slides both default to.
  pptx.layout = 'LAYOUT_WIDE';
  pptx.title = 'The Admin Key Is Gone — escrobot x CERTEN';
  pptx.author = 'CERTEN';

  for (const els of slides) {
    const s = pptx.addSlide();
    s.addShape(pptx.ShapeType.rect, { x: 0, y: H - FOOT, w: W, h: FOOT, fill: { color: ACCENT }, line: { width: 0 } });

    for (const e of els) {
      if (e.k === 'rect' || e.k === 'box') {
        s.addShape(e.k === 'rect' ? pptx.ShapeType.rect : pptx.ShapeType.roundRect, {
          x: e.x, y: e.y, w: e.w, h: e.h,
          ...(e.k === 'box' ? { rectRadius: e.r } : {}),
          fill: e.fill ? { color: e.fill } : { type: 'none' },
          line: e.line ? { color: e.line, width: 1, dashType: e.dash || 'solid' } : { width: 0 },
        });
      } else if (e.k === 'line') {
        s.addShape(pptx.ShapeType.line, {
          x: e.x, y: e.y, w: e.dx || 0, h: e.dy || 0,
          line: {
            color: e.color, width: e.width, dashType: e.dash || 'solid',
            ...(e.arrow === 'start' ? { beginArrowType: 'triangle' } : { endArrowType: 'triangle' }),
          },
        });
      } else if (e.k === 'text') {
        s.addText(e.str, {
          x: e.x, y: e.y, w: e.w, h: e.h,
          fontFace: e.face || FONT, fontSize: e.size, bold: !!e.bold, italic: !!e.italic,
          color: e.color || INK, align: e.align || 'left', valign: e.valign || 'top',
          charSpacing: e.track || 0, margin: 0, wrap: true,
        });
      } else if (e.k === 'list') {
        s.addText(
          e.items.map((t) => ({ text: t, options: { bullet: { characterCode: e.bullet === '✓' ? '2713' : '00D7' }, breakLine: true } })),
          {
            x: e.x, y: e.y, w: e.w, h: e.h,
            fontFace: FONT, fontSize: e.size, color: e.color, valign: 'top',
            lineSpacingMultiple: 1.5, margin: 0,
          },
        );
      }
    }
  }
  return pptx.writeFile({ fileName: join(HERE, 'carp-panel-brief.pptx') });
}

// ========================================================== emitter: preview

const PX = 120; // px per inch
const p = (v) => `${(v * PX).toFixed(1)}px`;
const pt = (v) => `${(v * PX / 72).toFixed(1)}px`;
// --debug outlines every text frame, so a box that is too small to hold its
// words is obvious in the PNG.
const FRAME = process.argv.includes('--debug') ? 'outline:1px dashed rgba(255,0,0,.2)' : '';

function previewHtml() {
  const body = slides.map((els) => {
    const parts = [`<div class="foot"></div>`];
    for (const e of els) {
      if (e.k === 'rect' || e.k === 'box') {
        parts.push(`<div style="position:absolute;left:${p(e.x)};top:${p(e.y)};width:${p(e.w)};height:${p(e.h)};
          background:${e.fill ? '#' + e.fill : 'transparent'};
          border:${e.line ? `1px ${e.dash ? 'dashed' : 'solid'} #${e.line}` : 'none'};
          border-radius:${e.k === 'box' ? p(Math.min(e.r * e.h, e.h / 2)) : '0'};box-sizing:border-box"></div>`);
      } else if (e.k === 'line') {
        const horiz = (e.dx || 0) > 0;
        parts.push(`<div style="position:absolute;left:${p(e.x)};top:${p(e.y)};
          width:${horiz ? p(e.dx) : '0'};height:${horiz ? '0' : p(e.dy)};
          border-${horiz ? 'top' : 'left'}:${e.width}px ${e.dash ? 'dashed' : 'solid'} #${e.color}"></div>`);
        const hx = horiz ? e.x + (e.arrow === 'start' ? 0 : e.dx) : e.x;
        const hy = horiz ? e.y : e.y + (e.arrow === 'start' ? 0 : e.dy);
        const rot = horiz ? (e.arrow === 'start' ? 180 : 0) : (e.arrow === 'start' ? 270 : 90);
        parts.push(`<div style="position:absolute;left:${p(hx)};top:${p(hy)};width:0;height:0;
          border-left:9px solid #${e.color};border-top:5px solid transparent;border-bottom:5px solid transparent;
          transform:translate(-50%,-50%) rotate(${rot}deg)"></div>`);
      } else if (e.k === 'text') {
        const jc = { top: 'flex-start', middle: 'center', bottom: 'flex-end' }[e.valign || 'top'];
        parts.push(`<div style="position:absolute;left:${p(e.x)};top:${p(e.y)};width:${p(e.w)};height:${p(e.h)};
          display:flex;flex-direction:column;justify-content:${jc};
          font-family:${e.face === MONO ? 'Consolas,monospace' : '\'Segoe UI\',sans-serif'};
          font-size:${pt(e.size)};font-weight:${e.bold ? 700 : 400};color:#${e.color || INK};
          text-align:${e.align || 'left'};letter-spacing:${(e.track || 0) * 0.75}px;line-height:1.24;
          ${FRAME}">${e.str}</div>`);
      } else if (e.k === 'list') {
        parts.push(`<ul style="position:absolute;left:${p(e.x)};top:${p(e.y)};width:${p(e.w)};height:${p(e.h)};
          margin:0;padding:0;list-style:none;font-family:'Segoe UI',sans-serif;font-size:${pt(e.size)};
          color:#${e.color};line-height:1.5;outline:1px dashed rgba(255,0,0,.14)">
          ${e.items.map((t) => `<li style="margin:0 0 ${p(0.06)} 0"><span style="color:#${e.bulletColor};font-weight:700">${e.bullet}</span>&nbsp;${t}</li>`).join('')}</ul>`);
      }
    }
    return `<div class="slide">${parts.join('')}</div>`;
  }).join('');

  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>
  body{margin:0;background:#fff}
  .slide{position:relative;width:${p(W)};height:${p(H)};background:#fff;overflow:visible}
  .foot{position:absolute;left:0;top:${p(H - FOOT)};width:${p(W)};height:${p(FOOT)};background:#${ACCENT}}
  </style></head><body>${body}</body></html>`;
}

async function emitPreview() {
  const puppeteer = (await import('puppeteer-core')).default;
  const exe = [
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  ].find((x) => existsSync(x));
  if (!exe) throw new Error('no Chrome/Edge to render the preview with');

  const htmlPath = join(HERE, '.brief.preview.html');
  await writeFile(htmlPath, previewHtml(), 'utf8');

  const browser = await puppeteer.launch({ executablePath: exe, headless: 'new', args: ['--no-sandbox', '--hide-scrollbars'] });
  const page = await browser.newPage();
  await page.setViewport({ width: Math.round(W * PX), height: Math.round(H * PX), deviceScaleFactor: 1 });
  await page.goto(pathToFileURL(htmlPath).href, { waitUntil: 'load' });

  const dir = join(HERE, 'slides-preview');
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  const nodes = await page.$$('.slide');
  for (let i = 0; i < nodes.length; i++) {
    await nodes[i].screenshot({ path: join(dir, `brief-${i + 1}.png`) });
  }
  await browser.close();
  await rm(htmlPath, { force: true });
  console.log(`PNG  : ${dir}`);
}

await emitPptx();
console.log(`PPTX : ${join(HERE, 'carp-panel-brief.pptx')}  (${slides.length} slides, native shapes)`);
if (process.argv.includes('--preview')) await emitPreview();
