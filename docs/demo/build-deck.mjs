// Build a single self-contained HTML presenter deck from carp-demo-deck.md.
//
// Slides are separated by `---`. Speaker notes are HTML comments beginning
// `NOTE:` — they never render on the slide, and appear in the presenter panel
// (press N).
//
// marked + mermaid are INLINED, so the deck works with no network. That matters:
// a demo laptop on conference wifi should not be able to break the slides.
//
//   node build-deck.mjs        -> carp-demo-deck.html
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const MARKED = 'https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js';
const MERMAID = 'https://cdn.jsdelivr.net/npm/mermaid@10.9.3/dist/mermaid.min.js';

// JSON-encode into a safe inline <script> literal: the whole value becomes one
// JS string, and "</" is neutralized so the browser cannot close our script tag
// early.
const lit = (v) => JSON.stringify(v).replace(/<\//g, '<\\/');

async function fetchText(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} -> HTTP ${r.status}`);
  return r.text();
}

// Shipped to the browser via .toString(); never executed in node, so references
// to browser globals are fine.
function clientMain() {
  const slides = SLIDES;
  let i = 0;
  let notesOpen = false;

  marked.setOptions({ gfm: true, breaks: false });
  mermaid.initialize({
    startOnLoad: false,
    theme: 'dark',
    themeVariables: { fontSize: '15px' },
    securityLevel: 'loose',
    flowchart: { useMaxWidth: true, htmlLabels: true },
    sequence: { useMaxWidth: true },
  });

  const stage = document.getElementById('stage');
  const notes = document.getElementById('notesBody');
  const counter = document.getElementById('counter');
  const bar = document.getElementById('bar');

  async function render(n) {
    i = Math.max(0, Math.min(slides.length - 1, n));
    const s = slides[i];
    stage.innerHTML = marked.parse(s.md);

    stage.querySelectorAll('code.language-mermaid').forEach((code) => {
      const div = document.createElement('div');
      div.className = 'mermaid';
      div.textContent = code.textContent;
      code.closest('pre').replaceWith(div);
    });
    for (const node of Array.from(stage.querySelectorAll('.mermaid'))) {
      try {
        await mermaid.run({ nodes: [node] });
      } catch (e) {
        node.innerHTML = '<pre class="mmerr">' + node.textContent.replace(/</g, '&lt;') + '</pre>';
      }
    }

    notes.innerHTML = s.notes
      ? marked.parse(s.notes)
      : '<em>No notes for this slide.</em>';
    counter.textContent = (i + 1) + ' / ' + slides.length;
    bar.style.width = (((i + 1) / slides.length) * 100) + '%';
    location.hash = String(i + 1);
    stage.parentElement.scrollTo(0, 0);
  }

  function toggleNotes() {
    notesOpen = !notesOpen;
    document.body.classList.toggle('notes-open', notesOpen);
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowRight' || e.key === 'PageDown' || e.key === ' ') { e.preventDefault(); render(i + 1); }
    else if (e.key === 'ArrowLeft' || e.key === 'PageUp') { e.preventDefault(); render(i - 1); }
    else if (e.key === 'Home') render(0);
    else if (e.key === 'End') render(slides.length - 1);
    else if (e.key.toLowerCase() === 'n') toggleNotes();
    else if (e.key.toLowerCase() === 'f') document.documentElement.requestFullscreen?.();
  });
  document.getElementById('prev').onclick = () => render(i - 1);
  document.getElementById('next').onclick = () => render(i + 1);
  document.getElementById('notesBtn').onclick = toggleNotes;

  const start = parseInt(location.hash.slice(1), 10);
  render(Number.isFinite(start) && start > 0 ? start - 1 : 0);
}

const CSS = `
:root{--bg:#0d1017;--panel:#151924;--ink:#1c2130;--text:#dde3ee;--muted:#8b93a7;
      --accent:#5b8cff;--good:#3fb950;--border:#2a3040;--code:#0a0d13;}
*{box-sizing:border-box}
html,body{margin:0;height:100%;overflow:hidden}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
     background:var(--bg);color:var(--text);display:flex;flex-direction:column}
#wrap{flex:1;display:flex;overflow:hidden}
#main{flex:1;overflow:auto;display:flex;justify-content:center;padding:38px 30px 90px}
#stage{max-width:1080px;width:100%}
#stage h1{font-size:44px;line-height:1.15;color:#fff;margin:.2em 0 .5em;letter-spacing:-.5px}
#stage h2{font-size:31px;color:#fff;margin:.1em 0 .7em;border-bottom:1px solid var(--border);padding-bottom:12px}
#stage p,#stage li{font-size:19px;line-height:1.65}
#stage strong{color:#fff}
#stage blockquote{border-left:4px solid var(--accent);margin:22px 0;padding:10px 22px;
     background:var(--ink);border-radius:0 10px 10px 0;font-size:21px}
#stage table{border-collapse:collapse;width:100%;margin:20px 0;font-size:16.5px;display:block;overflow:auto}
#stage th,#stage td{border:1px solid var(--border);padding:10px 13px;text-align:left;vertical-align:top}
#stage th{background:var(--ink);color:#fff}
#stage tr:nth-child(even) td{background:rgba(255,255,255,.02)}
#stage code{background:var(--code);padding:2px 7px;border-radius:5px;font-size:15px;
     font-family:"SF Mono",Consolas,Menlo,monospace;color:#e6c07b}
#stage pre{background:var(--code);border:1px solid var(--border);padding:15px 17px;border-radius:10px;overflow:auto}
#stage pre code{background:none;padding:0;color:var(--text);font-size:15px}
.mermaid{background:#0f131c;border:1px solid var(--border);border-radius:12px;
     padding:20px;margin:22px 0;text-align:center;overflow:auto}
.mermaid svg{max-width:100%;height:auto}
.mmerr{color:#ff7b72;text-align:left}
#notes{width:0;overflow:hidden;background:var(--panel);border-left:1px solid var(--border);
     transition:width .18s ease}
body.notes-open #notes{width:390px;overflow:auto;padding:26px 22px}
#notes h3{margin-top:0;color:var(--accent);font-size:14px;letter-spacing:.12em;text-transform:uppercase}
#notes p,#notes li{font-size:16px;line-height:1.6;color:#c5ccdb}
#bottom{position:fixed;left:0;right:0;bottom:0;height:56px;background:var(--panel);
     border-top:1px solid var(--border);display:flex;align-items:center;gap:14px;padding:0 18px}
button{background:var(--ink);color:var(--text);border:1px solid var(--border);
     border-radius:8px;padding:8px 15px;font-size:14px;cursor:pointer}
button:hover{background:#232a3c}
#counter{color:var(--muted);font-size:14px;min-width:74px}
#hint{color:var(--muted);font-size:13px;margin-left:auto}
#track{position:fixed;left:0;right:0;bottom:56px;height:3px;background:var(--ink)}
#bar{height:100%;background:var(--accent);width:0;transition:width .18s ease}
@media print{#bottom,#track,#notes{display:none}#main{overflow:visible}}
`;

async function main() {
  const raw = await readFile(join(HERE, 'carp-demo-deck.md'), 'utf8');

  const slides = raw.split(/^---$/m).map((chunk) => {
    const notes = [];
    // Pull NOTE comments out of the slide body so they never render inline.
    const md = chunk.replace(/<!--\s*NOTE:([\s\S]*?)-->/g, (_, n) => {
      notes.push(n.trim().replace(/\n\s+/g, '\n'));
      return '';
    }).trim();
    return { md, notes: notes.join('\n\n') };
  }).filter((s) => s.md.length);

  let markedJs = '', mermaidJs = '', cdn = false;
  try {
    [markedJs, mermaidJs] = await Promise.all([fetchText(MARKED), fetchText(MERMAID)]);
    console.log('Inlined marked + mermaid — the deck needs no network.');
  } catch (e) {
    cdn = true;
    console.warn('Could not download libraries (' + e.message + ').');
    console.warn('Falling back to CDN tags — THE DECK WILL NEED INTERNET TO RENDER.');
  }

  const libs = cdn
    ? `<script src="${MARKED}"></script>\n<script src="${MERMAID}"></script>`
    : `<script>(0,eval)(${lit(markedJs)});</script>\n<script>(0,eval)(${lit(mermaidJs)});</script>`;

  const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CERTEN × CARP — Two Agents, One Escrow</title>
<style>${CSS}</style></head>
<body>
<div id="wrap">
  <div id="main"><article id="stage"></article></div>
  <aside id="notes"><h3>Speaker notes</h3><div id="notesBody"></div></aside>
</div>
<div id="track"><div id="bar"></div></div>
<div id="bottom">
  <button id="prev">← Prev</button>
  <button id="next">Next →</button>
  <span id="counter"></span>
  <button id="notesBtn">Notes (N)</button>
  <span id="hint">← → navigate · N notes · F fullscreen</span>
</div>
${libs}
<script>const SLIDES=${lit(slides)};</script>
<script>(${clientMain.toString()})();</script>
</body></html>`;

  const out = join(HERE, 'carp-demo-deck.html');
  await writeFile(out, html, 'utf8');
  console.log(`\nWrote ${out} (${Math.round(Buffer.byteLength(html) / 1024)} KB, ${slides.length} slides)`);
}

main().catch((e) => { console.error(e); process.exit(1); });
