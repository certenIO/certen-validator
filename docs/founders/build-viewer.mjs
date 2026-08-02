// Build a single self-contained HTML viewer for the founder docs.
// Inlines the Markdown content + marked (renderer) + mermaid (diagrams) so the
// resulting file works offline by double-clicking. Re-run after editing docs:
//   node build-viewer.mjs
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));

const DOC_LIST = [
  ['README.md', 'Start Here'],
  ['01-infrastructure-and-workflows.md', '1 · Infrastructure & Workflows'],
  ['02-external-chains-and-accumulate.md', '2 · External Chains & Accumulate'],
  ['03-end-to-end-workflows.md', '3 · End-to-End Workflows'],
  ['04-proof-types-and-parts.md', '4 · Proof Types & Parts'],
  ['05-how-proofs-are-used.md', '5 · How Proofs Are Used'],
  ['06-contracts-explained.md', '6 · Contracts Explained'],
  ['07-positioning-and-monetization.md', '7 · Possible Framing & Monetization Paths'],
  ['policy-engine/README.md', 'Policy Engine · Start Here'],
  ['policy-engine/01-what-the-policy-gate-is.md', 'P1 · What the Policy Gate Is'],
  ['policy-engine/02-how-your-engine-participates.md', 'P2 · How Your Engine Participates'],
  ['policy-engine/03-from-decision-to-proof.md', 'P3 · From Decision to Proof'],
  ['policy-engine/04-assurance-and-operations.md', 'P4 · Assurance & Operations'],
];

const MARKED_URL = 'https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js';
const MERMAID_URL = 'https://cdn.jsdelivr.net/npm/mermaid@10.9.3/dist/mermaid.min.js';

// JSON-encode any string/value into a SAFE inline-<script> literal: the whole
// value becomes one JS string (or JSON), and we neutralize the only
// HTML-sensitive sequence ("</") so the browser never closes our <script> early.
const safeLiteral = (value) => JSON.stringify(value).replace(/<\//g, '<\\/');

async function fetchText(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return res.text();
}

// This function's SOURCE is shipped to the browser via .toString(). It is never
// executed in Node, so references to browser globals (DOCS, marked, mermaid) are fine.
function clientMain() {
  const fileIndex = {};
  DOCS.forEach((d, i) => { fileIndex[d.file] = i; });
  let pendingAnchor = null;
  let currentFile = DOCS[0].file;

  // Resolve a doc-relative href against the doc it appears in, so links keep
  // working once docs live in subdirectories: "./x.md" inside "policy-engine/"
  // is "policy-engine/x.md", and "../README.md" is "README.md".
  const resolvePath = (fromFile, href) => {
    const cut = fromFile.lastIndexOf('/');
    const base = cut === -1 ? '' : fromFile.slice(0, cut + 1);
    const out = [];
    for (const part of (base + href).split('/')) {
      if (part === '' || part === '.') continue;
      if (part === '..') out.pop();
      else out.push(part);
    }
    return out.join('/');
  };

  const slug = (s) => s.toLowerCase().replace(/[^\w\s-]/g, '').replace(/\s/g, '-').replace(/^-+|-+$/g, '');

  marked.setOptions({ gfm: true, breaks: false });
  mermaid.initialize({ startOnLoad: false, theme: 'default', securityLevel: 'loose', flowchart: { useMaxWidth: true, htmlLabels: true }, sequence: { useMaxWidth: true } });

  const content = document.getElementById('content');
  const nav = document.getElementById('nav');

  // build sidebar
  DOCS.forEach((d, i) => {
    const a = document.createElement('a');
    a.href = '#' + d.file;
    a.textContent = d.title;
    a.dataset.idx = String(i);
    nav.appendChild(a);
  });

  async function render(i, anchor) {
    const d = DOCS[i] || DOCS[0];
    currentFile = d.file;
    content.innerHTML = marked.parse(d.md);

    content.querySelectorAll('h1,h2,h3,h4,h5,h6').forEach((h) => { if (!h.id) h.id = slug(h.textContent); });

    content.querySelectorAll('code.language-mermaid').forEach((code) => {
      const pre = code.closest('pre');
      const div = document.createElement('div');
      div.className = 'mermaid';
      div.textContent = code.textContent;
      pre.replaceWith(div);
    });

    nav.querySelectorAll('a').forEach((a) => a.classList.toggle('active', Number(a.dataset.idx) === i));

    const nodes = Array.from(content.querySelectorAll('.mermaid'));
    for (const node of nodes) {
      try { await mermaid.run({ nodes: [node] }); }
      catch (e) { node.innerHTML = '<div class="mmerr">Diagram could not render. Source:</div><pre>' + node.textContent.replace(/</g, '&lt;') + '</pre>'; }
    }

    if (anchor) {
      const t = document.getElementById(anchor);
      if (t) { t.scrollIntoView(); return; }
    }
    content.parentElement.scrollTo(0, 0);
  }

  function go(i, anchor) {
    pendingAnchor = anchor || null;
    const h = '#' + DOCS[i].file;
    if (location.hash === h) render(i, anchor);
    else location.hash = h;
  }

  content.addEventListener('click', (e) => {
    const a = e.target.closest('a');
    if (!a) return;
    const href = a.getAttribute('href');
    if (!href) return;
    if (href.startsWith('#')) {
      e.preventDefault();
      const t = document.getElementById(href.slice(1));
      if (t) t.scrollIntoView();
      return;
    }
    const parts = href.split('#');
    const file = resolvePath(currentFile, parts[0]);
    if (file in fileIndex) { e.preventDefault(); go(fileIndex[file], parts[1]); }
  });

  window.addEventListener('hashchange', () => {
    const f = decodeURIComponent(location.hash.slice(1));
    const i = (f in fileIndex) ? fileIndex[f] : 0;
    render(i, pendingAnchor);
    pendingAnchor = null;
  });

  const start = decodeURIComponent(location.hash.slice(1));
  render((start in fileIndex) ? fileIndex[start] : 0);
}

const CSS = `
:root{--bg:#0f1117;--panel:#161922;--ink:#1a1d27;--text:#d7dbe6;--muted:#8b93a7;--accent:#5b8cff;--border:#272b38;--code:#0c0e14;}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);display:flex}
#sidebar{width:300px;min-width:300px;height:100vh;overflow:auto;background:var(--panel);border-right:1px solid var(--border);padding:22px 16px}
#sidebar .brand{font-size:18px;font-weight:700;color:#fff;padding:6px 10px 4px}
#sidebar .sub{font-size:12px;color:var(--muted);padding:0 10px 16px;border-bottom:1px solid var(--border);margin-bottom:12px}
#nav{display:flex;flex-direction:column;gap:2px}
#nav a{color:var(--text);text-decoration:none;padding:9px 11px;border-radius:8px;font-size:14px;line-height:1.3}
#nav a:hover{background:var(--ink)}
#nav a.active{background:var(--accent);color:#fff;font-weight:600}
#main{flex:1;height:100vh;overflow:auto;display:flex;justify-content:center}
#content{max-width:900px;width:100%;padding:46px 54px 120px;line-height:1.65}
#content h1,#content h2,#content h3{color:#fff;line-height:1.25;scroll-margin-top:20px}
#content h1{font-size:30px;border-bottom:1px solid var(--border);padding-bottom:14px;margin-top:8px}
#content h2{font-size:23px;margin-top:42px;border-bottom:1px solid var(--border);padding-bottom:8px}
#content h3{font-size:18px;margin-top:30px}
#content a{color:var(--accent);text-decoration:none}
#content a:hover{text-decoration:underline}
#content p,#content li{font-size:15.5px}
#content table{border-collapse:collapse;width:100%;margin:18px 0;font-size:14px;display:block;overflow:auto}
#content th,#content td{border:1px solid var(--border);padding:9px 12px;text-align:left;vertical-align:top}
#content th{background:var(--ink);color:#fff}
#content tr:nth-child(even) td{background:rgba(255,255,255,.02)}
#content code{background:var(--code);padding:2px 6px;border-radius:5px;font-size:13px;font-family:"SF Mono",Consolas,Menlo,monospace;color:#e6c07b}
#content pre{background:var(--code);border:1px solid var(--border);padding:14px 16px;border-radius:10px;overflow:auto}
#content pre code{background:none;padding:0;color:var(--text)}
#content blockquote{border-left:4px solid var(--accent);margin:18px 0;padding:6px 18px;background:var(--ink);border-radius:0 8px 8px 0;color:#c5ccdb}
#content blockquote p{margin:8px 0}
#content hr{border:none;border-top:1px solid var(--border);margin:34px 0}
.mermaid{background:#f7f8fb;border:1px solid var(--border);border-radius:10px;padding:18px;margin:20px 0;text-align:center;overflow:auto}
.mmerr{color:#b00;font-size:13px;margin-bottom:8px;text-align:left}
#content .mermaid svg{max-width:100%;height:auto}
@media (max-width:880px){body{flex-direction:column}#sidebar{width:100%;min-width:0;height:auto;position:static}#main{height:auto}#content{padding:26px 18px 80px}}
`;

async function main() {
  const docs = [];
  for (const [file, title] of DOC_LIST) {
    const md = await readFile(join(HERE, file), 'utf8');
    docs.push({ file, title, md });
  }

  let markedJs = '', mermaidJs = '', usedCdn = false;
  try {
    [markedJs, mermaidJs] = await Promise.all([fetchText(MARKED_URL), fetchText(MERMAID_URL)]);
    console.log('Downloaded marked + mermaid (inlining for offline use).');
  } catch (e) {
    usedCdn = true;
    console.warn('Could not download libraries (' + e.message + ').');
    console.warn('Falling back to CDN <script> tags — the file will need internet to render.');
  }

  const libScripts = usedCdn
    ? `<script src="${MARKED_URL}"></script>\n<script src="${MERMAID_URL}"></script>`
    : `<script>(0,eval)(${safeLiteral(markedJs)});</script>\n<script>(0,eval)(${safeLiteral(mermaidJs)});</script>`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Certen — Founder's Guide</title>
<style>${CSS}</style>
</head>
<body>
<aside id="sidebar">
  <div class="brand">Certen</div>
  <div class="sub">Founder's Guide to the Whole System</div>
  <nav id="nav"></nav>
</aside>
<main id="main"><article id="content"></article></main>
${libScripts}
<script>const DOCS=${safeLiteral(docs)};</script>
<script>(${clientMain.toString()})();</script>
</body>
</html>`;

  const out = join(HERE, 'certen-guide.html');
  await writeFile(out, html, 'utf8');
  const kb = Math.round(Buffer.byteLength(html) / 1024);
  console.log(`\nWrote ${out} (${kb} KB)${usedCdn ? ' [CDN mode — needs internet]' : ' [offline-ready]'}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
