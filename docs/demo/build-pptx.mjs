// Render a markdown deck to JPG slides and a real .pptx.
//
//   node build-pptx.mjs [carp-panel-brief.md]
//     -> slides/<name>-1.jpg …        one 1600x900 image per slide
//     -> <name>.pptx                  those images, one per 16:9 slide
//
// Slides are separated by `---`. The theme is LIGHT: these get printed, pasted
// into email, and shown on projectors that wash out dark backgrounds.
//
// Rendering uses the browser already installed on this machine via
// puppeteer-core, so there is no 150MB Chromium download. mermaid is inlined, so
// the render does not depend on the network at build time.
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join, basename } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import puppeteer from 'puppeteer-core';
import PptxGenJS from 'pptxgenjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const MARKED = 'https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js';
const MERMAID = 'https://cdn.jsdelivr.net/npm/mermaid@10.9.3/dist/mermaid.min.js';

// 16:9 at a size that keeps text crisp when scaled into PowerPoint.
const W = 1600;
const H = 900;

const BROWSERS = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
];

const lit = (v) => JSON.stringify(v).replace(/<\//g, '<\\/');

async function fetchText(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} -> HTTP ${r.status}`);
  return r.text();
}

// Light theme. Ink on white, one accent, generous leading — it has to survive a
// projector and a monochrome printout.
const CSS = `
:root{--ink:#12161f;--muted:#5b6472;--accent:#1a56db;--rule:#d7dce4;--soft:#f4f6f9;--code:#f7f8fa;}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:#fff}
body{font-family:"Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;color:var(--ink)}
.slide{width:${W}px;height:${H}px;background:#fff;padding:58px 72px;overflow:hidden;
  display:flex;flex-direction:column;justify-content:flex-start;position:relative}
.slide::after{content:"";position:absolute;left:0;right:0;bottom:0;height:8px;background:var(--accent)}
h1{font-size:52px;line-height:1.1;margin:0 0 22px;letter-spacing:-1px}
h2{font-size:34px;margin:0 0 16px}
p,li{font-size:22px;line-height:1.5;margin:10px 0}
strong{font-weight:700}
blockquote{border-left:5px solid var(--accent);background:var(--soft);margin:16px 0;
  padding:14px 24px;font-size:23px;line-height:1.45;border-radius:0 8px 8px 0}
blockquote p{margin:6px 0;font-size:23px}
table{border-collapse:collapse;width:100%;margin:16px 0;font-size:20px}
th,td{border:1px solid var(--rule);padding:9px 13px;text-align:left;vertical-align:top}
th{background:var(--soft);font-weight:700}
code{background:var(--code);border:1px solid var(--rule);padding:1px 6px;border-radius:4px;
  font-family:Consolas,"SF Mono",Menlo,monospace;font-size:0.92em;color:#0b3ea8}
pre{background:var(--code);border:1px solid var(--rule);border-radius:8px;padding:14px 18px;
  overflow:hidden;margin:14px 0}
pre code{background:none;border:none;padding:0;color:var(--ink);font-size:19px;line-height:1.45}
.mermaid{background:#fff;margin:10px 0;text-align:center}
.mermaid svg{max-width:100%;max-height:330px;height:auto}
hr{display:none}
`;

async function main() {
  const srcName = process.argv[2] || 'carp-panel-brief.md';
  const stem = basename(srcName, '.md');
  const raw = await readFile(join(HERE, srcName), 'utf8');

  // Speaker notes never belong on a printed slide.
  const slides = raw
    .split(/^---$/m)
    .map((c) => c.replace(/<!--\s*NOTE:[\s\S]*?-->/g, '').trim())
    .filter(Boolean);

  const [markedJs, mermaidJs] = await Promise.all([fetchText(MARKED), fetchText(MERMAID)]);

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>${CSS}</style></head>
<body><div id="root"></div>
<script>(0,eval)(${lit(markedJs)});</script>
<script>(0,eval)(${lit(mermaidJs)});</script>
<script>
const SLIDES = ${lit(slides)};
marked.setOptions({ gfm: true, breaks: false });
mermaid.initialize({ startOnLoad:false, theme:'base', securityLevel:'loose',
  themeVariables:{ fontSize:'17px', primaryColor:'#eef2fb', primaryTextColor:'#12161f',
    primaryBorderColor:'#1a56db', lineColor:'#5b6472', background:'#ffffff',
    actorBkg:'#eef2fb', actorBorder:'#1a56db', noteBkgColor:'#fff6e0', noteBorderColor:'#d9a441' },
  flowchart:{ useMaxWidth:true }, sequence:{ useMaxWidth:true, actorMargin:52 } });

window.ready = (async () => {
  const root = document.getElementById('root');
  SLIDES.forEach((md) => {
    const d = document.createElement('div');
    d.className = 'slide';
    d.innerHTML = marked.parse(md);
    root.appendChild(d);
  });
  document.querySelectorAll('code.language-mermaid').forEach((code) => {
    const div = document.createElement('div');
    div.className = 'mermaid';
    div.textContent = code.textContent;
    code.closest('pre').replaceWith(div);
  });
  for (const node of Array.from(document.querySelectorAll('.mermaid'))) {
    try { await mermaid.run({ nodes: [node] }); } catch (e) { node.textContent = ''; }
  }
  return true;
})();
</script></body></html>`;

  const htmlPath = join(HERE, `.${stem}.render.html`);
  await writeFile(htmlPath, html, 'utf8');

  const exe = BROWSERS.find((p) => existsSync(p));
  if (!exe) throw new Error('No Chrome or Edge found to render with');

  const browser = await puppeteer.launch({
    executablePath: exe,
    headless: 'new',
    args: ['--no-sandbox', '--force-device-scale-factor=1', '--hide-scrollbars'],
  });

  const outDir = join(HERE, 'slides');
  await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });

  const page = await browser.newPage();
  await page.setViewport({ width: W, height: H, deviceScaleFactor: 2 });
  await page.goto(pathToFileURL(htmlPath).href, { waitUntil: 'load' });
  await page.evaluate(() => window.ready);

  const nodes = await page.$$('.slide');
  if (nodes.length !== slides.length) {
    console.warn(`rendered ${nodes.length} slides but parsed ${slides.length}`);
  }

  const images = [];
  for (let i = 0; i < nodes.length; i++) {
    const file = join(outDir, `${stem}-${i + 1}.jpg`);
    await nodes[i].screenshot({ path: file, type: 'jpeg', quality: 92 });
    images.push(file);
    console.log(`  slide ${i + 1} -> ${file}`);
  }
  await browser.close();
  await rm(htmlPath, { force: true });

  // One image per slide, edge to edge — PowerPoint's 16:9 is 13.333 x 7.5 in.
  const pptx = new PptxGenJS();
  pptx.layout = 'LAYOUT_16x9';
  pptx.title = slides[0].match(/^#\s+(.+)$/m)?.[1]?.trim() ?? stem;
  for (const img of images) {
    pptx.addSlide().addImage({ path: img, x: 0, y: 0, w: 13.333, h: 7.5 });
  }
  const pptxPath = join(HERE, `${stem}.pptx`);
  await pptx.writeFile({ fileName: pptxPath });

  console.log(`\n${images.length} slides`);
  console.log(`JPGs : ${outDir}`);
  console.log(`PPTX : ${pptxPath}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
