#!/usr/bin/env node
// finality-pins-sync: compares the finality pins file and its SHA-256 constant across the three repositories (V2_SPEC_S7 4.1, RB12-OPS-A1).
//
//   node scripts/finality-pins-sync.mjs --validator <certen-validator checkout> --sdk <certen-sdk checkout> [--contracts <this repo>] [--json]
//
// The canonical copy is evm/deployments/finality-pins.json of certen-contracts (this repository unless --contracts says otherwise). The
// check is byte for byte, offline, with no dependency but node:
//
//   contracts.format         the canonical file is UTF-8 without BOM, LF only, ends with one LF, and is JSON
//   contracts.sha256-file    evm/deployments/finality-pins.sha256 names the SHA-256 of the canonical file
//   validator.file           pkg/finality/pins/finality-pins.json is the canonical file, byte for byte
//   validator.constant       the PinsSHA256 constant of pkg/finality/pins.go is the SHA-256 of the canonical file
//   sdk.file                 packages/verify/src/proof-v2/finality/finality-pins.json is the canonical file, byte for byte
//   sdk.constant             the PINS_SHA256 constant of .../finality/pins.ts is the SHA-256 of the canonical file
//   sdk.embedded             the EMBEDDED_PINS_TEXT literal of .../finality/pins-embedded.ts is the canonical file, byte for byte
//   links.<period>.<repo>    the light-client link <period>.ssz that the ledger of the pins names: the canonical copy
//                            (evm/deployments/finality-pins-links/), the validator copy (pkg/finality/pins-links/) and the SDK copy
//                            (EMBEDDED_LINKS_BASE64 of .../finality/pins-links-embedded.ts) are the same bytes, and none is missing
//
// A missing file, a constant or literal that cannot be found, and a difference are all failures, each named by its check id. Exit status:
// 0 every check passed, 1 at least one failed, 2 usage error. Prints a table (or JSON with --json).
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PATHS = {
  contracts: { file: 'evm/deployments/finality-pins.json', sha: 'evm/deployments/finality-pins.sha256', links: 'evm/deployments/finality-pins-links' },
  validator: { file: 'pkg/finality/pins/finality-pins.json', constant: 'pkg/finality/pins.go', links: 'pkg/finality/pins-links' },
  sdk: {
    file: 'packages/verify/src/proof-v2/finality/finality-pins.json',
    constant: 'packages/verify/src/proof-v2/finality/pins.ts',
    embedded: 'packages/verify/src/proof-v2/finality/pins-embedded.ts',
    links: 'packages/verify/src/proof-v2/finality/pins-links-embedded.ts',
  },
};

const sha256 = (b) => createHash('sha256').update(b).digest('hex');

function read(root, rel) {
  const p = join(root, rel);
  return existsSync(p) ? readFileSync(p) : null;
}

function check(results, id, repo, what, expected, actual, ok, note = '') {
  results.push({ id, repo, what, expected, actual, ok, note });
}

// a missing input is a failed check that says which path was missing
function need(results, id, repo, what, root, rel) {
  const b = read(root, rel);
  if (b === null) check(results, id, repo, what, 'present', 'MISSING', false, `${rel} does not exist under ${root}`);
  return b;
}

function constantOf(text, re) {
  const m = re.exec(text);
  return m ? m[1] : null;
}

// the string literal that follows `name =`, JSON-parsed (the file embeds JSON.stringify output)
function stringLiteralAfter(text, name) {
  const i = text.search(new RegExp(`\\b${name}\\s*=\\s*"`));
  if (i < 0) return { error: `no double-quoted literal after ${name} =` };
  const start = text.indexOf('"', i);
  let j = start + 1;
  while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
  if (j >= text.length) return { error: 'unterminated string literal' };
  try {
    return { value: JSON.parse(text.slice(start, j + 1)) };
  } catch (e) {
    return { error: `the literal is not a JSON string: ${e.message}` };
  }
}

// { period: Buffer } from the object literal EMBEDDED_LINKS_BASE64 = { '1378': 'chunk' + 'chunk', ... }
function embeddedLinks(text) {
  const start = text.search(/\bEMBEDDED_LINKS_BASE64\b[^=]*=\s*\{/);
  if (start < 0) return { error: 'no EMBEDDED_LINKS_BASE64 object' };
  const out = {};
  const entry = /['"](\d+)['"]\s*:\s*((?:\s*'[A-Za-z0-9+/=]*'\s*\+?)+)/g;
  entry.lastIndex = start;
  let m;
  while ((m = entry.exec(text)) !== null) {
    const b64 = [...m[2].matchAll(/'([A-Za-z0-9+/=]*)'/g)].map((x) => x[1]).join('');
    const buf = Buffer.from(b64, 'base64');
    if (buf.toString('base64') !== b64) return { error: `the base64 of period ${m[1]} is not canonical` };
    out[m[1]] = buf;
  }
  return { value: out };
}

function linksOfDir(root, rel) {
  const dir = join(root, rel);
  if (!existsSync(dir)) return null;
  const out = {};
  for (const f of readdirSync(dir)) {
    const m = /^(\d+)\.ssz$/.exec(f);
    if (m) out[m[1]] = readFileSync(join(dir, f));
  }
  return out;
}

export function compare({ contracts, validator, sdk }) {
  const r = [];
  const canon = need(r, 'contracts.file', 'contracts', 'canonical file present', contracts, PATHS.contracts.file);
  if (canon === null) return r;
  const want = sha256(canon);

  // contracts.format
  const problems = [];
  if (canon.length >= 3 && canon[0] === 0xef && canon[1] === 0xbb && canon[2] === 0xbf) problems.push('byte order mark');
  if (canon.includes(0x0d)) problems.push('carriage return');
  if (canon.length === 0 || canon[canon.length - 1] !== 0x0a || (canon.length > 1 && canon[canon.length - 2] === 0x0a)) problems.push('not exactly one final LF');
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(canon);
    JSON.parse(canon.toString('utf8'));
  } catch (e) {
    problems.push(`not UTF-8 JSON (${e.message})`);
  }
  check(r, 'contracts.format', 'contracts', 'UTF-8, no BOM, LF only, JSON', 'clean', problems.length ? problems.join('; ') : 'clean', problems.length === 0);

  const shaFile = need(r, 'contracts.sha256-file', 'contracts', 'finality-pins.sha256 names the file hash', contracts, PATHS.contracts.sha);
  if (shaFile !== null) {
    const named = (/^([0-9a-f]{64})\b/.exec(shaFile.toString('utf8')) || [])[1] || 'unreadable';
    check(r, 'contracts.sha256-file', 'contracts', 'finality-pins.sha256 names the file hash', want, named, named === want);
  }

  for (const [repo, root] of [['validator', validator], ['sdk', sdk]]) {
    const p = PATHS[repo];
    const b = need(r, `${repo}.file`, repo, 'pins file', root, p.file);
    if (b !== null) check(r, `${repo}.file`, repo, 'pins file == canonical, byte for byte', want, sha256(b), b.equals(canon));

    const ct = need(r, `${repo}.constant`, repo, 'SHA-256 constant', root, p.constant);
    if (ct !== null) {
      const re = repo === 'validator' ? /const\s+PinsSHA256\s*=\s*"([0-9a-f]{64})"/ : /export\s+const\s+PINS_SHA256\s*=\s*['"]([0-9a-f]{64})['"]/;
      const got = constantOf(ct.toString('utf8'), re);
      check(r, `${repo}.constant`, repo, `${repo === 'validator' ? 'PinsSHA256' : 'PINS_SHA256'} == sha256(canonical)`, want, got ?? 'NOT FOUND', got === want,
        got === null ? `no ${repo === 'validator' ? 'PinsSHA256' : 'PINS_SHA256'} constant in ${p.constant}` : '');
    }
  }

  // sdk.embedded
  const emb = need(r, 'sdk.embedded', 'sdk', 'EMBEDDED_PINS_TEXT', sdk, PATHS.sdk.embedded);
  if (emb !== null) {
    const lit = stringLiteralAfter(emb.toString('utf8'), 'EMBEDDED_PINS_TEXT');
    if (lit.error) check(r, 'sdk.embedded', 'sdk', 'EMBEDDED_PINS_TEXT == canonical', want, 'UNREADABLE', false, lit.error);
    else {
      const got = Buffer.from(lit.value, 'utf8');
      check(r, 'sdk.embedded', 'sdk', 'EMBEDDED_PINS_TEXT == canonical, byte for byte', want, sha256(got), got.equals(canon));
    }
  }

  // links
  const canonLinks = linksOfDir(contracts, PATHS.contracts.links) ?? {};
  const valLinks = linksOfDir(validator, PATHS.validator.links);
  if (valLinks === null) check(r, 'links.validator', 'validator', 'links directory', 'present', 'MISSING', false, `${PATHS.validator.links} does not exist under ${validator}`);
  const sdkText = need(r, 'links.sdk', 'sdk', 'embedded links', sdk, PATHS.sdk.links);
  let sdkLinks = null;
  if (sdkText !== null) {
    const l = embeddedLinks(sdkText.toString('utf8'));
    if (l.error) check(r, 'links.sdk', 'sdk', 'embedded links', 'readable', 'UNREADABLE', false, l.error);
    else sdkLinks = l.value;
  }
  const periods = new Set([...Object.keys(canonLinks), ...Object.keys(valLinks ?? {}), ...Object.keys(sdkLinks ?? {})]);
  for (const period of [...periods].sort((a, b) => Number(a) - Number(b))) {
    const c = canonLinks[period];
    if (!c) {
      check(r, `links.${period}.contracts`, 'contracts', `link ${period}.ssz published`, 'present', 'MISSING', false, `${PATHS.contracts.links}/${period}.ssz does not exist`);
      continue;
    }
    for (const [repo, set] of [['validator', valLinks], ['sdk', sdkLinks]]) {
      if (set === null) continue; // already reported as one failed check above
      const got = set[period];
      check(r, `links.${period}.${repo}`, repo, `link ${period}.ssz == canonical`, sha256(c).slice(0, 64), got ? sha256(got) : 'MISSING', !!got && got.equals(c));
    }
  }
  return r;
}

function table(results, want) {
  const w = (s, n) => String(s).padEnd(n);
  const short = (s) => (/^[0-9a-f]{64}$/.test(s) ? `${s.slice(0, 8)}..${s.slice(-4)}` : s);
  const lines = [`finality-pins-sync: canonical sha256 ${want ?? '(canonical file missing)'}`, `${w('check', 24)}${w('repo', 11)}${w('result', 7)}${w('expected', 17)}${w('actual', 17)}what`];
  for (const x of results) lines.push(`${w(x.id, 24)}${w(x.repo, 11)}${w(x.ok ? 'ok' : 'FAIL', 7)}${w(short(x.expected), 17)}${w(short(x.actual), 17)}${x.what}${x.note ? `  [${x.note}]` : ''}`);
  const failed = results.filter((x) => !x.ok);
  lines.push(failed.length === 0 ? `RESULT: ok, ${results.length} checks` : `RESULT: ${failed.length} of ${results.length} checks FAILED: ${failed.map((x) => x.id).join(', ')}`);
  return lines.join('\n');
}

function main(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (['--validator', '--sdk', '--contracts'].includes(a) && i + 1 < argv.length) args[a.slice(2)] = resolve(argv[++i]);
    else {
      console.error(`unknown or incomplete argument ${a}\nusage: finality-pins-sync.mjs --validator <dir> --sdk <dir> [--contracts <dir>] [--json]`);
      return 2;
    }
  }
  if (!args.validator || !args.sdk) {
    console.error('usage: finality-pins-sync.mjs --validator <dir> --sdk <dir> [--contracts <dir>] [--json]');
    return 2;
  }
  args.contracts ??= resolve(dirname(fileURLToPath(import.meta.url)), '..');
  for (const k of ['contracts', 'validator', 'sdk']) {
    if (!existsSync(args[k])) {
      console.error(`--${k} ${args[k]} does not exist`);
      return 2;
    }
  }
  const results = compare(args);
  const canon = read(args.contracts, PATHS.contracts.file);
  if (args.json) console.log(JSON.stringify({ canonical_sha256: canon ? sha256(canon) : null, ok: results.every((x) => x.ok), checks: results }, null, 1));
  else console.log(table(results, canon ? sha256(canon) : null));
  return results.every((x) => x.ok) ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.slice(2));
