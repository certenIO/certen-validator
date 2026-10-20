// Writes pkg/finality/adiri/testdata/finality_adiri4: the Adiri pins-strictness verdicts and the genesis-link load checks.
// Stdlib only (fs, path, crypto) and it never calls the verifier: every expectation is a literal this script composes from the
// documented states (pins reason bad_value / unknown_key with the key, V2_SPEC_S7 and states.json) in the canonical form
// {"code":...,"fields":{sorted keys, every value a string}}. The Go tests then require the verifier to produce exactly these texts.
//
//   node pkg/finality/adiri/vectorgen/gen_adiri4.mjs        (run from the repository root)
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const root = 'pkg/finality/adiri/testdata';
const out = path.join(root, 'finality_adiri4');
const adiri3 = JSON.parse(fs.readFileSync(path.join(root, 'finality_adiri3/vectors.json'), 'utf8'));
const embeddedPins = JSON.parse(fs.readFileSync('pkg/finality/pins/finality-pins.json', 'utf8'));
const linkBytes = fs.readFileSync(path.join(root, 'pins/genesis_link_1_290.bin'));
const rot = adiri3.vectors.find((v) => v.name === 'syn-rotation');
if (!rot) throw new Error('syn-rotation not found in finality_adiri3');

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const clone = (x) => JSON.parse(JSON.stringify(x));

// canonical {code, fields}: keys sorted, every value a string, no whitespace
function state(code, fields) {
  const keys = Object.keys(fields).sort();
  const body = keys.map((k) => JSON.stringify(k) + ':' + JSON.stringify(String(fields[k]))).join(',');
  return '{"code":' + JSON.stringify(code) + ',"fields":{' + body + '}}';
}
const pinsBad = (key, extra = {}) => state('finality_pins_corrupt', { key, reason: 'bad_value', ...extra });

fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(path.join(out, 'evidence'), { recursive: true });
fs.mkdirSync(path.join(out, 'link'), { recursive: true });
fs.copyFileSync(path.join(root, 'finality_adiri3/evidence', rot.evidence), path.join(out, 'evidence', rot.evidence));
fs.writeFileSync(path.join(out, 'link/genesis_link_1_290.bin'), linkBytes);

// ---- vectors.json: verdicts of Verify under a mutated adiri pins section (the evidence is syn-rotation, valid under the control) ----
const base = rot.pins;
const hex = (n, ch = '1') => ch.repeat(n);
const cases = [];
const add = (name, note, mutate, expect) => {
  const pins = clone(base);
  mutate(pins);
  cases.push({ name, group: 'pins', note, leg: rot.leg, pins, evidence: rot.evidence, expect });
};
cases.push({
  name: 'pins-control-valid', group: 'pins', leg: rot.leg, pins: clone(base), evidence: rot.evidence, expect: rot.expect,
  note: 'control: the unmodified inline adiri pins section gives the same verdict as syn-rotation of finality_adiri3',
});
add('pins-genesis-hash-63-digits', 'genesis_hash with an odd number of digits (63) is refused, never padded to 32 bytes', (p) => { p.genesis_hash = p.genesis_hash.slice(0, -1); }, pinsBad('adiri.genesis_hash'));
add('pins-genesis-hash-non-hex-digit', 'genesis_hash with a non-hex digit is refused, never truncated', (p) => { p.genesis_hash = p.genesis_hash.slice(0, -1) + 'g'; }, pinsBad('adiri.genesis_hash'));
add('pins-genesis-hash-no-prefix', 'genesis_hash without its 0x prefix', (p) => { p.genesis_hash = p.genesis_hash.slice(2); }, pinsBad('adiri.genesis_hash'));
add('pins-genesis-hash-one-char', 'genesis_hash of one character (shorter than the prefix)', (p) => { p.genesis_hash = '0'; }, pinsBad('adiri.genesis_hash'));
add('pins-epoch0-hash-63-digits', 'epoch0_final_state.hash with 63 digits', (p) => { p.epoch0_final_state.hash = p.epoch0_final_state.hash.slice(0, -1); }, pinsBad('adiri.epoch0_final_state.hash'));
add('pins-codehash-63-digits', 'eip2935.runtime_codehash with 63 digits', (p) => { p.eip2935.runtime_codehash = p.eip2935.runtime_codehash.slice(0, -1); }, pinsBad('adiri.eip2935.runtime_codehash'));
add('pins-address-39-digits', 'eip2935.address with 39 digits (20 bytes if a zero were prepended)', (p) => { p.eip2935.address = p.eip2935.address.slice(0, -1); }, pinsBad('adiri.eip2935.address'));
add('pins-address-bare-0x', 'eip2935.address that is only the prefix', (p) => { p.eip2935.address = '0x'; }, pinsBad('adiri.eip2935.address'));
add('pins-committee-key-191-digits', 'a genesis committee key with 191 digits (96 bytes if a zero were prepended)', (p) => { p.genesis_committee[0] = p.genesis_committee[0].slice(0, -1); }, pinsBad('adiri.genesis_committee', { index: 0 }));
add('pins-committee-key-non-hex-digit', 'a genesis committee key with a non-hex digit at index 2', (p) => { p.genesis_committee[2] = p.genesis_committee[2].slice(0, -2) + 'zz'; }, pinsBad('adiri.genesis_committee', { index: 2 }));
add('pins-committee-key-95-bytes', 'a genesis committee key of 95 bytes at index 1', (p) => { p.genesis_committee[1] = p.genesis_committee[1].slice(0, -2); }, pinsBad('adiri.genesis_committee', { index: 1 }));
add('pins-committee-empty', 'no genesis committee', (p) => { p.genesis_committee = []; }, pinsBad('adiri.genesis_committee'));
add('pins-committee-256-keys', 'a genesis committee of 256 keys (the CFA1 table holds at most 255)', (p) => { p.genesis_committee = Array.from({ length: 256 }, () => hex(192)); }, pinsBad('adiri.genesis_committee'));
add('pins-chain-id-zero', 'chain_id 0', (p) => { p.chain_id = 0; }, pinsBad('adiri.chain_id'));
add('pins-min-committee-size-zero', 'min_committee_size 0', (p) => { p.min_committee_size = 0; }, pinsBad('adiri.min_committee_size'));
add('pins-max-headers-zero', 'max_headers 0', (p) => { p.max_headers = 0; }, pinsBad('adiri.max_headers'));
add('pins-link-sha-63-chars', 'genesis_link_sha256 with 63 characters', (p) => { p.genesis_link_sha256 = p.genesis_link_sha256.slice(0, -1); }, pinsBad('adiri.genesis_link_sha256'));
add('pins-unknown-key', 'an unknown member of the adiri section', (p) => { p.surprise = 1; }, state('finality_pins_corrupt', { key: 'adiri.surprise', reason: 'unknown_key' }));
add('pins-chain-id-is-a-string', 'chain_id given as a JSON string', (p) => { p.chain_id = '2017'; }, pinsBad('adiri.chain_id'));
add('pins-max-headers-is-a-string', 'max_headers given as a JSON string', (p) => { p.max_headers = 'many'; }, pinsBad('adiri.max_headers'));

fs.writeFileSync(path.join(out, 'vectors.json'), JSON.stringify({ format: 'finality_adiri4/1', vectors: cases }, null, 1) + '\n');

// ---- genesis_link.json: the load-time check of the embedded genesis link (pkg/finality/adiri CheckGenesisLink) ----
const real = embeddedPins.adiri;
const hexOf = (b) => Buffer.from(b).toString('hex');
const linkCases = [];
const addLink = (name, note, { pins = clone(real), edits = [], linkHex, expect }) => {
  const c = { name, note, pins, expect };
  if (linkHex !== undefined) c.link_hex = linkHex;
  else { c.link = 'link/genesis_link_1_290.bin'; c.edits = edits; }
  linkCases.push(c);
};
const linkKey = (k) => pinsBad(k);
addLink('link-valid', 'the 290-header link under the real pins: genesis_hash -> block 1 ... block 290 = epoch0_final_state', { expect: 'ok' });
addLink('link-one-bit-flipped', 'one bit of the file flipped: its sha256 is no longer genesis_link_sha256', {
  edits: [{ offset: 1000, delete: 1, insert: (linkBytes[1000] ^ 1).toString(16).padStart(2, '0') }], expect: linkKey('adiri.genesis_link_sha256'),
});
addLink('link-truncated-by-one-byte', 'the last byte removed', { edits: [{ offset: linkBytes.length - 1, delete: 1, insert: '' }], expect: linkKey('adiri.genesis_link_sha256') });
addLink('link-extended-by-one-byte', 'an extra byte (0xc0) appended', { edits: [{ offset: linkBytes.length, delete: 0, insert: 'c0' }], expect: linkKey('adiri.genesis_link_sha256') });
addLink('link-absent', 'no file at all', { linkHex: '', pins: clone(real), expect: linkKey('adiri.genesis_link_sha256') });
addLink('pins-name-another-genesis', 'the right file under pins whose genesis_hash differs in one digit: the sha256 matches, the first header does not link to it', {
  pins: Object.assign(clone(real), { genesis_hash: real.genesis_hash.slice(0, -1) + (real.genesis_hash.endsWith('f') ? 'e' : 'f') }), expect: linkKey('adiri.genesis_link'),
});
addLink('pins-name-another-tip-number', 'epoch0_final_state.number 289 instead of 290', {
  pins: Object.assign(clone(real), { epoch0_final_state: { ...real.epoch0_final_state, number: real.epoch0_final_state.number - 1 } }), expect: linkKey('adiri.genesis_link'),
});
addLink('pins-name-another-tip-hash', 'epoch0_final_state.hash differs in one digit', {
  pins: Object.assign(clone(real), { epoch0_final_state: { ...real.epoch0_final_state, hash: real.epoch0_final_state.hash.slice(0, -1) + (real.epoch0_final_state.hash.endsWith('f') ? 'e' : 'f') } }), expect: linkKey('adiri.genesis_link'),
});
for (const [name, note, garbage] of [
  ['link-pinned-but-not-rlp', 'a file the pins hash-pin that is not RLP', Buffer.from('not a header chain')],
  ['link-pinned-but-empty', 'the empty file, hash-pinned', Buffer.alloc(0)],
  ['link-pinned-hostile-length', 'a hash-pinned file whose first list declares a 2^63 length', Buffer.from([0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])],
  ['link-pinned-single-header', 'a hash-pinned file holding only block 1 (it must end at epoch0_final_state)', linkBytes.subarray(0, firstHeaderLength(linkBytes))],
]) {
  const pins = clone(real);
  pins.genesis_link_sha256 = sha256(garbage);
  addLink(name, note, { pins, linkHex: hexOf(garbage), expect: linkKey('adiri.genesis_link') });
}
function firstHeaderLength(b) {
  // the first item is a long list (0xf8..0xff prefix): 1 + length-of-length + length
  const l = b[0] - 0xf7;
  let n = 0;
  for (let i = 0; i < l; i++) n = n * 256 + b[1 + i];
  return 1 + l + n;
}
fs.writeFileSync(path.join(out, 'genesis_link.json'), JSON.stringify({ format: 'finality_adiri4-genesis-link/1', vectors: linkCases }, null, 1) + '\n');

fs.writeFileSync(path.join(out, 'README.md'), "# finality_adiri4 (RB11-GATE-A): Adiri pins strictness and the genesis-link load check\n\nNew evidence, new set: finality_adiri1/2/3 stay byte-identical (a published vector set is specification and is never edited). This\nset adds what finality_adiri3 does not pin, for the Go verifier and the TypeScript port alike.\n\nFiles (all hashed by MANIFEST.json, which MANIFEST.json.sha256 hashes):\n\n- vectors.json, format finality_adiri4/1: the SAME vector shape as finality_adiri3 (name, group, note, leg, pins, evidence, expect),\n  group pins, 21 vectors. Each judges Verify(pins, leg, evidence) of the small synthetic rotation chain (evidence/syn-rotation.bin, a\n  copy of finality_adiri3's) under the inline adiri pins section of finality_adiri3's syn-rotation with exactly one member changed.\n  pins-control-valid is the unchanged section (verdict = syn-rotation's); every other vector is a pins refusal:\n  finality_pins_corrupt{key, reason:bad_value|unknown_key[, index]}. The rule they pin: a pinned hash, address or key is exact hex,\n  with its 0x prefix where it has one: an odd number of digits (63, 39, 191) is NOT padded with a zero, a non-hex digit is NOT\n  truncated, a bare 0x or a one-character value is refused, and the committee, bounds, link-hash length and member names are checked\n  as listed. Upper case is accepted (the EIP-2935 address is a mixed-case checksum).\n- genesis_link.json, format finality_adiri4-genesis-link/1, 12 vectors: the load-time check of the 290-header genesis link\n  (V2_SPEC_S7 4.2, annex A7). Each vector has pins (an adiri section), a link file (link: a path in this set, edited by edits\n  {offset, delete, insert-hex}; or link_hex, the bytes inline, possibly empty) and expect: the literal text ok, or the canonical\n  state. The check: sha256(file) must equal pins.genesis_link_sha256 (else finality_pins_corrupt{key:adiri.genesis_link_sha256,\n  reason:bad_value}); then the file must be a concatenation of RLP header lists that runs from block 1 (parentHash =\n  pins.genesis_hash) through linked headers to epoch0_final_state (else key adiri.genesis_link). It is checked once at load, never\n  per proof. A pins section without an adiri member is finality_pin_unknown (not a vector: it needs a whole pins file).\n- evidence/syn-rotation.bin and link/genesis_link_1_290.bin (176,758 B): data.\n\nExpectations are literals composed by pkg/finality/adiri/vectorgen/gen_adiri4.mjs (stdlib only; it does not call the verifier):\n{\"code\":...,\"fields\":{sorted keys, every value a string}}. Regenerate with node from the repository root; the output is deterministic.\n");

// ---- MANIFEST: the sha256 of every file of the set, and of the manifest itself ----
const files = {};
const walk = (d) => {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (!['MANIFEST.json', 'MANIFEST.json.sha256'].includes(e.name)) files[path.relative(out, p).split(path.sep).join('/')] = sha256(fs.readFileSync(p));
  }
};
walk(out);
const manifest = JSON.stringify({ files: Object.fromEntries(Object.entries(files).sort(([a], [b]) => (a < b ? -1 : 1))) }, null, 1) + '\n';
fs.writeFileSync(path.join(out, 'MANIFEST.json'), manifest);
fs.writeFileSync(path.join(out, 'MANIFEST.json.sha256'), sha256(Buffer.from(manifest)) + '\n');
console.log('finality_adiri4:', cases.length, 'verdict vectors,', linkCases.length, 'genesis-link vectors,', Object.keys(files).length, 'files');
