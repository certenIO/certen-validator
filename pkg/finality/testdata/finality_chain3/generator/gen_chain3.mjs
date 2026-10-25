// Writes legs.json, MANIFEST.json and MANIFEST.json.sha256 of finality_chain3 (the finality member's optional leg.headerRlp).
// Usage: node gen_chain3.mjs <set directory>   (node standard library only; README.md is hand-written and listed in the manifest)
// The two real headers are in headers.json (dumped once from the repo's fixtures); every expectation is written by hand from the rule:
// keccak256(headerRlp) == blockHash, positional number == blockNumber, else finality_chain_broken{seq 0, check leg_binding, want, got}.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = process.argv[2];
const H = JSON.parse(readFileSync(join(dir, 'generator', 'headers.json'), 'utf8')).headers;
const base = H.base_sepolia_47368146;
const other = H.telcoin_adiri_498759;

const section = (leg) => JSON.stringify({ format: 'certen-finality-addenda/1', leg, addenda: [] });
const leg = (o = {}) => ({ chain: base.chain, blockNumber: base.number, blockHash: base.hash, ...o });
const withHeader = (h, o = {}) => leg({ headerRlp: h, ...o });
const q = (s) => JSON.stringify(s);
const mal = (field, reason, key) => `{"code":"finality_addendum_malformed","fields":{"field":${q(field)},${key ? `"key":${q(key)},` : ''}"reason":${q(reason)}}}`;
const broken = (member, want, got) =>
  `{"code":"finality_chain_broken","fields":{"check":"leg_binding","got":{${q(member)}:${q(got)}},"seq":"0","want":{${q(member)}:${q(want)}}}}`;
const bytes = (hex) => hex.length / 2;

const vectors = [];
const add = (name, input, expect, note, headerBytes) => vectors.push({ name, input, expect, note, ...(headerBytes !== undefined ? { headerBytes } : {}) });

add('leg_header_valid', section(withHeader(base.headerRlp)), 'ok', 'the real Base Sepolia header of the leg block: bound to blockHash and blockNumber', bytes(base.headerRlp));
add('leg_header_absent', section(leg()), 'ok', 'no headerRlp: the member predating this field, read as before', 0);
add('leg_header_of_another_block', section(withHeader(other.headerRlp)), broken('blockHash', '0x' + other.hash, '0x' + base.hash), 'a real header of another block (Adiri 498759): keccak256(header) is not the carried blockHash');
add('leg_header_wrong_block_number', section(withHeader(base.headerRlp, { blockNumber: base.number + 1 })), broken('blockNumber', String(base.number), String(base.number + 1)), 'the header hashes to blockHash but its positional number is not the carried blockNumber');
add('leg_header_upper_case_hex', section(withHeader(base.headerRlp.toUpperCase())), mal('leg.headerRlp', 'not_lowercase_hex'), 'hex is lower case only');
add('leg_header_odd_length', section(withHeader(base.headerRlp.slice(0, -1))), mal('leg.headerRlp', 'not_lowercase_hex'), 'an odd number of hex digits');
add('leg_header_0x_prefix', section(withHeader('0x' + base.headerRlp)), mal('leg.headerRlp', 'not_lowercase_hex'), 'no 0x prefix, as blockHash');
add('leg_header_empty', section(withHeader('')), mal('leg.headerRlp', 'bad_value'), 'an empty header is not a header: omit the member instead');
add('leg_header_number', section(withHeader(1)), mal('leg.headerRlp', 'bad_value'), 'a string only');
add('leg_header_null', section(withHeader(null)), mal('leg.headerRlp', 'bad_value'), 'null is never a value');
add('leg_header_oversized', section(withHeader('00'.repeat(16 * 1024 + 1))), mal('leg.headerRlp', 'bad_value'), 'more than MaxLegHeaderBytes (16384)');
add('leg_header_key_spelling', section(leg({ headerRLP: base.headerRlp })), mal('leg', 'unknown_key', 'headerRLP'), 'the member is spelled headerRlp');
add('leg_header_duplicate_key', section(withHeader(base.headerRlp)).replace('"headerRlp":', `"headerRlp":${q(base.headerRlp)},"headerRlp":`), mal('leg', 'duplicate_key', 'headerRlp'), 'a duplicate key is refused');
add('leg_header_not_a_block_header', section(withHeader('c0')), '{"code":"finality_evidence_malformed","fields":{"got_len":"0","part":"header","reason":"header_too_few_items","want_len":"12"}}', 'valid hex of an RLP list with no items: ReadHeader names it (the part of a block header that is missing)');

const out = { format: 'certen-finality-vectors/1', set: 'finality_chain3', kind: 'leg', runner: 'ParseSection(input), then section.leg.Ref() when the parse succeeded; expect is ok (and headerBytes = the length of the header the reference holds) or the canonical state', vectors };
const body = JSON.stringify(out, null, 2) + '\n';
writeFileSync(join(dir, 'legs.json'), body);
const sha = (b) => createHash('sha256').update(b).digest('hex');
const files = {};
for (const f of ['legs.json', 'README.md', 'generator/gen_chain3.mjs', 'generator/headers.json']) files[f] = sha(readFileSync(join(dir, f)));
const manifest = JSON.stringify({ format: 'certen-finality-vectors-manifest/1', set: 'finality_chain3', files }, null, 2) + '\n';
writeFileSync(join(dir, 'MANIFEST.json'), manifest);
writeFileSync(join(dir, 'MANIFEST.json.sha256'), sha(manifest) + '\n');
