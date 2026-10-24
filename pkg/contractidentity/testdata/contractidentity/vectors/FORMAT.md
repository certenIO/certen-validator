# Published vector sets of the S8 contract-identity verifier (format `certen-contract-identity-vectors/1`)

Frozen with `V2_SPEC_S8.md` r3.2 (the sha256 of the frozen text is `SpecSHA256` in `names_gen.go`; r3.1 was `a08baa07eafc96d2b2dcff15635f11cb5f6a2b37e748fc7e77af1476f0a3766c`). Go (`pkg/contractidentity`, loader `vectors.go`)
and TypeScript consume the same bytes; any Go/TS verdict difference on any vector is stop-the-line. A change to this file is a new specification
revision.

## Files

| file | content | written by |
|---|---|---|
| `MANIFEST.json` (this directory) | the INDEX: one entry per row of Freeze inventory item 5 (`id`, `step`, `mutation`, `expectedText`, `expected`, `other_tokens`, `set`, `status`) lifted from the specification by `design/vectors/s8/lift.mjs`; `set` is the published set that contains the vector (null while `spec_only`) | `lift.mjs` |
| `<set>/` | one directory per PUBLISHED SET (below) | the vector packages |

The index is regenerated, never edited by hand. `status` is `spec_only` (no published file), `published` (a vector file of that id exists in `<set>`) or
`superseded` (its set has a `SUPERSEDED.md`).

## A published set `testdata/contractidentity/vectors/<set>/`

| file | content |
|---|---|
| `MANIFEST` | the sha256 of every other file of the directory, one line per file, sorted by file name: `<64 lowercase hex>␣␣<file name>` (LF line ends, no line for `MANIFEST` itself) |
| `<id>.inputs.json`, `<id>.expected.json`, `manifest.<sha256>.json`, `extension.<sha256>.json` | the MATERIALISED form of every vector (below): present for every vector of a set that a runner without a world builder (TypeScript) must run | the vector packages (`contractidentity.Materialise`) |
| `world.json` | the synthetic world H0 (the honest world that yields `verified`): block headers, node sets, code blobs, transaction and receipt leaves as lowercase hex, the manifest bytes and the context members, in the shape the world builder reads. Its content is the world builder's contract; it is JSON and nothing else here constrains it |
| `<id>.json` | one vector: `{id, base:"H0", mutations:[...], expected:{...}}` |
| `<id>.container.hex` | lowercase hex of the container bytes, present only where the container of the vector differs from H0's and is easier to state as bytes than as mutations (the mutation list may still apply after it) |
| `SUPERSEDED.md` | present only when a newer set replaces this one: names the replacing set and says why |

A set is **never edited**: a loader rejects a file that differs from its `MANIFEST` hash, an unlisted file, a listed file that is missing and a
directory inside the set. A correction is a NEW set (new directory name, new `MANIFEST`) and a `SUPERSEDED.md` in the old one. A vector id is
`VS8-nnn` (the row of item 5) or `VS8-nnn.<case>` where a row says "one vector per ..."; `<case>` is `[A-Za-z0-9_-]+`; the row is the part before the first dot.

## `<id>.json`

```json
{
 "id": "VS8-012.truncate_0302",
 "base": "H0",
 "mutations": [ { "op": "truncate", "target": "container", "length": 302 } ],
 "expected": {
  "headline": "refused",
  "states": [ { "part": "first", "code": "contract_identity_evidence_malformed",
                "fields": { "part": "attest", "index": "280", "reason": "truncated", "got_len": "3", "want_len": "4" } } ]
 }
}
```

`base` is always `"H0"`. `mutations` are applied to the artifacts of H0 in order. `expected`:

| member | meaning |
|---|---|
| `headline` | required; the headline kind (`refused`, `pending`, `unproven`, `verified_core`, `verified`, `not_applicable`) |
| `parts` | optional; `{<judged part>: <status>}`, each compared with the part status of the report |
| `states` | optional; `[{part, code, fields}]`; `part` is a judged part (its `state` must be this state) or `first` (the first refusal of a `refused` headline); `code` has the `contract_identity_` prefix |
| `open` | optional; the EXACT list of the report's Open entries in canonical order `[{part, kind, code, fields}]` |

`fields` are written in the **canonical form** of the state (the form Go and TypeScript compare): integers as decimal STRINGS, byte strings as `0x` + lowercase
hex, strings as strings, booleans as booleans, lists as lists; a JSON number never matches. States are compared by `code` and the canonical JSON of `fields`;
the context members (chain, block, ...) are not part of the comparison.

## Mutation operations (closed vocabulary)

A mutation has `op`, a `target` and only the members its operation uses. An operation outside this table, a member an operation does not use, or a missing
member makes the vector invalid (the loader refuses the set).

| op | target | members | effect |
|---|---|---|---|
| `set_byte` | `container` | `offset`, `value` (one byte as 2 hex digits) | replace one byte of the container bytes |
| `replace_hex` | `container` | `offset`, `old`, `new` (hex) | replace `old` at `offset` by `new` (`old` must be there; the length may change; no length field is repaired) |
| `truncate` | `container` | `length` | keep the first `length` bytes |
| `append_hex` | `container` | `value` (hex) | append bytes |
| `drop_node` | `container` | `index` | decode, remove `nodes[index]`, re-encode canonically |
| `add_node` | `container` | `value` (hex) | decode, insert the node at its keccak256 position, re-encode canonically (a unique, sorted, unreferenced node) |
| `reorder` | `container` | `list` (`codes`, `nodes`, `hopHeaders`, `spine`, `blockTxs`) | decode, reverse that list, re-encode WITHOUT validation (`EncodeUnvalidated`) |
| `set_field` | `container`, `context`, `manifest`, `extension`, `world` | `path` (dot path in the JSON form of the target), `value` (JSON) | set a member of the structured form; for `container` the result is re-encoded WITHOUT validation; for `manifest` the manifest hash pin is recomputed unless the vector is about the pin (`world` decides) |
| `unset_field` | `container`, `context`, `manifest`, `extension`, `world` | `path` | remove a member (a context member becomes zero / nil) |

The structured JSON form of `container` is `{chain, leg:{number,hash}, codes:[{address,runtime}], settle:{tag,stated?}, attest:{tag,stated?|attest?}, nodes:[hex]}`
with hex for every byte string and decimal strings for integers; `context` is the `LegContext` members by the lower-case tokens of Freeze item 2a
(`settlement`, `tx`, `receipt`, `adi_url`, `s6_status`, `s6_reason`, `s6_state`, `s6`, `batch.batchRoot`, ..., `registry9`, `s7`); `manifest` and `extension` are
the manifest documents themselves.

## Running a vector

A runner turns `world.json` and the vector into `{LegContext fields, container, manifest, extension}` (the `WorldBuilder` of `vectors.go`), runs the
`Verifier` (`Verify(ctx, container, manifest)`) and compares the Report with `expected`. The outcomes are:

* `pass` - a Verifier judged the inputs and the Report satisfies `expected` exactly;
* `fail` - the world could not be built, the Verifier returned an error, or the Report does not satisfy `expected` (an empty Report never satisfies anything);
* `not_run` - there is no world builder or no Verifier. A runner without a Verifier reports every vector `not_run`, never `pass`.

## Decode error fields (the numbers inside `evidence_malformed`, shared by Go and TypeScript)

`evidence_malformed{part, index, reason, got_len, want_len}` carries all five fields; a number that does not apply is `"0"`.

| reason | part | index | got_len | want_len |
|---|---|---|---|---|
| `bad_magic` | `magic` | 0 | 0 | 0 |
| `truncated` | the part of the read that failed (an `lp` length prefix and its body belong to the same part) | byte offset where that read started (for an `lp` body: after its length prefix) | bytes remaining | bytes the read needs |
| `trailing_bytes` | `container` | offset of the first trailing byte | trailing byte count | 0 |
| `codes_not_ascending`, `codes_duplicate` | `codes` | index of the offending code | 0 | 0 |
| `nodes_not_ascending`, `nodes_duplicate` | `nodes` | index of the offending node | 0 | 0 |
| `unknown_part_tag` | `settle` or `attest` | offset after the tag byte | 0 | 0 |
| `unknown_link` | `attest` | offset after the link byte | 0 | 0 |
| `bad_stated_state`, `bad_stated_reason` | `settle` or `attest` | offset after the offending STR | 0 | 0 |
| `string_not_ascii` | `kind`, `settle` or `attest` | offset after the offending STR | 0 | 0 |
| `nodes_unreferenced` (step 22b, verifier rule) | `nodes` | index of the first node no walk visited | 0 | 0 |
| `unknown_stated_reason` (step 1c(b) / 15, verifier rule, `Container.CheckStatedReasons`) [r3.2:E-f] | `settle` or `attest` (settle first) | 0 | 0 | 0 |

Parts of `evidence_too_large{part, count, limit}`: `container` (total size), `kind` (> 64), `codes` (count > 16, or a runtime > 262144), `nodes` (count or a node), `attest`
(a header or a leaf), `hopHeaders` and `spine` (count or a header), `blockTxs` (count, one transaction, or the total), `failures` (count, or any `Stated` text > 1024).
The reads of `chain`, `leg.number` and `leg.hash` are part `container`; the `kind` STR is read before anything else but the magic, and a `kind` of at most 64
bytes that differs from `contract-identity/v1` is `evidence_unrecognised{kind, version}` with `version` the text after the last `/`.

## Canonical report order (Freeze item 2b)

`parts` by part name; `open` and `findings` by `(part, code, canonical JSON of the fields)` bytewise; `rules_judged` by rule id; `rules_not_judged` by `(row, reason)`;
`residuals` by id. `findings` is present only in a `pending` headline that has findings.

## Materialised vectors [r3.2:E-i]

A runner that cannot rebuild the Go world (the TypeScript runner) reads, per vector, files that hold everything already resolved. A vector of a materialised
set has, besides `<id>.json` (provenance: base, mutations, expected):

| file | content |
|---|---|
| `<id>.inputs.json` | `{format:"certen-contract-identity-inputs/1", id, container, manifest, extension, context}` (below) |
| `<id>.expected.json` | exactly the `expected` object of `<id>.json` (a loader refuses a set in which they differ) |
| `<id>.container.hex` | lowercase hex of the container bytes the Verifier receives (always present when `container` is not null) |
| `manifest.<sha256>.json`, `extension.<sha256>.json` | the raw manifest / extension DOCUMENTS, named by the sha256 of their bytes (identical documents are stored once per set) |

`container` and `extension` are `null` or `{file, sha256}`; `manifest` is `{file, sha256, pin}` where `pin` (0x hex) is the hash the manifest bytes must have when loaded:
the embedded pin `ManifestSHA256` for an unmodified manifest, the hash of the bytes for a modified but valid manifest (the runner then reports manifest_source
`override:<sha256>`), anything else for a vector about a corrupt manifest. The `sha256` of every referenced file is checked by the loader, and every file is in the set's `MANIFEST`.

**The runner resolves step 0 itself.** It loads the manifest document against `pin` (`manifest_corrupt` on a mismatch), merges the extension under the no-shadow rule
(`manifest_shadow`, `manifest_unknown{chain}`) and, when either fails, the RESULT of the vector is the refused headline whose `first` is that framework state - the
Verifier is not called (it refuses to start). Otherwise it calls `Verify(context, container, manifest)`.

`context` (canonical-style JSON: bytes as lowercase `0x` hex, integers as decimal strings; a member that is absent is `null`):

| member | form |
|---|---|
| `chain` | decimal string |
| `settlement` | the `ethproof.Settlement` JSON of the proof file (`block_hash`, `block_header_rlp`, `tx_hash`, `tx_inclusion_proof`, `receipt_inclusion_proof` with the ethproof field names) |
| `tx` | the typed wire encoding of the transaction (EIP-2718), 0x hex |
| `receipt` | `{type, post_state_or_status, cumulative_gas_used, bloom, logs:[{address, topics:[...], data}]}` |
| `adi_url`, `s6_status`, `s6_reason`, `s6_state` | strings |
| `s6` | `{contract, leaf_key, settlement_block:{number,hash}, proven_at:{number,hash}, code_hash}` |
| `batch` | `{batch_root, batch_operation_id, acc_set_root, incarnation}` |
| `registry9` | `{members:[{address, power, bls_key}], num, den, certen_set_root, signer_commitment}` (`bls_key` lowercase hex without 0x, 192 characters) |
| `s7` | `{block:{chain,number,hash}, headline, levels:{<level>:{status, code}}, unsupported, finalized_block:{number,hash,state_root}}`: the S7 report members that S8 reads (step 24): per level the status and the CODE of its state when it is not verified, the headline level name (`none` for none), the leg's finalized block, the unsupported-chain state code ("" none). Levels: `included`, `l1_posted`, `finalized`. |

A set written by the world builder (`world.WriteSet`) before this format carries no `<id>.inputs.json`; a loader accepts it and the runner needs the world builder for those vectors.
