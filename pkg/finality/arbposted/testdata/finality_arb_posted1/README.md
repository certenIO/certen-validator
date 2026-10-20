# finality_arb_posted1 - published conformance vectors for arb-sepolia/l1_posted/v1

Spec: V2_SPEC_S7 r2 sections 3.3 and 5.6, annex R11-arbitrum-sepolia A6. The Go verifier is `pkg/finality/arbposted`
(`Kind.Verify`); the TypeScript verifier consumes a byte-identical copy of this directory and must return the same
canonical verdict bytes on every case.

## Files

| path | content |
|---|---|
| `raw/evidence.bin` | the LIVE CFE1 container (kind `arb-sepolia/l1_posted/v1`, level 2) built by `Builder.BuildFor` from rows the capture runner stored, and accepted by the verifier |
| `raw/leg.json` | the Arbitrum Sepolia block it is about: hash, number, raw RLP header, the consensus encodings of all its transactions |
| `raw/pins.json` | the pins file the live case is judged under: the embedded pins plus ONE Sepolia ledger entry for the signing period (its `derived_by` says it was read from a Lodestar bootstrap: a vector pin, not an independent derivation) |
| `raw/capture.json` | when and from where it was recorded |
| `pins/<name>.json` | `main` (= raw/pins.json) and variants that alter exactly one pin |
| `cases/<id>.json` | one case |
| `MANIFEST.json` | sha256 of every file under raw/, pins/ and cases/; `MANIFEST.json.sha256` is the sha256 of the manifest |

## A case

`{format, id, description, pins, leg{chain, number, hash, header_rlp}, evidence_base, evidence_patch{at, del, ins}, expect_canonical}`.
The evidence is `base[:at] || ins || base[at+del:]` with `base` = `raw/evidence.bin` (`ins` is `0x` hex). The leg is the BlockRef
handed to the verifier (`header_rlp` is `Settlement.Header`, the L2 header; it is NOT part of the evidence). A case whose leg
differs from `raw/leg.json` states a different transaction list for the leg block (header root recomputed), over the same real evidence.
The pins are parsed as an override pins file (hash not checked). The call is `Kind.Verify(pins, leg, evidence)`.

## Expected verdicts

`expect_canonical` is the canonical text of the verdict: `{"code":"verified","fields":{...}}` for an accepted case (fields: the
verdict fields plus `kind` and `level` as the level name) or `{"code":<state>,"fields":{...}}` for a named state. Canonical form:
keys sorted at every level, no whitespace, EVERY integer a decimal string, every byte string `0x` + lower-case hex, a list of integers
a list of decimal strings. The literals are written in `cmd/finalityarbpostedrecord/build.go`, not computed from the verifier; `build`
refuses a case whose verdict differs from its literal.

## Check order (the first failing check names the state)

kind string / chain / level of the container header; pins (`arb_sepolia` present, chain ids, bridge, layout, bounds) and the KZG setup pin;
container decode (strict, bounded); the L2 header's number against `bold_genesis_l2_block` (`pre_bold_block`); the ordered-trie root of
`blockTxs` against the header's transactionsRoot; `dataKind 3` (`no_data_batch`); the L1 finalized head from the LC (`l1_finality_unproven
{lc_refused}`); the spine (`spine_refused`); `stateBlock` on the spine; Bridge account, EIP-1967 implementation slot and implementation
code hash (`bridge_impl` pin); `acc_N` from the Bridge storage; for calldata the data flag; the recomputed accumulator; blobs (count,
versioned hash, KZG blob proof); the payload (header byte, brotli, segments); block transaction classification; the delayed section when
the block holds a 0x64/0x65/0x66/0x69 transaction; the message match.

## Regenerating

    finalityarbpostedrecord record -store <capture dir of cmd/finalityarbpostedcapture> -out <raw dir> -batch N     # network
    finalityarbpostedrecord build  -raw <raw dir> -out pkg/finality/arbposted/testdata/finality_arb_posted1         # offline, deterministic
