# finality_arb_posted2 - strictness and completeness vectors for arb-sepolia/l1_posted/v1 (RB11-E2B)

Spec: V2_SPEC_S7 r2 sections 3.3 and 5.6, annex R11-arbitrum-sepolia A6; Nitro sources nitro@ccc5c82 (`arbstate/inbox.go`,
`arbos/parse_l2.go`, `zeroheavy/zeroheavy.go`). The Go verifier is `pkg/finality/arbposted` (`Kind.Verify`); the TypeScript verifier
consumes a byte-identical copy of this directory and must return the same canonical verdict bytes on every case.
`finality_arb_posted1` is not edited; its two zero-heavy expectations that changed are recorded in its `SUPERSEDED.md`.

## Every case is synthetic, and says so

There is no recording here. The L1 side of every case is a synthetic Bridge state under a synthetic finalized head signed by a four-key
test committee (secret scalars derived from fixed labels at generation time and never stored), exactly as in the synthetic half of
finality_arb_posted1. The L2 leg is the REAL Arbitrum Sepolia block header of finality_arb_posted1 (`raw/leg.json`, copied) with its
`transactionsRoot` recomputed from the case's transaction list; a case's `leg.hash` is the hash of that altered header. Delayed-inbox
messages of the kinds below (submit retryable, unsigned / contract / batch L2 messages, L2 funded by L1) and zero-heavy batches did not occur
in the captured window of Arbitrum Sepolia, so no positive case is a recording of a live one; the delayed-message derivations are checked
against the Nitro source and, independently, by `arbposted/derive_test.go`, which restates go-ethereum's `arb_types.go` field orders.

## Files and a case

As in finality_arb_posted1: `MANIFEST.json` (sha256 of every file under `raw/`, `pins/`, `cases/`) and `MANIFEST.json.sha256`; `pins/synth.json` is the
embedded pins file with a synthetic Sepolia network section (fork schedule, genesis validators root, one ledger entry for the committee
root); `cases/<id>.json` is `{format, id, description, pins, leg{chain, number, hash, header_rlp}, evidence_base, evidence_patch{at, del, ins},
expect_canonical}`. `evidence_base` is empty in this set: the whole evidence is `evidence_patch.ins` (`0x` hex, at 0, del 0). The call is
`Kind.Verify(pins, leg, evidence)`; `expect_canonical` is the canonical text (sorted keys, no whitespace, every integer a decimal string,
every byte string `0x` + lower-case hex). The literals are written in `cmd/finalityarbpostedrecord/synth2.go`, not computed from the
verifier; `build2` refuses a case whose verdict differs from its literal.

## What the cases pin

* **Brotli streams are complete or refused.** `andybalholm/brotli` returns a clean EOF when its source ends while the decoder still wants input,
  so a stream cut short decoded to a prefix with no error; Nitro (`arbcompress.Decompress`) and every standard decoder refuse it. The
  verifier now refuses (`l1_posted_content_not_found{reason:payload_undecodable}`) a batch stream cut at ANY byte of a short stream
  (`adv_brotli_short_stream_cut_to_*`, every length from 2 to len-1), cut by 1, 2, 8 bytes and in half behind a needed message
  (`adv_brotli_batch_cut_*_byte`), the header byte alone, and a byte after a complete stream. A per-message Brotli segment (segment kind 1)
  that is cut, empty or followed by a byte is DROPPED like Nitro drops it (`no_matching_message` with `messages_scanned 0`). Controls
  (`valid_brotli_*`) show the same bytes accepted when complete.
* **The zero-heavy layer (header byte 0x20)** is decoded once, with the bound 101% of the batch bound + 64 (an excess is the uncompressed-batch
  bound), and the result must begin with the Brotli header byte; a second layer, a DAS byte, or any other byte after the layer is
  `l1_batch_header_unknown{byte: that byte}` (Nitro reads nothing else after the layer); the flag alone decodes to nothing (`payload_undecodable`).
  Positive cases in calldata mode and in a KZG-verified blob.
* **Delayed-origin blocks.** When the container carries a Delayed section (or the block holds a 0x64 / 0x65 / 0x66 / 0x69 transaction) the block's
  transactions other than the internal 0x6a and the execution-derived retry 0x68 must be, byte for byte and in order, what Nitro derives from
  the proven message: ETH deposit (kind 12), submit retryable (kind 9), L2 message (kind 3) holding an unsigned tx, a contract tx or a batch of
  them (sub-request ids `keccak256(requestId || index)`), L2 funded by L1 (kind 7: a deposit to the poster with From unset, then the unsigned tx
  under `keccak256(requestId || 1)`). The chain id is part of the compared bytes. A message kind with no derivation (13, batch posting report)
  stays `l1_posted_delayed_origin_unproven`.

## Double faults are not parity-tested

A container may carry two faults at once; which state it reports is the first failing check of V2_SPEC_S7 section 5.6, and an implementation
may differ from another only where a fault is detected at a granularity its decoder cannot expose. No case in this set has two faults: in
particular a Brotli stream that is both over the uncompressed cap AND corrupt after the cap point is not tested (Go reports
`finality_evidence_too_large{uncompressed_batch}` because it stops reading at the cap; a node or a one-shot decoder reports
`payload_undecodable`). Both are refusals.

## Regenerating

    finalityarbpostedrecord build2 -raw pkg/finality/arbposted/testdata/finality_arb_posted1/raw -out pkg/finality/arbposted/testdata/finality_arb_posted2

`build2` is offline and deterministic (the secret scalars and every random-looking byte come from fixed labels and fixed seeds).
