# finality_arb_posted3 - a malformed sequencer message is not a message (RB11-E2B, second box)

Spec: V2_SPEC_S7 r2 section 5.6 (statement 1.1: "a message whose signed transactions are exactly this block's signed transactions") and the
bullet `[r2:E2B]`; Nitro source nitro@ccc5c82 `arbos/parse_l2.go` (`parseL2Message`, `ParseL2Transactions`). The Go verifier is
`pkg/finality/arbposted` (`Kind.Verify`); the TypeScript verifier consumes a byte-identical copy of this directory and must return
the same canonical verdict bytes on every case. `finality_arb_posted1` and `finality_arb_posted2` are not edited.

## The rule these cases pin

A sequencer-batch L2 message (segment kind 0, or kind 1 after Brotli) is parsed as Nitro parses it with no L1 request id:

* kind 4 (signed tx): the rest of the message is ONE transaction. A transaction whose first byte is not a legacy list (>= 0xc0) and not
  1, 2 or 4 (Arbitrum types >= 0x64, the blob type 3, any unknown type) or that is empty FAILS the message. Nothing else is unmarshalled:
  the bytes are compared with the block's own transactions, which are valid by construction, so an invalid message transaction can never equal one.
* kind 3 (batch): nested messages `u64 length || message`, depth below 16 (a batch at depth 16 fails the message). A length prefix that is cut,
  larger than 256 KiB, or past the data ends the batch QUIETLY with what it has (the message stays valid).
  ANY nested message that fails fails the WHOLE message, not just that nested one.
* kind 0 (unsigned user tx): its fields (gas, max fee, nonce, to, value) must parse; it is built from the poster and is not a signed
  transaction, so it adds none and does not fail the message. Kind 1 (a contract tx needs an L1 request id), 2, 6 (heartbeats are disabled),
  7 and every unknown kind FAIL the message.
* A failed message has no transactions and matches no block, but it is still a message of the batch: it keeps its ordinal
  (`valid_second_message_after_a_failed_one`: ordinal 1 of 2).

Before this set the verifier skipped a failing nested message and kept the others, so `[t1, t2, <kind 2>]` matched a block of `t1, t2` although
Nitro drops the whole message (`adv_message_*` answer `verified` at 3a16e7c and `no_matching_message` now).

## Stricter by design (not a Nitro difference to port)

Nitro keeps the first 102,400 segments of a batch and ignores the rest (`MaxSegmentsPerSequencerMessage`); the verifier REFUSES a batch with
more segments than the pinned `max_segments` (`finality_evidence_too_large{part:"segments"}`, V2_SPEC_S7 8.2: a bound never truncates). A TS port must
refuse, not truncate. (finality_arb_posted1 holds the 102,401-segment case.)

## Every case is synthetic

L1 side: the four-key test committee and a synthetic Bridge, as in finality_arb_posted1 / 2. L2 leg: the real header of finality_arb_posted1
(`raw/leg.json`) with its `transactionsRoot` recomputed for the case's transaction list. Format, files, canonical form and the call are as
described in finality_arb_posted2/README.md: `cases/<id>.json` = `{format, id, description, pins, leg, evidence_base (empty), evidence_patch
(the whole evidence), expect_canonical}`, `Kind.Verify(pins, leg, evidence)`.

## Double faults are not parity-tested

As in finality_arb_posted2: precedence among simultaneous faults is the order of checks of section 5.6; no case here has two faults.

## Regenerating

    finalityarbpostedrecord build3 -raw pkg/finality/arbposted/testdata/finality_arb_posted1/raw -out pkg/finality/arbposted/testdata/finality_arb_posted3
