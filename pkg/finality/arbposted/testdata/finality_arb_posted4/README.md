# finality_arb_posted4 - the findings of the completeness review V-E2-A1 (RB11-E2-FIX)

Spec: V2_SPEC_S7 r2 section 5.6 (O4: the block's transactions are matched against what a decoded message, or the proven delayed message,
derives), the bullet `[r2:E2B]`; Nitro source nitro@ccc5c82 `arbos/parse_l2.go` (`ParseL2Transactions`). The Go verifier is
`pkg/finality/arbposted` (`Kind.Verify`); the TypeScript verifier consumes a byte-identical copy of this directory and must return the same
canonical verdict bytes on every case. `finality_arb_posted1`, `2` and `3` are not edited.

## The four rules these cases pin

1. **A delayed-origin judgement must prove some content.** When the container carries a `Delayed` section (or the block holds a
   `0x64/0x65/0x66/0x69` transaction) the block's transactions other than `0x6a` and `0x68` must be, byte for byte, what Nitro derives
   from the proven delayed message. If BOTH lists are empty the equality is vacuous (the message is an empty batch, the block holds only
   the internal start-block transaction or nothing): no transaction of the block is shown to have been posted, and the verdict is
   `l1_posted_content_not_found{reason:"no_standard_transactions", batch}` - the state the sequencer branch already raises for a block with
   no content to match, one registered reason, no new code. (`l1_posted_delayed_origin_unproven` is kept for what it names: a missing
   `Delayed` section, a message that does not hash into the proven accumulator or was not consumed by this batch, a kind with no
   derivation, and a block whose transactions differ from the derived ones - `adv_delayed_empty_batch_block_holds_a_transaction`.)
   The guard sits after the byte-for-byte comparison, so a differing block never reaches it.
2. **A top-level sequencer message is capped like a nested one.** Nitro's `ParseL2Transactions` drops a message whose `L2msg` is longer
   than `MaxL2MessageSize` (262,144 bytes) before reading it. A message of exactly 262,144 bytes is parsed; 262,145 and longer is a
   failed message: no transactions, no match, but it keeps its ordinal (`valid_second_message_after_an_oversize_one`: ordinal 1 of 2).
   The message in the boundary cases is a batch message holding the block's transaction, then a length prefix above the cap (which ends
   a batch quietly), then zero padding, so the ONLY difference between the accepted and the refused case is the size of the message.
   (`adv_toplevel_message_over_cap_262194` is the size of the reviewer's probe.)
3. **`Kind.Verify` binds the BlockRef.** The container header's block number and hash must equal the BlockRef's (`finality_block_mismatch`
   `blockNumber`, then `blockHash`; the order and states of arbfinal and baseposted), and the BlockRef's own `header_rlp` must hash to
   the BlockRef's hash and carry its number (`blockHash`, then `blockNumber`, with `want` = the BlockRef and `got` = the header), judged
   before the pre-BoLD check. The cases alter the leg of a valid container; the evidence bytes are unchanged.
4. **Numeric pins are judged by presence.** `arb_sepolia.bold_genesis_l2_block`, `arb_sepolia.layout.acc_array_slot` and
   `arb_sepolia.layout.delayed_acc_array_slot` may legitimately be any value, so an absent (or JSON `null`) key must not decode as 0 and
   switch the pre-BoLD guard or a storage slot silently to 0: `pin_mismatch{field}` with the field `bold_genesis_l2_block`,
   `layout.acc_array_slot` or `layout.delayed_acc_array_slot`. The check runs after the section's other pins (the order of the earlier
   pin cases is unchanged). Every published pins file of sets 1-3 and the embedded pins carry all three keys, so no published verdict changes.

## The seven re-bound cases of finality_arb_posted1

Rule 3 changes the verdict of seven cases of set 1 (they pair a synthetic leg with the recorded container; see set 1's `SUPERSEDED.md`).
Here each appears again as `<id>_container_bound`: the same patched live evidence with ONLY the container header's block hash replaced by the
case leg's hash, under the pins file of set 1 (`pins/live.json`, byte-identical to set 1's `pins/main.json`), and under the expectation set 1
recorded: the match logic those cases were written for is unchanged. `raw/evidence.bin` is set 1's recorded live evidence (the base of the
patches).

## Controls

`valid_delayed_deposit_control` (an ETH deposit consumed by the batch is still `l1_posted`), `valid_toplevel_message_at_cap_262144`,
`valid_control_pins_present` and `adv_delayed_empty_batch_block_holds_a_transaction` pass or keep their state before and after the fix;
they pin that the guards are not wider than the rules above.

## Every case is synthetic

L1 side: the four-key test committee and a synthetic Bridge, as in finality_arb_posted1 / 2 / 3. L2 leg: the real header of
finality_arb_posted1 (`raw/leg.json`) with its `transactionsRoot` recomputed for the case's transaction list (the binding cases alter the
leg, not the evidence). Pins: `pins/synth.json` as in set 3 and six variants of it with one numeric pin absent or null. Format, files,
canonical form and the call are as described in finality_arb_posted2/README.md: `cases/<id>.json` = `{format, id, description, pins, leg,
evidence_base (empty), evidence_patch (the whole evidence), expect_canonical}`, `Kind.Verify(pins, leg, evidence)`. Every
`expect_canonical` is a literal written in the generator and checked against the verifier before the file is written.

## Double faults are not parity-tested

As in finality_arb_posted2: precedence among simultaneous faults is the order of checks of section 5.6; no case here has two faults.

## Regenerating

    finalityarbpostedrecord build4 -raw pkg/finality/arbposted/testdata/finality_arb_posted1/raw -out pkg/finality/arbposted/testdata/finality_arb_posted4

or, where `go run` is not used, `PV2_BUILD4_OUT=<this directory>` with `go test ./cmd/finalityarbpostedrecord -run TestBuild4`; without the
variable the same test rebuilds the set in a temporary directory and compares every file with this one.
