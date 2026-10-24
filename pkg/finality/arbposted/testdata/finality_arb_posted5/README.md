# finality_arb_posted5 - the binding of the BlockRef to the container (RB12-ARBFINAL-FIX, BETA audit G2)

Spec: V2_SPEC_S7 r2 section 5.6. The Go verifier is `pkg/finality/arbposted` (`Kind.Verify`); the TypeScript verifier consumes a byte-identical copy
of this directory and must return the same canonical verdict bytes on every case. `finality_arb_posted1` to `4` are not edited.

## What it pins

`Kind.Verify` judges first that the container is about the block the caller asks about: the container header's block number equals the BlockRef's
number (`finality_block_mismatch{field: blockNumber, want: the BlockRef's, got: the container's}`), then its block hash equals the BlockRef's hash
(`blockHash`). Later it judges that the BlockRef's own `header_rlp` hashes to the BlockRef's hash and carries its number (`blockHash`, then
`blockNumber`, with `want` = the BlockRef and `got` = the header).

The two cases of `finality_arb_posted4` that name the container binding (`adv_leg_number_differs_from_container`, `adv_leg_hash_differs_from_container`)
alter the leg's number or hash and leave its header alone, so the leg also disagrees with its OWN header; the later header checks answer the same
state with the same fields. The container binding is therefore pinned by no vector in sets 1 to 4: removing it changes no published verdict.

These cases give the leg a header of its own that agrees with it, so the leg is consistent and ONLY the container disagrees:

- `adv_leg_number_differs_from_container_leg_header_agrees`: the leg is block n+5 with a header that carries number n+5 (so its hash differs as
  well); the container is about block n. `finality_block_mismatch{blockNumber, want: n+5, got: n}`. The number is judged before the hash, so
  this case also pins the order of the two checks (a verifier that judged the hash first answers `blockHash`).
- `adv_leg_hash_differs_from_container_leg_header_agrees`: the leg is block n with a header of its own that differs from the container's block only in its
  `extraData` (same number, same transactions, another hash); the container is about the original header.
  `finality_block_mismatch{blockHash, want: the leg's hash, got: the container's}`. Without the container binding the rest of the evidence verifies
  and the leg is `verified` under a hash the container is not about.
- `valid_control_leg_and_container_agree`: the control, `verified`: the leg and the container are about the same block and the leg's header is its own.

## Every case is synthetic

L1 side: the four-key test committee and a synthetic Bridge, as in `finality_arb_posted3` / `4`. L2 leg: the real header of `finality_arb_posted1`
(`raw/leg.json`) with its `transactionsRoot` recomputed for the case's transaction list, and for the two adversarial cases the one header item
edited that the case names. Pins: `pins/synth.json`, byte for byte the file of sets 3 and 4. Format, files, canonical form and the call are as
described in `finality_arb_posted2/README.md`: `cases/<id>.json` = `{format, id, description, pins, leg, evidence_base (empty), evidence_patch
(the whole evidence), expect_canonical}`, `Kind.Verify(pins, leg, evidence)`. Every `expect_canonical` is a literal written in the generator
(`cmd/finalityarbpostedrecord/synth5.go`, `build5`) and checked against the verifier before the file is written. `build5` reads the pins from set
4 and not from the embedded pins, so the set regenerates byte for byte whatever the embedded pins file holds
(`TestBuild5WritesTheCommittedSetByteForByte`).

## Double faults are not parity-tested

As in `finality_arb_posted2`: precedence among simultaneous faults is the order of checks of section 5.6; the number case above has two
disagreements by construction (a header of block n+5 has another hash) and is the pin of that order; no other case has two faults.
