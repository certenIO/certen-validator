# finality_adiri5 (RB11-F1-FIX): link-kind-2 leg binding and the min_committee_size floor

New evidence, new set: finality_adiri1/2/3/4 stay byte-identical. This README is not hashed by MANIFEST.json (the manifest pins
vectors.json and the evidence files; editing this text changes no hash). For the Go verifier and the TypeScript port alike.

Format finality_adiri5/1, the SAME vector shape as finality_adiri3 (name, group, note, leg{chain,number,hash,header_hex?}, pins,
evidence, expect). Every `expect` is a literal composed by `pkg/finality/adiri/vectorgen/set5.go` (canonical text, sorted keys, every
value a string); the verifier under test is never called to produce one. 14 vectors.

## group slot (10): linkKind 2, the leg is bound to the EIP-2935 ring

Each evidence file is a single-epoch chain (five synthetic committee keys, all five sign) whose seal header F commits to a synthetic
EIP-2935 account (the real runtime code, the pinned code hash) holding exactly the slots the vector needs. The window rule:
F.number - N <= 8190 (MaxSlotDistance, the spec's bound: 3.3 "F.number - N <= 8190"; the ring holds 8191 hashes). Order of the new
checks inside linkKind 2, after `N = F` (link_kind_2_at_seal) and before the final header is read:

1. `F - N > 8190` -> `finality_block_mismatch{field:"slotDistance", want:8190, got:F-N}`
2. leg hash all zero -> `finality_block_mismatch{field:"legHash", want:"nonzero", got:0x00..00}`
3. when the leg carries its header: unreadable -> `finality_link_broken{from:F, to:N, at:N, check:"header_decode"}`; keccak256(header)
   != leg hash -> `finality_block_mismatch{field:"legHeaderHash", want:<leg hash>, got:<keccak256(header)>}`; header number != N ->
   `finality_block_mismatch{field:"legHeaderNumber", want:N, got:<header number>}`

Then the existing checks (final header = F, account code hash, proof, slot value; a proven-absent slot is a zero value and so
`slot_value_mismatch` for any non-zero leg hash).

| vector | pins |
|---|---|
| slot5-window-edge-8190-accepted | F=20000, N=F-8190: finalized, distance 8190 |
| slot5-window-8191-refused | N=F-8191, slot holds the leg hash: slotDistance 8190/8191 |
| slot5-alias-9000-claimed-809 | block really numbered 9000 (its header is the leg's) claimed as 809, F=12000: both are ring slot 809 and the slot holds block 9000's hash; slotDistance 8190/11191 |
| slot5-alias-9000-claimed-809-no-leg-header | the same evidence and claim without the leg header: same refusal |
| slot5-zero-leg-hash-absent-slot | all-zero leg hash, slot proven absent: legHash |
| slot5-leg-hash-absent-slot | real leg hash, slot proven absent: slot_value_mismatch (got zero) |
| slot5-leg-header-ok | control: the leg's header hashes to the leg hash and carries N: finalized |
| slot5-leg-header-number-mismatch | in-window; header (hash = leg hash = slot value) is block 11000, leg says 11500: legHeaderNumber |
| slot5-leg-header-hash-mismatch | in-window; the header is block 11500's, the leg hash is block 11000's: legHeaderHash |
| slot5-leg-header-undecodable | leg header `c0`: header_decode at N |

## group pins (4): min_committee_size >= 4

Each judges `Verify(pins, leg, evidence)` of finality_adiri3's `syn-rotation` evidence (copied to `evidence/syn-rotation.bin`) under
that vector's inline adiri pins section with `min_committee_size` changed. `pins5-min-committee-size-4-control` is the floor itself
and gives syn-rotation's verdict; sizes 3, 2 and 1 are `finality_pins_corrupt{key:"adiri.min_committee_size", reason:"bad_value"}`.
Telcoin's own rule lets a committee shrink only to at least 4 members (annex A4 "when smaller: len >= 4"; V2_SPEC_S7 4.2 pins 4):
a pin is a verifier user's strictness on top of that rule, never a relaxation of it (finality_adiri4 already pins 0 as bad_value).

## Not vector-expressible (Go unit tests only; the TypeScript twin needs the same tests)

`VerifyCommitteeChain` is exported and judges any CFA1. It re-applies the decoder's rules to every record before it indexes
anything: table indices (`finality_evidence_malformed{part:"cfa1.record", index, reason:"table_index_out_of_range"}`) then signer
indices strictly increasing and below the committee size (`committee_chain_broken{check:"signer_index_invalid", index, signer,
committee_size}`). `Verify` never reaches the difference (DecodeCFA1 refuses first), so no vector can show it.

## Regeneration

The synthetic keys are drawn once from a random seed kept only in the gitignored `pkg/finality/adiri/vectorgen/keys/` (the vectors
hold public keys and signatures only); the committed bytes are the specification. A build from the same seed is byte-identical
(`TestAdiri5BuildsDeterministicallyFromOneSeed`); a build from another seed is a different set. Written by running that test with
`ADIRI5_OUT=<dir> ADIRI5_KEYS=<seed dir>` through the programme's Go wrapper, or `go run ./pkg/finality/adiri/vectorgen -mode adiri5
-out <dir>` where the module cache is available.
