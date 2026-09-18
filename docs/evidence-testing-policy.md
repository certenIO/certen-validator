# Testing policy for evidence-bearing code

"Evidence-bearing" means any code that writes, reads or publishes a claim about what happened: anchor
rows, quorum records, layer-5 bindings, proof artifacts, schema history. Two rules. Both exist because
they are what actually found the defects between 2026-09-15 and 2026-09-18, and the ordinary practices
around them did not.

---

## 1. Golden vectors come from the real system, not from a fixture you wrote

**A fixture you wrote cannot contradict your assumption. The chain can.**

The backfill compared the anchor's `operationCommitment` (tuple index 3) against the calldata's operation
id. Every hand-built test passed, because the fixtures were built from the same belief as the code. Run
against the deployed anchor it refused all 313 candidates, because a batch anchor leaves index 3 **empty**
and binds at index 7 instead:

```
[ 1] merkleRoot           0xd4d5fe5c…
[ 3] operationCommitment  0x00000000…   EMPTY on a batch anchor
[ 7] operationID          0x6ba3ae63…   the one that binds
```

That exact 15-word response is now pinned verbatim in `TestDecodeAnchorStateReadsTheLiveAnchorLayout`.

**The rule.** When a test asserts something about an external system's shape — an ABI tuple, an RPC
response, a wire format — capture a real response and commit it, with the date and the address or
transaction it came from. Note in the comment *why* those particular bytes are the interesting ones.

**Where this applies beyond the anchor:** the `certen_schema_history` checksums (they are hashes of real
file bytes — see the CRLF note below), layer-5 `layer_json` shapes, and the gateway's intent envelope.

## 2. Mutation-verify every evidence test

**A test over evidence that has never been seen to fail is decoration.**

The discipline: break the line the test exists for, watch it go red, restore. It takes under a minute.

In this work it caught, three separate times, a test that could not fail:

| Test | What it missed |
|---|---|
| `TestMembersFromTreeCarryTheIntentIdOnTheCadenceLane` | built `BatchLeafInput` directly, bypassing `LeafInput()` — the plumbing it existed to cover |
| the anchor-state decode | asserted on a hand-built struct, never on the tuple index that was wrong |
| the writer's member mapping | neither neighbouring test reached `AnchorQuorumRecordFrom`; the `accumulate_tx_hash` line was uncovered |

Each looked like real coverage. Each would have let the defect through.

**The rule.** A pull request that adds or changes an evidence test states, in the description, which line
was broken to verify it and what the failure said. If breaking the line does not turn the test red, the
test is not testing that line.

## 3. Two traps worth knowing (they cost hours)

**Line endings are part of the contract where bytes are hashed.** `db/schema.go` hashes migration file
bytes into `certen_schema_history`, so a CRLF checkout produces a binary whose baseline hash differs from
the one a Linux build wrote — and that binary refuses to start against a healthy production database,
reporting `checksum mismatch`, which reads like corruption. `.gitattributes` pins `db/migrations/*.sql`
and `db/*.fingerprint` to LF. If you edit files with a script on Windows, write bytes (`'wb'`), not text.

**Tests must build their schema with the production runner.** `schema.Runner.Up()`, never a hand-written
`CREATE TABLE`. A hand-rolled fixture drifts from production one `NOT NULL` at a time, and worse, it can
be green while production rejects the identical write — which is exactly what happened with
`valid_batch_type`. `pkg/database/legacy_catalog_frozen_test.go` guards the related failure: a migration
placed in the retired catalog, where nothing would ever apply it.

---

## The pattern underneath all of it

Every defect in that window was a claim that was **structurally unfalsifiable** — nothing in the system
could have disagreed with it:

| Claim | Reality | Found by |
|---|---|---|
| "root `d2d24ab3…` is in tx `0x9e4ff6ab…`" | that root was never published | reading layer 5 by hand |
| "quorum met" | read from a per-validator shadow row | code audit |
| backfill refuses everything | wrong tuple index | first live dry run |
| canonical row complete | `anchor_create_tx` blank | first live gate |
| migration merged and deployed | landed in a retired catalog | hand-checking a constraint |

The fixes that held were the ones that made the claim checkable against something that does not share the
code's assumptions: the chain, a real response, a standing query, a deliberately broken line. That is the
whole policy — everything above is a specific way of doing it.
