# What Accumulate must expose for CERTEN to verify L3/L4

**Audience:** Accumulate core.
**Status:** proposal · **Written:** 2026-07-28.
**Target:** the network as it runs **today** — CometBFT. DAG-BFT is deliberately
out of scope; it has not shipped, and an API that waits for it delivers nothing
in the meantime.

---

## 1. The ask in one paragraph

CERTEN validators carry an Accumulate proof inside every block they agree on.
Today that proof holds Merkle receipts and nothing else, so a verifier can
confirm the receipts are internally consistent but cannot confirm the anchor
they reach is one Accumulate actually produced. Closing that needs one thing:
**the commit that attests a block, served as a self-contained, verifiable
object.** Everything below already exists inside a CometBFT node — this is an
exposure and framing problem, not new cryptography.

Two documents already draft most of this
(`L3_CONSENSUS_PROOF_API_REQUIREMENTS.md`, `L4_VALIDATOR_API_REQUIREMENTS.md`).
This is the same ask, reduced to what is strictly required and stated in terms
of what a client must be able to *recompute*.

---

## 2. Design principle: proof-bearing, not trust-bearing

Every response must be verifiable **without a second call and without trusting
the responder**. A client behind a hostile proxy, a stale mirror or a
compromised node must reach the same verdict as one talking to an honest node —
otherwise the endpoint has moved trust rather than removed it.

Each response must be checkable using only its own bytes, a validator set the
client already holds, SHA-256 and ed25519.

A field the client cannot recompute is a field the client must not rely on.
`verified: true` flags, status strings and server-side assertions are worse than
useless here: they invite precisely the trust the proof exists to eliminate.
CERTEN's own carried proof has a `Verified bool` today and the verifier
**ignores it** for exactly this reason.

---

## 3. The one structural detail that shapes everything

In CometBFT, `Header.AppHash` at height **H** is the application state *after
executing block H−1*. The state produced by block H appears in the header of
block **H+1**.

So proving "Accumulate's state root at block H" requires the header and commit
of **H+1**, not H. This is not a subtlety to be discovered by the implementer;
it must be explicit in the API, or every consumer will get it wrong once and
silently prove the wrong thing.

Two workable framings — either is fine, but one must be chosen and documented:

- **Client-facing height means "state after this block"**, and the service
  internally serves H+1's header/commit. Friendlier, hides a real trap.
- **Client-facing height is literal**, and the docs state plainly that callers
  wanting state at H must request H+1.

---

## 4. What CERTEN needs

### 4.1 `BlockHeaderQuery` — the canonical header at a height

**Request:** partition, height.

**Response:** every field that goes into the header hash, in the order it is
hashed, plus the resulting hash:

```
version {block, app}, chain_id, height, time,
last_block_id {hash, parts {total, hash}},
last_commit_hash, data_hash, validators_hash, next_validators_hash,
consensus_hash, app_hash, last_results_hash, evidence_hash, proposer_address,
header_hash
```

**The client will recompute `header_hash`** as the Merkle root over those
fields and compare. That is only possible if the response is complete and the
field order and encoding are pinned. A response missing one field is unusable —
not degraded, unusable.

### 4.2 `ConsensusProofQuery` — the commit for a height

**Request:** partition, height.

**Response:**

```
height, round, chain_id
block_id { hash, parts { total, hash } }
signatures[]:
    block_id_flag           // commit / nil / absent
    validator_address
    timestamp               // per-signature; it is inside the signed bytes
    signature
```

**What the client checks** — and therefore what the response must permit:

1. `block_id.hash` equals the `header_hash` from §4.1.
2. For each precommit, reconstruct the **CanonicalVote** preimage —
   `{type, height, round, block_id, timestamp, chain_id}` — and verify the
   ed25519 signature against that validator's public key.
3. Sum the **voting power** of validators with valid commit signatures; require
   more than 2/3 of total power.

Step 2 is where this succeeds or fails. Each precommit's timestamp is part of
its own signed bytes, so a response that omits per-signature timestamps cannot
be verified at all. Likewise `chain_id` and `round`: they are in the preimage
and not derivable.

**Byte-exactness is the entire contract.** The canonical vote encoding —
length-prefixed protobuf, field order, the `SignedMsgType` value for a precommit
— must be pinned in documentation, not left to be inferred from CometBFT source
by each integrator. If a client's reconstruction differs by one byte, every
proof fails, and the failure is indistinguishable from an attack.

### 4.3 `ValidatorSetQuery` — the set at a height, with proof

A validator set the client fetches is a set an attacker can substitute. It must
be anchored:

```
height, validators[] { address, pubkey, voting_power }, total_voting_power
```

The header's `validators_hash` (§4.1) is the commitment. The client hashes the
returned set and compares against `validators_hash` in a header it has already
attested via §4.2. That closes the loop without any new proof machinery — the
binding already exists in the header and simply needs to be usable.

### 4.4 `ValidatorTransitionQuery` — how the set changes over a range

To trust the set at height N given trust at height M < N, a client needs the
intervening changes, each attested by the set in force at the time:

```
transitions[]: { height, added[], removed[], power_changes[] }
```

Each transition is verifiable by the same means: the header at that height
carries `next_validators_hash`, so a client walking headers forward can confirm
each new set against the previous header's commitment.

This is the induction step that makes L4 possible: trust at a known point,
extended forward one attested step at a time. Without it, every client trusts
whatever set it was handed.

---

## 5. What CERTEN does with it

The proof carried in a CERTEN ValidatorBlock gains one populated field:

```go
type CompleteProof struct {
    // ... existing Merkle receipts ...
    ConsensusProof *ConsensusProof   // DEFINED TODAY, NEVER POPULATED
}

type ConsensusProof struct {          // already exists in healing_proof.go
    BlockHash           []byte
    ValidatorSignatures [][]byte
    SignedPower         int64
    TotalPower          int64
}
```

The type is already there. It needs the header preimage, per-signature
timestamps and the validator set alongside it — but the plumbing exists and the
field is simply never filled, because nothing serves the data.

Verification then runs **inside CERTEN's consensus**, where it must be
deterministic: no network, no clock, pure hashing and signature checks against a
validator set held in committed state. The response shapes above make that
possible; nothing less does.

The chain of reasoning completes as:

```
account state → BPT root → app_hash (header at H+1) → header_hash
              → block_id → precommits → ≥2/3 voting power → validator set
              → attested by an earlier header's next_validators_hash → ... → genesis
```

Every arrow is hashing or signature verification. No step requires trusting a
server.

---

## 6. Why this matters beyond CERTEN

The gap is not CERTEN-specific. Any lite client, bridge or external verifier
wanting to check Accumulate state without running a full node hits the same
wall: receipts prove structure, and nothing available proves the anchor is real.
Every such integration currently ends at "trust an API server" — the property
Accumulate's architecture otherwise exists to remove.

Serving these four endpoints makes Accumulate's consensus independently
checkable by anyone. That is a materially stronger claim than "the API said so",
and it is the claim the whole BPT/anchoring design already earns internally.

---

## 7. Sequencing

1. **Pin the byte-exact preimages first** — canonical vote encoding and header
   hash field order — and publish them as specification rather than as source to
   read. Everything else is mechanical once these are fixed; nothing works if
   they are ambiguous.
2. **`BlockHeaderQuery` + `ConsensusProofQuery` together.** Neither is useful
   alone: the header without the commit is unattested, the commit without the
   header has nothing to check `block_id` against. This pair alone unlocks L3.
3. **`ValidatorSetQuery`.** Small, and it closes §4.2 step 3 against a set the
   client can verify rather than one it is handed.
4. **`ValidatorTransitionQuery`.** Completes L4. Genuinely optional for a client
   willing to pin a recent validator set out of band, which is a reasonable
   interim posture.

Steps 1–2 are the whole ask if effort is constrained. They convert CERTEN's
anchor check from "internally consistent" to "attested by ≥2/3 of Accumulate's
validators", which is the entire point.

---

## 8. What CERTEN does while waiting

Nothing here blocks us. `accumulate-anchor-checkpoints.md` describes a design
that reaches most of the same guarantee with **no API changes at all** — the
fleet agrees a known-good Accumulate root, and proofs must chain to it by pure
hashing.

The two are complementary rather than alternatives: when these endpoints ship,
the checkpoint's seed root stops being operator-attested and becomes *proven*,
and the rest of that design is unchanged.
