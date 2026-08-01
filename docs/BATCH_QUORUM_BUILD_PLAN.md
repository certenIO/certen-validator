# Cross-ADI Batch Quorum — Build Plan

Status: IN PROGRESS (started 2026-08-01)
Decision owner: Jason. Approach and fallback policy approved.

---

## The defect being fixed

The cross-ADI batch path forms its Merkle tree on a **local 1-minute timer per validator**
(`BatchStack.RunFlushLoop`), entirely outside consensus. Two consequences, both observed live
on Sepolia 2026-08-01:

1. **Divergent trees.** validator-2 flushed bundleId `0xe4c950df…` while validator-3 flushed
   `0x5e71d83a…` in the same window. Nothing makes validators agree on batch membership.
2. **No quorum.** `signBatchPreExecBLS` (`pkg/consensus/batch_quorum_prover.go:88-100`) signs
   with `km.PrivateKey()` — *this validator alone* — while `buildValidatorSetForBatch` declares
   all 7 validators, `TotalVotingPower: 700`, `SignedVotingPower: 700`.

It also submits the raw 48-byte BLS signature where the contract requires an abi-encoded
Groth16 blob (the on_demand path calls `ecm.generateBLSZKProof`).

**The chain rejects this, so it fails SAFE.** Live evidence, anchor `0x5e71d83a…`:

```
ProofVerificationFailed(merkleVerified: true, commitmentVerified: true,
                        blsVerified: false, reason: "BLS signature verification failed")
```

`merkleVerified: true` proves the leaf/root/ADI-binding math is already correct on chain.

### DO NOT "fix" this by wrapping the single signature in generateBLSZKProof

That is the obvious-looking one-liner and it is a **quorum forgery**: it would mint a valid ZK
proof asserting 700/700 signed voting power from one key — precisely the CRYPTO-007 class of
attack the authorized-subset commitments exist to prevent. The 29 registered commitments are
subsets of size 5, 6, and 7 only; a single-signer aggregate is not among them, which is why
the chain refuses it.

---

## Why bundleId needs no reservation

`CertenAnchorV8_1.sol:776-784` **re-derives** the bundleId and rejects any mismatch:

```solidity
bytes32 derivedBundleId = keccak256(abi.encodePacked(
    "certen:batchbundle:v1", DEPLOYMENT_CHAIN_ID, batchRoot,
    leafCount, batchOperationID, accumulateBlockHeight));
if (!(bundleId == derivedBundleId)) revert BundleIdMustDeriveFromBatchRootCount();
```

It is a pure function of batch content — not chain-assigned, nothing to reserve. Fix membership
and the bundleId is known before any transaction is sent, so the quorum can sign it in advance.

The contract already anticipates exactly this design (`:772-775`): a rogue validator restating
root or leafCount "produces a different bundleId, which the honest quorum's BLS signature does
not cover."

**Subtle trap:** `accumulateBlockHeight` feeds the derivation. It MUST be agreed in consensus,
not read locally per validator, or identical membership still yields divergent bundleIds.

---

## Why cross-ADI cannot be composed pre-signature

A batch holds dozens of intents from dozens of ADIs, each signing independently on Accumulate at
its own time. No moment exists where they could co-sign a batch. The soundness comes from two
signature layers with different scopes:

| Signature | Scope | Authorizes |
|---|---|---|
| ADI key page (Accumulate) | one intent, one ADI | the operation → becomes the leaf |
| Validator BLS quorum (Phase 3) | one batch, all ADIs | that these leaves are validly in this root |

The quorum never authorizes anyone's funds. `CertenAccountV7._authorizeLeaf` permits a leaf to
be spent only by the account whose **immutable** `adiURL` hashes into it. A malicious quorum
could include a leaf but could not fabricate one for an ADI that never signed.

---

## Approved architecture: reuse Phase 3 + Phase 4

Per `onboarding_v6_1_proof_cycle.html`: Phase 3 has every validator BLS-sign the 6-field pre-exec
binding; Phase 4 runs CometBFT Propose→Prevote→Precommit→Commit where "the aggregate BLS sig from
Phase 3 is locked into the committed block", with deterministic-leader rotation electing the
single submitter. **That is already "one proposer, six attest."**

Rejected alternative: a bespoke proposer→attest gossip protocol. It would have to re-solve
equivocation (proposer sends batch A to three validators, B to four — both could reach 5-of-7),
liveness/view-change, and validator-set-change snapshots. CometBFT solves all three.

### Transport decision: CometBFT txs, NOT the HTTP broadcaster

`pkg/batch/attestation_broadcaster.go` already implements request/collect/aggregate — but:

- it is **dead code** (never constructed in `main.go`; `ConsensusCoordinator` is also unwired), and
- it signs via `SignWithDomain(msgHash, bls.DomainAttestation)` (`:344`), which hashes to a
  different G1 point and **makes the V2 circuit unsatisfiable** — the documented cause of the
  Sepolia test #7 failure. Its aggregate could never verify on chain.

Use CometBFT as the transport instead: totally-ordered, replicated, equivocation-proof, and
already running. `BroadcastTxSync` is available (see `bft_integration.go:2754`).

---

## PROGRESS

### DONE — commit `cad0412`
`pkg/consensus/batch_quorum_aggregate.go` + tests, and `bls.PublicKey.VerifyG1`.

- `AggregateBatchAttestations` verifies each partial against the REGISTRY public key, refuses
  duplicate / unregistered / wrong-message / key-substituted / malformed attestations, sums
  `SignedVotingPower` from actual signers, enforces threshold BY POWER, and self-checks the
  fold before returning.
- `SignBatchAttestation` uses `bls_zkp.SignV6_1PreExec` (NOT `SignWithDomain`).
- `bls.PublicKey.VerifyG1` added — `Verify()` uses RFC-9380 ExpandMsgXmd and CANNOT check a
  `SignG1` signature; it silently returns false. This was a required addition.
- 12 tests pass, including `TestAggregate_SingleSignerIsRefused` (the forgery guard).
- **Proven against the live chain**: with the real `bls_keys_backup_MASTER.json`, aggregates
  fold to `0x0097ffa4…` (5-of-7), `0x003dd096…` (6-of-7), `0x00790bb7…` (7-of-7) — all three
  read back `authorizedPubkeyCommitments == true` on CertenAnchorV8_1. The 7-of-7 value is
  byte-identical to the one `cmd/subsetcommit/main.go` records as the production prover's
  output, which independently confirms the fold.

### DONE — commit `6f72b36`
Deterministic period selection in `pkg/execution/batch_mempool.go`:

- `PendingBatchIntent.CommitHeight` added — the BFT height the intent's round committed at.
- `BatchPeriodCutoff(height, periodBlocks)` buckets heights into periods.
- `PeekForPeriod` (non-destructive, for attesters) / `TakeForPeriod` (destructive, leader only).
- Selection = members with `CommitHeight != 0 && <= cutoff`, ordered by `(CommitHeight, IntentID)`,
  capped AFTER sorting. Zero-height members are SKIPPED, never guessed at.
- `DropMembers` for the approved fallback path (drop, never requeue).
- 7 tests pass, incl. `TestPeekForPeriod_IsIdenticalAcrossValidators`: two pools with the same
  intents in opposite arrival order and unrelated wall-clocks select the identical member list.

### DONE — commits `c6230ed`, `acb5922`

`c6230ed` — commit height threaded end to end. `EnqueueForBatch` takes `commitHeight`,
`bft_integration.go` passes `uint64(bftRes.Height)`, and enqueue REFUSES height 0 (such a
member could never be selected deterministically and would sit in the pool forever).

`acb5922` — `pkg/execution/batch_attestation.go`: the attester, and with it the security
boundary. `HandleBatchAttestationRequest` rebuilds the batch from its OWN mempool via
`PeekForPeriod(chainID, cutoffHeight)` and signs ONLY if its derived bundleId equals the
proposer's. The request carries no member data by design — accepting a member list from the
proposer would defeat the check entirely. 8 tests, including refusal of an injected extra
leaf, a tampered member amount, and a mismatched cutoff height; attesting never consumes the
mempool.

### ⚠ TWO REGRESSIONS THAT FAIL SILENTLY — READ BEFORE TOUCHING STEPS 3 OR 4

**1. Step 3 must not weaken step 2.** `BatchAttestationRequest` deliberately carries NO member
list. If the proposer's fan-out ever starts sending members "so the peer doesn't have to look
them up", the security boundary evaporates and EVERY EXISTING TEST STILL PASSES — because the
attester would then be validating the proposer's own data against itself. The peer must always
rebuild from `PeekForPeriod`. `TestWireFormat_CarriesNoMemberData` guards this.

**2. Step 4's temptation.** Wrapping a SINGLE signature in `generateBLSZKProof` compiles, runs,
and produces a structurally valid proof — asserting 700/700 signed power from one key. That is
the CRYPTO-007 quorum forgery. `signedVotingPower` must come from
`QuorumAggregate.SignedVotingPower` (sum of real signers), never from a constant or the total.
`TestAggregate_SingleSignerIsRefused` makes the regression fail loudly rather than ship.

### REMAINING WORK (in order)

1. ~~**Populate `CommitHeight`.**~~ DONE (`c6230ed`). `EnqueueForBatch` must take the BFT commit height and set it.
   Call site: `pkg/consensus/bft_integration.go:1392` — `bftRes.Height` is in scope there.
   Until this is done `PeekForPeriod` returns nothing (zero heights are skipped), so the batch
   path stays inert — safe, but non-functional.
2. ~~**Batch attestation over the peer endpoint.**~~ Handler DONE (`acb5922`). STILL TO DO: the HTTP wiring — serve it next to `/api/unified/attestation/request` in `main.go`, and add the proposer-side client that fans out to `ATTESTATION_PEERS`. Original note: Add a batch request/response alongside
   `PeerAttestationRequest`. Proposer sends `{chainID, cutoffHeight, bundleId}`. The attester
   MUST recompute its own tree via `PeekForPeriod(chainID, cutoffHeight)` and sign ONLY if its
   derived bundleId equals the proposer's. This check is the security boundary: without it a
   malicious proposer could insert a leaf draining an ADI's account and have the quorum bless
   it. Sign with `consensus.SignBatchAttestation`.
3. **Leader aggregation + submit.** Collect partials, call
   `consensus.AggregateBatchAttestations(atts, registry, msgHash, 2, 3)`, then pass the REAL
   aggregate + `SignedVotingPower` into `ecm.generateBLSZKProof` and submit. Registry (address →
   pubkey, power) must be read from the anchor, not from config.
   Replace `signBatchPreExecBLS`'s solo signing at `batch_quorum_prover.go:88-100`.
   Replace `AggregateSignature: sigBytes` with the ZK blob at `batch_proof_submitter.go:~232`.
4. **Leader election.** Reuse `bv.selectExecutorForRound` (`bft_integration.go:1352`).
   Non-leaders attest only; they must never call `createBatchAnchor`.
5. **Fallback.** On quorum failure: `DropMembers` + route to the per-intent on_demand path.
   Never requeue (re-forming the identical tree reverts `AnchorAlreadyExists` and hides the
   real fault).
6. **Deploy + live e2e**, per the verification checklist below.

### TRANSPORT — decided, verified reachable
Use the EXISTING peer attestation HTTP path, not CometBFT txs and not
`pkg/batch/attestation_broadcaster.go`.

- Endpoint already served: `main.go:374` `/api/unified/attestation/request` →
  `UnifiedOrchestrator.HandlePeerAttestationRequest`.
- Client already implemented: `collectPeerAttestations` (`pkg/execution/unified_orchestrator.go:1421`),
  posts to `%s/api/unified/attestation/request` (`:1502`).
- Peers ARE configured in production: `ATTESTATION_PEERS=http://validator-2:8080,...`.
- Currently idle (0 peer-attestation log lines in 60m) — wired but unexercised.

Rejected: `pkg/batch/attestation_broadcaster.go` is dead code (never constructed in `main.go`;
`ConsensusCoordinator` also unwired) AND signs with `SignWithDomain(bls.DomainAttestation)`
at `:344`, which makes the V2 circuit unsatisfiable. Do not revive it as-is.

### KEY DESIGN REFINEMENT — deterministic composition beats negotiation
Membership does NOT need a new consensus round. Make the batch a deterministic function of
already-committed state, and every validator derives an identical tree, root, and bundleId
with no negotiation:

- period = `commitHeight / periodBlocks`; cutoff = `period * periodBlocks`
- members = pending intents whose BFT round committed at height <= cutoff, sorted
  deterministically (by leaf, ascending)
- `accumulateBlockHeight` = cutoff  ← this is what makes the bundleId agree

`PendingBatchIntent` must therefore carry its commit height. Without a cutoff, validator A may
have processed an intent that B has not yet seen, and the trees diverge — which is exactly what
happened live (v2 `0xe4c950df…` vs v3 `0x5e71d83a…`).

## Build steps

### 1. Batch proposal becomes consensus content
- Flush loop STOPS anchoring directly. It proposes.
- New tx type `BatchProposalTx`: `{chainID, memberLeaves[], leafCount, batchRoot,
  batchOperationID, accumulateBlockHeight, proposerID}`.
- Only the deterministically-elected proposer for the period may propose; others validate.
- ABCI `DeliverTx` records the committed proposal → this IS the agreement on membership
  AND `accumulateBlockHeight`.
- Every validator derives the same bundleId from committed content.

### 2. Phase 3 signing over the derived bundleId
- Each validator computes `ComputeBatchPreExecMessage(chainID, bundleID, batchRoot,
  batchOperationID, setRoot)` and signs with **`bls_zkp.SignV6_1PreExec`** — NOT
  `SignWithDomain`.
- Partial signature broadcast as `BatchAttestationTx` through CometBFT.
- ABCI collects; each is verified against the signer's REGISTERED pubkey before counting.

### 3. Aggregate + submit (elected leader only)
- On ≥ threshold (5-of-7 by power: 500 ≥ 467) the leader aggregates via
  `bls.AggregateSignatures` and aggregates the corresponding pubkeys.
- `signedVotingPower` = sum of the powers of validators that ACTUALLY signed. Never a constant.
- `generateBLSZKProof(aggSig, msgHash, signedPower, totalPower, aggPubHex)` — now legitimate.
- Leader submits `createBatchAnchor` then `executeComprehensiveProof`.
- The resulting pubkey commitment must be one of the 29 authorized subsets.

### 4. Failure policy — APPROVED: fall back, never requeue
- Quorum not reached in the window → members drop to the **per-intent on_demand path**.
- Rationale: requeueing risks a permanently stuck batch; fallback costs more gas but guarantees
  settlement. Matches `EnqueueForBatch` already refusing unconfigured chains rather than
  stranding intents.
- Anchor already mined but attestation failed → do NOT requeue (re-forming the identical tree
  derives the same bundleId and reverts `AnchorAlreadyExists`, hiding the real fault).

---

## Verification required before declaring done

1. Unit: bundleId derivation matches the contract byte-for-byte (live check against deployed).
2. Unit: aggregate of 5, 6, 7 signers → commitment ∈ the 29 authorized set.
3. Unit: `signedVotingPower` reflects actual signers, never a constant.
4. Negative: single-signer aggregate MUST be rejected (guards against reintroducing the forgery).
5. Negative: divergent membership → different bundleId → signature does not cover it.
6. Live e2e on Sepolia: real batch intents through to settlement, `proofExecuted = true`,
   leaf consumed, balance moved.
7. Multi-member: ≥2 intents from ≥2 distinct ADIs in ONE batch — the actual point of the feature.

---

## Known state at plan time (2026-08-01)

- Live anchor: `CertenAnchorV8_1` `0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0`, binding ENFORCED,
  29 commitments authorized, setRoot `0xa85a6911…`, 7 validators @100 power.
- FactoryV9 `0xf96f936fbfc7c02e4e1d1c847b9817e60c4b6f4e` → V8_1.
- Test account `0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B` for `acc://certen-kermit-12.acme`,
  funded, keyless, pinned to V8_1.
- Fixed and shipped earlier today: attestation-runner wiring (`c9a2102`), batch leaf ADI URL
  (`51fc054`), BFT timeout (`2f75213`), govproof CLI timeout (`0bf0eba`), operationID accessor
  (`8b53c1c`).
- Stranded anchors from failed flushes (~550k gas): `0xe4c950df…`, `0x5e71d83a…`.
- `scripts/submit_intent_v8_1_cadence.js` is under a **gitignored** directory — not committed.

## Open item, not blocking

G2 governance proof: only 1 of its 4 sub-checks is real (payload binding recomputes the tx hash).
Effect verification is tautological as invoked (no `--expect-entry` passed, so it compares
computed vs expected — the same comparison payload binding already made); receipt binding and
witness consistency are "we got here" flags. `go_verifier.go:60-71` also has a path where an
unset `goVerifyPath` yields a G2 pass with zero real cryptography. Raised with Jason; awaiting
direction. Does not block batch quorum.
