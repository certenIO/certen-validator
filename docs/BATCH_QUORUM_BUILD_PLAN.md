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

### DONE — commit `5c3fd49` (step 3)
Peer HTTP wiring, both sides.

- `pkg/execution/batch_attestation_client.go`: `CollectBatchAttestations` fans out concurrently
  to `ATTESTATION_PEERS`, discards refusals/timeouts/mismatched bundleIds, returns only usable
  partials. `NewBatchAttestationRequest(tree, cutoff, proposerID)` takes the TREE so the
  bundleId can never drift from the root it belongs to.
- `main.go`: serves `execution.BatchAttestationEndpoint` (`/api/batch/attestation/request`) via
  `batchStackForAttestation` / `batchAttesterIdentity` atomic holders (same pattern as the
  existing unified endpoint, which is registered before the stack exists). A refusal returns
  200 with `Error` set — it is a normal outcome, not an HTTP failure.
- `TestWireFormat_CarriesNoMemberData` is the tripwire for regression #1 below.

**NEW ENV REQUIRED — `VALIDATOR_EVM_ADDRESS`.** Each validator must know the EVM address it
signs as, and it MUST match its registry entry on the anchor (the aggregator resolves voting
power by address; a wrong one contributes nothing). Unset ⇒ that validator can propose but
cannot co-sign, and the quorum runs one signer short. main.go warns loudly on startup.
Values are the seven `SEPOLIA_V6_VALIDATOR_*` addresses already registered on V8_1.

**IDENTITY GAP — VERIFIED ON THE LIVE SERVER 2026-08-01.** The containers have ONLY
`VALIDATOR_ID=validator-N`. `SEPOLIA_V6_VALIDATOR_*` is NOT present in `.env.shared` (checked
directly; those addresses live in `certen-contracts/evm/.env`, a different repo). So today no
validator can determine its own EVM address, and `batchAttesterIdentity` would never be set —
every peer would answer 503 and quorum could never form.

Two ways to close it, in order of preference:

1. **Self-configure from the registry (recommended, no new config).** The validator already
   holds its BLS private key. The anchor's registry maps EVM address → BLS pubkey. At startup,
   read the registered validator set and find the entry whose pubkey equals
   `bls.GetValidatorBLSKey().PrivateKey().PublicKey().Hex()`; that IS this validator's address.
   Impossible to misconfigure, and it fails loudly if the node's key is not registered — which
   is exactly when it should refuse to attest. Costs one chain read at startup.
2. **Explicit env.** Add `VALIDATOR_EVM_ADDRESS` per service in `docker-compose.yml` (7 edits)
   from the seven addresses registered on V8_1. `main.go` already reads this. Simpler, but
   silently wrong if an address is pasted into the wrong service — and a wrong address
   contributes no voting power, so the quorum just mysteriously runs short.

`main.go` currently implements (2) and warns when unset. Prefer adding (1) with (2) as override.

**ALSO NOTED:** `RunFlushLoop` is currently passed `func() uint64 { return 0 }` as its height
source (main.go, batching block). Step 4 must replace this with the real consensus height, or
`BatchPeriodCutoff` always yields 0 and no period ever selects members.

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

### DONE — steps 4, 5, 6 and the identity gap

**Validated first: the ADI URL vs org identity question.** Re-checked independently, and the
`51fc054` fix is right for a reason stronger than the keccak match alone:

- `CertenAccountV7` has exactly ONE adiURL consumer — its own immutable `adiURL` via
  `adiURLHash()` (`:252`, `:269`). `proof.adiURL` is explicitly *"advisory / event label only —
  NOT used for the leaf"* (`:110`). There is no competing anchor-side ADI-membership check in
  the V7 batch path, so the bare org ADI is the ONLY string that has to match.
- The data-account form is not wrong everywhere — `v6_1_signing.go` builds `"%s/data"` at seven
  sites for the per-intent pre-exec bundle binding, and that is correct there: it binds the
  Accumulate tx principal, which genuinely is the data account. The two fields are not
  interchangeable and both are now used correctly.
- It is already enforced against deployed bytecode: `verifyLeavesAgainstAccounts`
  (`batch_orchestrator.go:223-232`) reads each account's on-chain `adiURLHash()` and refuses the
  batch BEFORE `createBatchAnchor` if it disagrees. So a regression here costs a refused flush,
  not an unspendable paid-for anchor.

**Step 4 — aggregation and submit.** `pkg/execution/batch_quorum_attestor.go`. The leader signs
its own partial, fans out to `ATTESTATION_PEERS`, folds via `AggregateBatchAttestations` against
the registry, and submits. `consensus.signBatchPreExecBLS` / `BatchQuorumProver` /
`BatchProofSubmitter` are DELETED — the solo-signing shape is gone, not merely bypassed. It had
to move to `pkg/execution` because `pkg/consensus` cannot import it (the dependency runs the
other way, via `executor.go:24`).

`SubmitBatchComprehensiveProof` → `SubmitBatchQuorumProof`, taking a `*QuorumAggregate`:
- `AggregateSignature` is now the Groth16 blob from `generateBLSZKProof`, not the raw signature.
- `SignedVotingPower` is `agg.SignedVotingPower`. `buildValidatorSetForBatch` no longer returns
  a signed power **at all** — the four-value signature makes reintroducing `signed = total` a
  compile error rather than a silent forgery.
- `ThresholdMet` is computed from the two, never asserted.
- Guards refuse a nil aggregate, zero signed power, and any aggregate with fewer than 2 signers
  (the authorized commitments cover subsets of 5, 6 and 7 only) — all before any gas is spent.

**Identity gap — closed by self-configuration (option 1).**
`ReadValidatorRegistry` reads `validators(address)` off the anchor for pubkey + power;
`ResolveOwnEVMAddress` matches this node's own BLS pubkey against it. No new env. It fails
loudly when the key is not registered — exactly when the node should refuse to attest.
`VALIDATOR_EVM_ADDRESS` survives as a bring-up override only. Resolution runs in a background
goroutine with retries so a slow RPC at startup does not cost the process its ability to attest.

The registry read also refuses a config power that disagrees with the chain: that means the
local `currentValidatorSetRoot` is stale and every signature would be rejected, so it is better
to fail with the cause named.

**Real height source.** `func() uint64 { return 0 }` is gone. `BFTValidator.observedHeight` is
a monotonic atomic recording each round's `bftRes.Height`, exposed as
`ObservedConsensusHeight()`. That is the exact value stamped onto members by `EnqueueForBatch`,
so a cutoff derived from it can never be ahead of every member.

**Deterministic membership.** `FlushChain` takes `cutoffHeight` and uses `TakeForPeriod`, not
`Take`. `BuildBatchTree` gets the cutoff as its height, so `accumulateBlockHeight` — and
therefore the bundleId — agrees across validators. Height 0 is refused outright.

**Step 5 — leader election.** `IsBatchPeriodLeader(chainID, cutoffHeight)`: a pure function of
`sha256("certen:batchperiod:v1|chain|cutoff")` over a sorted roster (`BATCH_LEADER_VALIDATORS`,
defaulting to the seven production IDs). Four bytes are folded, not one — one byte mod 7 is
measurably biased (256 = 7·36 + 4). Non-leaders never form a batch; they only answer
attestation requests. Tested for exactly-one-leader across 600 (chain, period) pairs, roster
order independence, rotation across all seven, and chain sensitivity.

**Step 6 — fallback.** `BatchFlushResult.Dropped` + `BatchFallbackFn`. Quorum failure or an
unusable anchor DROPS members (never requeues) and routes each to
`BFTValidator.RunBatchMemberFallback`, which re-runs `SubmitAnchorFromValidatorBlock` on the
per-intent path. That needed `PendingAttestation.SubmitVB` / `SubmitBFT`, captured on the batch
path where `vbMeta`/`bftMeta` are in scope. A member that somehow arrives without them still
attests the FAILURE rather than sitting pending silently.

Build, vet and the full test suite pass. 13 new tests.

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
3. ~~**Leader aggregation + submit.**~~ DONE — `pkg/execution/batch_quorum_attestor.go`.
4. ~~**Leader election.**~~ DONE — `IsBatchPeriodLeader`. (`selectExecutorForRound` was NOT
   reused: it keys on a roundID string, and a batch period has no round. It also folds a single
   hash byte modulo 7, which is biased.)
5. ~~**Fallback.**~~ DONE — `Dropped` + `RunBatchMemberFallback`.
6. **Deploy + live e2e**, per the verification checklist below. ← THE ONLY REMAINING STEP.

   Before deploying, set on every validator service (they must be IDENTICAL across all seven,
   because both feed the bundleId):
   - `BATCH_PERIOD_BLOCKS` (default 10 if unset)
   - `BATCH_LEADER_VALIDATORS` (defaults to validator-1..7)

   `ATTESTATION_PEERS` is already populated. `VALIDATOR_EVM_ADDRESS` is NOT needed — identity
   self-configures from the anchor registry. Watch for `🔏 [BATCH] Attesting as … (matched
   on-chain BLS registry)` on each node at startup; a node logging the ❌ line instead has a
   BLS key that is not registered and will refuse every attestation request.

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

---

## DEPLOY-TIME FINDINGS (2026-08-02)

Found by `cmd/batchpreflight` and by auditing the runtime path before pushing. Three were
blocking; all three are fixed (`bab6989`, `87ad2c7`). The fourth is a characterised limitation,
NOT fixed, and is described honestly below.

### 1. Only the elected executor enqueued — BLOCKING, fixed

Non-executors return from `executeCanonicalBFTWorkflow` before the batch enqueue, so six of
seven mempools were empty for every intent. An attester rebuilds the batch from its OWN mempool
— that reconstruction IS the security boundary — so it could never rebuild anything. Every peer
would have refused, every batch would have fallen back, and it would have looked exactly like
ordinary peer disagreement.

### 2. Selection was open-ended — BLOCKING, fixed

`CommitHeight <= cutoff` is correct only while every validator removes taken members in
lockstep, and attesters deliberately do NOT remove. The leader took period P, the attester kept
it, and at P+1 the leader derived a tree over P+1 while the attester derived one over P and P+1.
The FIRST batch would have worked and every later one failed, permanently.

Selection is now the half-open window `[periodStart, periodStart+periodBlocks)`. Consequences,
all handled: the flush loop iterates every closed period (`PendingPeriods`) so a straggler whose
leader was down is picked up later; `FlushChain` short-circuits when the bundleId already exists
AND is attested, because otherwise a second leader reaching the same period would re-submit,
hit replay protection, report quorum failure and route already-settled members to the
per-intent fallback — re-executing intents that had already moved funds; and `PruneOlderThan` is
a memory backstop that deliberately does not fall back, because on a non-leader those members
were settled by whoever led their period.

### 3. The cutoff advanced only on local activity — BLOCKING, fixed

`ObservedConsensusHeight` moved only when this node processed an intent, so a lone queued intent
could never close its own period. The cutoff now comes from `ValidatorApp.LatestHeight`.

### 4. `CreateEmptyBlocks = false` — NOT fixed, characterised

`bft_integration.go:2429` disables empty blocks, so the CometBFT height advances ONLY when a
transaction commits. Measured live 2026-08-02: height 195, unchanged over 40s of sampling.

A period closes when the chain passes its upper bound. On a busy chain that is immediate and the
design is sound — and a busy chain is exactly the regime where batching pays. On an IDLE chain a
queued intent waits for the next committed transaction to push the height past its period
boundary. It is never lost and never unsafe; it is late.

The wall-clock alternative was rejected as unsound: while the height sits inside period P, a
later intent can still commit INTO P, so a timer-based close lets one node form P while another
still has a member to add. That is the divergence class this whole design exists to remove.

**The correct fix is a consensus heartbeat**: when the flush loop sees members waiting in an
unclosed period and the height is static, broadcast a no-op tx via `BroadcastAppTxSync` to push
the height past the boundary. Closure then stays purely height-based and every node observes the
same advance. This needs a new accepted tx type — `ValidatorApp.CheckTx` currently admits only
policy updates and ValidatorBlocks — and touching the ABCI accept path deserves its own change
with its own tests, not a tail-end edit during a deploy.

Until then, set `BATCH_PERIOD_BLOCKS` to match real traffic: small periods close sooner but
batch fewer members. Deployed at 5.

---

## LIVE VERIFICATION (2026-08-02, Sepolia)

Deployed via `deploy/deploy-validators.sh`: seven images built capped (peak load 11, versus
5825 for the earlier uncapped build), rolling restart in groups of two, quorum never broken.

### Identity self-configuration — CONFIRMED

All seven resolved their attesting address from the anchor's BLS registry with NO
`VALIDATOR_EVM_ADDRESS` anywhere:

```
validator-1 → 0xd4a3dbba…   validator-5 → 0xf150ff92…
validator-2 → 0x5555afa8…   validator-6 → 0x70a6a81b…
validator-3 → 0x6acaa684…   validator-7 → 0xee2efa29…
```

Each matches what `cmd/batchpreflight` predicted offline. This closes the identity gap that
would otherwise have left every peer answering 503.

### Every validator enqueues — CONFIRMED, and this was the blocking defect

Intent `d81aecef-922b-4ce4-8d40-4b9b63ffbe74`, one leg, 1 wei on Sepolia:

```
v1 📦 BATCH-QUEUE queued  +  NOT elected executor
v2 📦 BATCH-QUEUE queued  +  NOT elected executor
v3 📦 BATCH-QUEUE queued  +  NOT elected executor
v4 📦 BATCH-QUEUE queued  +  NOT elected executor
v5 📦 BATCH-QUEUE queued  +  NOT elected executor
v6 📦 BATCH-QUEUE queued  +  ⚡ ELECTED EXECUTOR
v7 📦 BATCH-QUEUE queued  +  NOT elected executor
```

All seven hold the member while only ONE is the round's elected executor. Before the fix the
six non-executors returned before the enqueue, so their mempools were empty, `PeekForPeriod`
returned nothing, and every attestation request was refused — quorum could never have formed
and it would have read as ordinary peer disagreement.

### Pipeline timing, measured

Discovery → L1-L3 chained proof → G0/G1/G2 → ValidatorBlock → BFT commit took roughly three
minutes end to end, dominated by the three governance proofs at ~30s each. Chain height moved
195 → 200 on the committed round, which is also what closes the intent's period.

## Corrections to earlier entries in this document

Two root-cause claims made during the 2026-08-02 outage were WRONG and are corrected here so
the record is not misleading:

1. **The ZK keys were never missing.** `proving_key.bin` is present on the host and its digest
   matches `deploy/bls_zk_keys.SHA256SUMS` exactly. The trusted setup never ran. The Dockerfile
   hardening and `cmd/vkcheck` remain correct and worth having, but they address a LATENT
   hazard — they did not fix this outage.
2. **The build was not the primary cause.** A co-tenant container (`tidemark-prod-frontend`,
   unrelated to Certen) was spawning hundreds of `npm install` processes; at peak, 916 zombies
   under one `npm start`, load 7169. It recurred after a clean reboot with nothing of ours
   running.

What WAS ours: `kernel.pid_max` was 32768 against a ~19,000-thread idle baseline, so an
unbounded build consumed thin headroom and helped tip a host that was already degrading. The
prior boot shows `fork: EAGAIN` across sshd, dockerd and udevd with ZERO OOM kills — PID
exhaustion, not memory, on a box with 62GB RAM. Raised to 4194304 in
`/etc/sysctl.d/99-certen-pids.conf`, and every build is now capped by the deploy script.

---

## DURABILITY GAP — queued batch members do not survive a validator restart

Found 2026-08-02 on the migrated Kermit chain. All seven validators were recreated at the same
instant (identical container Created timestamps, exit=0, RestartCount=0 — a `docker compose up
-d`, not a crash and not the rolling deploy script, whose own restarts are staggered by
minutes). Two intents that had been accepted for batching were lost.

The mechanism, and why it strands rather than merely delays:

- `BatchMempool` is in-memory only. A restart empties it.
- `executeCanonicalBFTWorkflow` returns `batch_queued_...` once `enqueueForBatch` succeeds, so
  the intent does NOT take the per-intent on_demand path.
- The member's proof-cycle snapshot lives on the same in-memory object, so nothing survives to
  attest a failure either.

The intent is therefore neither settled nor failed nor retried: it is simply gone, with the
round having reported success. That is the one outcome the fallback policy exists to prevent,
and the fallback cannot fire because the process that would have fired it no longer holds the
member.

This is INDEPENDENT of the quorum work — it predates it — but the quorum work makes it matter
much more, because members now wait a settle grace plus a period boundary before flushing, so
the window in which a restart can eat them is minutes rather than seconds.

Options, in preference order:

1. **Persist the mempool.** The ledger store is already wired into the validator
   (`GetLedgerStoreProvider`), and `PendingBatchIntent` is serialisable apart from the opaque
   attestation snapshot, which would need an explicit encoding. Restart then resumes the period
   exactly where it left off, and determinism is unaffected because membership is still keyed
   on committed height.
2. **Re-derive on startup** from the intents' own Accumulate state rather than storing them.
   More faithful to "membership is a function of committed state", but needs a way to enumerate
   intents committed in recent periods.
3. **Refuse to report batch_queued until the member is durable** — the intent then takes the
   per-intent path on restart. Cheapest, and strictly better than losing it, but it gives up
   the amortisation for every intent in flight at restart time.

NOT fixed in this session. It needs its own change with its own tests, and it touches the point
where an intent's fate is decided.

---

## CROSS-ADI BATCH: FORMED AND ATTESTED 7-of-7 (2026-08-02) — one gate left

The determinism fix works. Two intents from two distinct ADIs, submitted five seconds apart:

```
344c5cf0  acc://certen-kermit-12.acme          Accumulate height 6259279
13b71159  acc://certen-kermit-12.acme/batchb   Accumulate height 6259282
```

Both heights were IDENTICAL on all seven validators (previously one intent got seven different
CometBFT heights), both fell in period [6259200, 6259300), and the elected leader formed:

```
forming tree: 2 members, root=0xf90f3918…, bundleId=0x9aa538ca…
anchor created tx=0x4aae3d30… gas=278069
quorum formed: 700 of 700 voting power from 7 signer(s)
zk proof 576 bytes, pubkeyCommitment=0x00790bb79d07a0eb, signed=700/700 over 7 signers
```

7-of-7 — every peer independently rebuilt the batch and derived the same bundleId. The
signer-set fix also worked: gas on executeComprehensiveProof went 128,219 -> 504,919, i.e. it
cleared every CRYPTO-007 check and the six-field message-hash comparison and reached the
Groth16 pairing. It then returned false.

### The remaining failure, stated precisely

The proof is VALID locally:

```
[BLS-ZK-DIAG] gnark local verify: result=true err=<nil>
[BLS-ZK] Generated valid ZK proof: 576 bytes, pubkeyCommitment: 0x00790bb79d07a0eb
```

and its pubkey commitment is one of the 29 the anchor authorizes (cmd/subsetaudit: 29
authorized, 0 unauthorized; 0x00790bb7… is the 7-of-7 value the plan already recorded).

The anchor's verifier is 0x8D15f88c84009D99350F40E9361aF69bAa7D2Baf, vkInitialized=true,
blsZKVerificationEnabled=true, pubkeyBindingEnforced=true, governanceVerifier=0 and
minimumGovernanceLevel=1 — so the governance and commitment gates are not the cause, and
cmd/anchorstate confirms merkleVerified would pass (bundleId re-derives from stored state).

The diagnostic that matters:

```
[BLS-ZK-DIAG] VK CommitmentKeys=1 PublicAndCommitmentCommitted=1 IC=6
[BLS-ZK-DIAG] Manual 4-pairing check: result=false err=expected 5 IC points, got 6
```

The circuit uses a gnark COMMITMENT. That changes the verification equation: it needs a fifth
pairing and the commitment folded into the public inputs. cmd/vkcheck confirmed the local VK
matches BLSZKVerifierV2Generated.sol on all 26 elements including all six IC points, so the key
is right — the question is whether the DEPLOYED verifier at 0x8D15f88c implements the
commitment form, and whether the public inputs it reconstructs from the blob match the ones the
prover committed to.

NOT resolved. The next step is to compare the deployed verifier's bytecode/behaviour against
BLSZKVerifierV2Generated.sol directly — vkcheck compares against the FILE, which proves nothing
about what is deployed at that address.

### Also observed

The per-intent on_demand fallback is ALSO failing right now, with constraint #774716
unsatisfied — the same constraint this document already attributes to proving against a pubkey
that did not sign. It uses the block signer's key from the ValidatorBlock. That is a
pre-existing defect on the fallback path, independent of the batch work, and it means dropped
members currently have nowhere to go.
