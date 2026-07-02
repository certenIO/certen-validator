# Certen Proof‑Gated Calls — Security Remediation Runbooks

Status: **DRAFT / not yet implemented.** These runbooks specify the 100%-correct fixes for the
13 bypasses found in the adversarial audit of the proof‑gated contract‑call feature. Implement
in the sequence in §Sequencing. Every fix must be **fail‑closed** (refuse on missing/ambiguous
data) and covered by a unit test **and** an on‑chain negative test before it is considered done.

## Flag policy during remediation
`CERTEN_ALLOW_CONTRACT_CALLS` stays **ON** on the devnet fleet — we are pre‑real‑users and need
the live pipeline available to test each fix. **Hard gate before real users:** all 13 findings
below closed, each with a passing negative test, and the feature re‑audited. Do NOT onboard real
users while any CRIT/HIGH here is open.

## Threat model (what "water‑tight" must defend)
The executor is **BFT‑elected and may be malicious** (running modified validator code). The BLS
quorum + the on‑chain contract are the trust anchors that must independently constrain it.
Therefore: (a) no single actor (executor) may be the sole enforcer of any part of the invariant;
(b) the on‑chain contract must reject an execution that doesn't match the signed commitment; and
(c) every verification must fail closed.

## Guiding invariant (must hold after remediation)
An external‑chain action is attested/written‑back as **successful** only if — the M‑of‑N
Accumulate authorization proved → the EXACT committed call `(chainId, target, value, calldata)`
executed (bound by `executionCommitment`, enforced BOTH in the validator AND on‑chain) →
`status==1` → finalized → receipt inclusion independently re‑verified vs the header roots →
(for calls) the committed event(s)/state proven in the inclusion‑proven result → the result
**independently re‑verified by ≥2/3 of the quorum** (not just the executor). Any gap ⇒ no
attestation ⇒ no write‑back.

## Repos touched
- `independant_validator` (Go) — most fixes.
- `certen-contracts` (Solidity, **redeploy required**) — RB‑2 on‑chain backstop.
- `api-bridge` (TS producer) — minor: stop decoupling top‑level `to`/`amountWei` from
  `executionPayload.target/value` for contract calls (supports validator fix #3).

## Anchor note
Line numbers below are from the audit + spot‑verification and may drift; **re‑confirm each anchor
before editing** (the surrounding code quoted in each runbook is the source of truth).

---

# WORKSTREAM 1 — Validator single choke point (findings #3, #4, #5, #9)

All contract‑call execution funnels through `extractAllLegsFromIntent`
(`pkg/execution/bft_target_chain_integration.go`). Today that function decouples the executed
params from the commitment, skips the commitment on empty/misclassified legs, and the gate arms
off an opt‑in flag. Fix the choke point so a leg that carries calldata CANNOT execute unless the
exact committed `(target,value,calldata)` is bound and verified.

## RB‑SEC‑3 (CRIT) — Bind executed target/value to the commitment (not top‑level `leg.To`/`AmountWei`)
**Root cause:** the leg is executed with `Target = parseChainAddress(leg.To)` and
`Value = leg.AmountWei` (top‑level fields, ~`:1005‑1020`, appended ~`:1110‑1119`), but the
CRITICAL‑003 recompute validates `executionPayload.Target/Value` (~`:1084‑1093`). For a
`contractCall` the producer legitimately sets `to != executionPayload.target`, so the two diverge
and the committed value never constrains what executes. `keccak256(legData)` is also never checked
against `executionPayload.dataHash`.

**Fix (fail‑closed):** for any leg with non‑empty calldata, derive the executed `Target`, `Value`,
and `Data` **from `executionPayload`**, and verify all three bind to the commitment:
1. `legTarget := common.HexToAddress(ep.Target)`, `legValue := parse(ep.Value)`, `legData := decode(ep.CallData)`.
2. Require `keccak256(legData) == common.HexToHash(ep.DataHash)` — else reject (tamper).
3. `computeExecutionCommitment(ep.ChainID, legTarget, legValue, legData) == HexToHash(ep.ExecutionCommitment)` — else reject.
4. Append `LegExecution{Target: legTarget, Value: legValue, Data: legData, ...}` (NOT `leg.To`/`leg.AmountWei`).
   For native/ERC‑20 legs (empty calldata) keep today's behavior (target=to, value=amountWei) —
   or, cleaner, always execute from `executionPayload` when present (producer already sets it for
   native too, target=recipient/token, value=amount).
**Producer support (api-bridge/CertenIntentService.ts):** for `contractCall` legs, ensure the leg's
top‑level `to` is not used for execution — validator will ignore it, but set `to == executionPayload.target`
to avoid confusion; keep native/ERC‑20 top‑level fields consistent with `executionPayload`.

**Tests:** unit — a leg whose `executionPayload.target` ≠ `leg.To` executes the `executionPayload.target`
and REJECTS if commitment/dataHash mismatch; extend `execution_calldata_rb1_test.go`. On‑chain
negative — craft an intent with committed calldata but a different top‑level `to`; confirm the
executor uses the committed target (or rejects), never `leg.To`.

## RB‑SEC‑4 (CRIT) — Reject empty `executionCommitment` on a calldata leg (no skip‑then‑execute)
**Root cause:** the CRITICAL‑003 block is guarded by `... && ep.ExecutionCommitment != ""`
(~`:1083`/`:1143`); `legData` is decoded and the leg executed regardless, so an empty commitment
skips verification but still runs attacker calldata.
**Fix (fail‑closed):** if a leg has non‑empty calldata (`len(legData) > 0`) then
`ep != nil && ep.ExecutionCommitment != "" && ep.DataHash != ""` MUST hold — else **reject the
intent** (`return nil`). Never execute calldata whose commitment is absent. Fold this into the
RB‑SEC‑3 verification block so calldata‑bearing legs have a single mandatory path.
**Tests:** unit — calldata + empty `executionCommitment` ⇒ `extractAllLegsFromIntent` returns nil.
On‑chain negative — submit such an intent; confirm no execution (`seen==false`) + a rejection log.

## RB‑SEC‑5 (CRIT) — Consistent chain classification (non‑EVM name can't route to the EVM executor)
**Root cause:** the commitment‑skip decision uses **name prefix** (`isCardanoLeg :=
HasPrefix(chain,"cardano")`, ~`:1066`/`:1126`), but routing uses `getNonEVMChainName(chainID,name)`
(~`:1288‑1332`) which has **no cardano case** and returns "" (EVM); `groupLegsByChain` keys by
`chainId` only (~`:1272`); the top‑level `switch targetChain` matches exact strings (~`:376/389`).
So `chain:"cardano-x" + chainId:11155111` skips the EVM commitment check yet executes on EVM.
**Fix (fail‑closed):** derive ONE canonical `platform` for a leg from a single function and use it
for BOTH the skip decision AND routing. Require consistency: if the leg routes to the EVM executor
(chainId is an EVM chainId / `getNonEVMChainName` == "") then the EVM CRITICAL‑003 check MUST run —
the non‑EVM skips may ONLY apply when the leg is actually routed to that non‑EVM executor. Concretely:
compute `platform := classifyLeg(chainID, chain)`; the isNear/isCardano/... skips become
`platform == PlatformNEAR` etc.; and `classifyLeg` must agree with `groupLegsByChain`/routing.
Add an assertion: an EVM‑routed leg with a non‑EVM `chain` string ⇒ reject (ambiguous).
**Tests:** unit — `chain:"cardano-x", chainId:11155111` ⇒ EVM classification ⇒ commitment enforced
(or rejected as ambiguous), never skipped. On‑chain negative — submit it; confirm rejection.

## RB‑SEC‑9 (HIGH) — Contract‑call detection from calldata, not an opt‑in flag
**Root cause:** the event gate arms only when `IsContractCall`/`ComprehensiveData["isContractCall"]`
(`external_chain_result.go` `isContractCallExpected` ~`:703`) or `CommitmentData["rbContractCall"]`
(`unified_orchestrator.go` ~`:635`) is set. The `VerifyAgainstResult` path's flag is never set in
prod; multi‑leg no‑match returns nil (`:653‑662`).
**Fix (fail‑closed):** treat a leg as a contract call **iff its committed calldata is non‑empty**
(the ground truth), derived from the user‑signed `executionPayload.callData` — not a separate
boolean an actor can omit. In the gate: if any leg on this chain group has non‑empty calldata and
no applicable descriptor matched, **refuse** (don't `return nil`). In `VerifyAgainstResult`: derive
"is call" from the presence of committed calldata/events, and require the event gate whenever calldata
is non‑empty. Remove reliance on `isContractCall` booleans as the arming signal (keep them only as
redundant hints).
**Tests:** unit — a commitment with non‑empty calldata but `IsContractCall=false` STILL triggers the
event gate; multi‑leg no‑match ⇒ refuse, not pass.

---

# WORKSTREAM 2 — Quorum independence (finding #1)

## RB‑SEC‑1 (CRIT) — Peers independently verify the committed effect before signing
**Root cause:** `HandlePeerAttestationRequest` (`pkg/execution/unified_orchestrator.go` ~`:1332`)
signs after only: structural checks, freshness, and `chainStrategy.ObserveTransaction` →
`IsFinalized && Status==1 && obs.ResultHash == msg.ResultHash`. It never runs RB‑2/RB‑4/RB‑5. The
committed events/state are not in `PeerAttestationRequest`/`AttestationMessage`
(`pkg/attestation/strategy/interface.go:65`), and `ResultHash` (evm_observer ~`:468‑482`) binds
header roots + status but NOT event membership or slot values. So the quorum trusts the executor.

**Fix (fail‑closed, trustless):** a peer must re‑derive the committed effect from the **user‑signed
intent it independently holds** (never from the executor's request) and run the same gate:
1. The peer resolves the intent by `msg.IntentID` / `msg.BundleID` from a trusted local source:
   its own intent‑discovery/consensus store, or by fetching the signed `crossChainData` from
   Accumulate (the peer already has Accumulate access). Add an intent lookup usable from the peer
   handler (by IntentID→crossChainData). If the peer cannot obtain the signed intent, it **refuses**
   to attest (fail closed) — it must not fall back to trusting the request.
2. From that signed intent, extract the contract‑call leg(s) for `msg.TargetChain` (same parser as
   the trigger in `bft_integration.go`), yielding `expectedEvents`/`expectedState`/committed
   `target,value,callData`.
3. Run `observer.VerifyExecutedCall(ctx, msg.AnchorTxHash, events, state)` (RB‑2 inclusion + RB‑4
   events + RB‑5 state) AND verify the executed tx's committed `(target,value,calldata)` matches the
   commitment (RB‑SEC‑3 logic). Only sign if all pass.
4. For native/value legs (no calldata) keep the existing finality+ResultHash check.
**Design notes:** do NOT add the committed events to the request as the source of truth (a malicious
executor would weaken them). They may be included as a hint, but the peer MUST cross‑check against
the signed intent. Consider also binding the committed‑effect digest into `ResultHash` (defense in
depth) so `ResultHash` equality itself implies the effect — but the authoritative fix is peer‑side
re‑derivation + verification.
**Tests:** unit — a peer request for a contract‑call bundle whose committed event is absent on‑chain
⇒ peer refuses. Multi‑validator live — a modified executor that skips its own gate cannot reach
threshold because honest peers refuse (see Global Acceptance).

### CONCRETE DESIGN (verified plumbing — 2026‑07‑02)
Trust anchor a peer independently has: **Accumulate itself** (the signed intent) + `msg.IntentID`
(a user can't forge a signed intent bearing another user's `intent_id`). Sound flow:
1. Extend `AccumulateQueryClient` (`unified_orchestrator.go:119`) with
   `GetIntentBlobs(ctx, txHash, accountURL) ([][]byte, error)` — implement on `LiteClientAdapter`
   (`pkg/accumulate/liteclient_adapter.go`, mirror `GetTransactionGovernanceData`: query
   `scope=acc://<txHash>@<accountURL>`, navigate `transaction.body.entry.data` (doubleHash blob
   array — see `:405`), hex‑decode → `[[intentData],[crossChainData],[governanceData],[replayData]]`).
   Update any test mocks of the interface.
2. Add `AccumulateTxHash` + `AccumulateAccountURL` to `AttestationMessage`
   (`pkg/attestation/strategy/interface.go`) as fetch **hints** (they need NOT be in `Hash()`; the
   binding is via `intent_id`, below). Populate them in `executePhase8` from `cycle.Request`.
3. In `HandlePeerAttestationRequest` (`unified_orchestrator.go:1332`), after the existing
   finality/status/ResultHash checks: fetch blobs via `GetIntentBlobs(msg.AccumulateTxHash,
   msg.AccumulateAccountURL)`. **Bind:** parse `intentData` and require its `intent_id ==
   msg.IntentID` — else refuse (executor pointed at the wrong/forged intent). Parse
   `crossChainData` for the contract‑call leg(s) on `msg.TargetChain` (calldata‑derived; a peer
   determines "is a call" from the FETCHED signed data, never from the request). If any such leg
   exists, run `observer.VerifyExecutedCall(msg.AnchorTxHash, events, state)` + the RB‑SEC‑3
   commitment binding; sign only if all pass. If fetch/parse fails ⇒ **refuse** (fail closed).
   No‑calldata (native) legs keep the existing finality+ResultHash check.
**Import‑cycle note:** `pkg/execution` cannot import `pkg/consensus` (consensus imports execution),
so the peer's crossChainData parser must use a local anonymous struct in `pkg/execution` (mirror
`extractAllLegsFromIntent`'s parse) — do NOT import `consensus.CrossChainEnvelope`.
**Why sound:** the committed events come from the Accumulate‑fetched signed intent bound to
`msg.IntentID`; a malicious executor can neither forge that intent nor point at a benign intent
(its committed events won't appear in the malicious `AnchorTxHash`'s inclusion‑proven logs).
**Live test:** build a validator with its Phase‑7 gate disabled; it must NOT reach quorum on a
fabricated‑effect call because honest peers on `dc02877`+this fix refuse.

---

# WORKSTREAM 3 — Alternate paths & fail‑open cleanups (#6, #7, #8, #10, #11, #12, #13)

## RB‑SEC‑6 (HIGH) — Legacy orchestrator must not attest contract calls ungated
**Root cause:** `pkg/execution/proof_cycle_orchestrator.go` (executePhase7 `:939`,
executePhase7Enhanced `:719`, executePhase9 `:1049` → `synthetic_transaction.go:781`) has no RB
gate; reachable when `FF_UNIFIED_ORCHESTRATOR=false` (`config.go:205`) or unified init fails
(`main.go:1484/1528`) → `SetProofCycleOrchestrator(legacy)` (`main.go:1565`).
**Fix (fail‑closed):** the legacy path must **refuse any contract‑call intent** (detect non‑empty
committed calldata in the commitment/intent and error out before write‑back), OR run the same RB
gate. Given the unified path is canonical, simplest correct fix: in the legacy executePhase7/9,
if the intent carries a contract‑call leg, abort with a clear error (no write‑back). Additionally,
make unified the hard default and treat unified‑init failure as fatal for contract‑call‑enabled
deployments (don't silently fall back to an ungated path while `CERTEN_ALLOW_CONTRACT_CALLS=true`).
**Tests:** unit — legacy orchestrator + contract‑call intent ⇒ error, no write‑back. Config test —
`CERTEN_ALLOW_CONTRACT_CALLS=true` + unified init failure ⇒ startup refuses / calls disabled.

## RB‑SEC‑7 (CRIT) — `VerifyAgainstResult` must key on committed `TargetChain`, never early‑return‑true for a call
**Root cause:** `external_chain_result.go` ~`:645‑660` returns `true` when
`TxTo==nil && TxData==nil && Status==1` and the **observed** `result.Chain` contains a non‑EVM
substring — `result.Chain` is attacker/RPC‑reported, not the committed `c.TargetChain`, and substring
matching is trivially satisfiable (`"ethereum-via-sui"`).
**Fix (fail‑closed):** (a) branch on the **committed** `c.TargetChain` (trusted), not `result.Chain`;
(b) require `result.Chain` to match `c.TargetChain` (consistency); (c) for the non‑EVM native path,
do NOT blanket `return true` on `Status==1` — still enforce the committed effect for that chain's
model (at minimum value/target; events/state where applicable). Never return true for a leg with
committed calldata without running the event gate.
**Tests:** unit — spoofed `result.Chain="...sui..."` with a committed EVM `TargetChain` ⇒ does NOT
early‑return true; the full checks run.

## RB‑SEC‑8 (HIGH) — Require inclusion proofs (nil ⇒ refuse) and don't trust caller‑supplied result fields
**Root cause:** `result_attestation.go` `VerifyAndAttest` ~`:889‑898` only verifies proofs
`if proof != nil` (nil ⇒ skipped, fail‑open); the observer continues on proof‑construction failure
(`external_chain_observer.go` ~`:202‑213`, `checkExecution` `:743‑747` `txProof, _ := ...`); and
`Status`/`ConfirmationBlocks`/`Logs` are read from the caller struct, not re‑observed.
**Fix (fail‑closed):** for any contract‑call result, `TxInclusionProof` AND `ReceiptInclusionProof`
MUST be present and `Verify()` true — nil ⇒ refuse. Make the observer treat proof‑construction
failure as fatal for contract calls (no result without proofs). Re‑observe (or bind via the
inclusion‑proven receipt) `Status`/`Logs` rather than trusting the passed struct. Ensure the RB‑4
event check runs against **inclusion‑proven** logs only.
**Tests:** unit — `VerifyAndAttest` with nil inclusion proof + a contract‑call commitment ⇒ error.
Observer — proof construction failure ⇒ no attestable result.

## RB‑SEC‑10 (MED) — Multi‑leg aggregator must fail‑fast when a chain group fails the gate
**Root cause:** on Phase‑7 gate failure `StartProofCycle` returns and calls `OnCycleFailed`
(`unified_orchestrator.go` ~`:445‑453`) which is **never set**; the aggregator's `OnChainGroupFailed`
(`multi_leg_aggregator.go:761`) is **dead code**; after `aggregationTimeout` (~30 min, `:129`)
`handleAggregationTimeout` (`:722`) → `buildUnifiedWriteBack` (`:247/326`) silently skips the failed
leg and writes a partial "success", breaking atomicity.
**Fix (fail‑closed):** wire `OnCycleFailed` → `MultiLegAggregator.OnChainGroupFailed`; a failed chain
group must mark the **whole intent** failed (no unified write‑back), especially in `atomic` mode.
Never write a "success" that omits a failed/unverified leg. Remove the silent `continue` that drops
failed legs in `buildUnifiedWriteBack`.
**Tests:** unit — 2‑leg intent, one group fails the gate ⇒ no unified write‑back (or an explicit
failure record), never partial success. Live — multi‑leg with a bad committed event on one leg ⇒
whole intent not attested.

## RB‑SEC‑11 (MED) — Batch/on_cadence path must not no‑op the gate
**Root cause:** `BatchAnchorCallbackAdapter` (`unified_adapter.go:427‑479`) builds the request with
**no `CommitmentData`** (`:454`), so `verifyContractCallGate`'s `if cm==nil { return nil }` (~`:631`)
makes it an unconditional no‑op for anything routed via batch.
**Fix (fail‑closed):** either (a) forbid contract‑call legs on the on_cadence/batch path (reject at
intake), or (b) thread the per‑leg commitment data into the batch request and run the gate. Until
(b) exists, the gate must **refuse** (not `return nil`) if it sees a batch request whose intent
carries committed calldata. The `cm==nil` early‑return must not be reachable for a contract call.
**Tests:** unit — batch request + contract‑call intent ⇒ refused, not silently passed.

## RB‑SEC‑12 (MED) — Strict event matching; remove non‑fatal comprehensive checks
**Root cause:** `external_chain_result.go` `verifyExpectedEvents` (~`:810‑867`) returns true on empty
list and `continue`s past entries with empty/bad `topic0` (treating them as satisfied);
`verifyComprehensive` (~`:740‑787`) has several non‑fatal branches (finalTarget "non‑fatal",
chainID/expectedEvents/anchorContract only enforced "if ok").
**Fix (fail‑closed):** a malformed/undecodable expected event ⇒ **fail**, not skip. Route all
contract‑call event checks through `verifyExpectedEventsStrict` (already fail‑closed). Make
`verifyComprehensive`'s committed checks mandatory (a committed finalTarget/chainID/anchorContract
that can't be confirmed ⇒ fail). Empty expected‑event list for a contract call ⇒ refuse (already
enforced in the RB path; enforce here too).
**Tests:** unit — expected event with malformed `topic0` ⇒ verification fails (not passes).

## RB‑SEC‑13 (MED) — Fix signature/voting‑power desync in aggregation
**Root cause:** `result_attestation.go` `aggregateBLSSignatures` (~`:711‑721`) skips unparseable
signatures, but `tryAggregate` (~`:581‑589`) still counts those validators' pubkeys + voting power;
`AddAttestation` (~`:459/478`) never verifies the individual signature (sets `Verified=true`). Only
the final aggregate verify + threshold saves it — fragile.
**Fix (defense in depth):** verify each individual BLS signature in `AddAttestation` before storing
(reject invalid); only count voting power / include a pubkey for signatures that parse AND verify;
ensure `SignedVotingPower`, the pubkey set, and the aggregated signature are computed over the SAME
consistent set. Keep the final aggregate verify + `CheckThreshold && MeetsSupermajority` as the last
gate. Guard `ThresholdDenominator==0` (currently panics).
**Tests:** unit — an attestation with a bad individual sig is rejected at `AddAttestation`; power is
never counted for it; aggregate finalizes only when signed set == counted set.

---

# WORKSTREAM 4 — On‑chain backstop (finding #2, Solidity redeploy)

## RB‑SEC‑2 (CRIT) — `CertenAccountV4` must enforce `executionCommitment` against executed params
**Root cause:** `certen-contracts/evm/src/account/CertenAccountV4.sol`
`_verifyValidatorSignatures` (`:486‑509`) destructures the anchor tuple and **discards**
`executionCommitment` (`:498`), returning only `valid && proofExecuted`. `_checkOperationAuthorization`
(`:512+`) checks an authority *level* for the selector/value but never recomputes the commitment.
`executeGovernanceProofDirect` (`:289‑308`) takes `(target,value,data)` from the caller and executes
them with no tie to the signed commitment. So the chain does not backstop the validator.
**Fix (fail‑closed, on‑chain):** in the account's execute paths (`executeWithGovernance`,
`executeGovernanceProofDirect`, batch variants), recompute
`keccak256(abi.encodePacked(block.chainid, target, value, keccak256(data)))` and require it EQUALS
the `executionCommitment` read from the anchor for `proof.anchorId` (the value currently discarded at
`:498`). Revert on mismatch (`ExecutionCommitmentMismatch`). This makes the on‑chain layer reject any
execution whose `(target,value,data)` differs from what the BFT quorum signed — independent of the
validator. Confirm the anchor's `executionCommitment` is the quorum‑signed one (trace
`CertenAnchorV6_1` anchor storage + how it's set from the governance proof).
**Redeploy:** new `CertenAccountV4` (and factory if the account is created via factory) on each chain;
update the validator/producer anchor/account addresses; migrate or re‑point test accounts.
**Tests:** Foundry — `executeGovernanceProofDirect` with `(target,value,data)` not matching the
anchor's `executionCommitment` reverts; matching succeeds. Cross‑language vector shared with the
validator (`certen-contracts/test/vectors/execution_commitment_test_vectors.json`). On‑chain — after
redeploy, an intent whose executed target ≠ committed target reverts on‑chain (backstops RB‑SEC‑3).

---

# Sequencing
1. **Workstream 1** (RB‑SEC‑3/4/5/9) — validator choke point. Fastest, closes the most calldata
   bypasses. Land + unit tests + on‑chain negatives.
2. **RB‑SEC‑7, RB‑SEC‑8, RB‑SEC‑12, RB‑SEC‑13** — fail‑closed cleanups in the verification
   primitives (independent, low‑risk).
3. **RB‑SEC‑6, RB‑SEC‑11** — close/guard the legacy + batch alternate paths.
4. **RB‑SEC‑10** — aggregator fail‑fast (multi‑leg atomicity).
5. **RB‑SEC‑1** — quorum independence (peer re‑derivation + verification). Needs the intent‑lookup
   plumbing; land after the choke point so peers reuse the same verified extraction.
6. **RB‑SEC‑2** — on‑chain backstop (Solidity + redeploy). Do last; it's the deepest defense and
   makes RB‑SEC‑3/4/5 belt‑and‑suspenders.

# Global acceptance (all must pass before real users)
1. Every finding #1‑#13 has a merged fix + a unit test + an on‑chain (or multi‑validator) negative
   test that FAILS closed.
2. Regression: native transfers + a correct contract call still attest + write back.
3. **Adversarial executor test:** run a validator built with its Phase‑7 gate disabled; confirm it
   CANNOT get the honest quorum to attest a contract call whose committed event/target didn't occur
   (RB‑SEC‑1 + RB‑SEC‑2).
4. **Ambiguity/spoof tests:** empty commitment (#4), `cardano-*`+EVM chainId (#5), decoupled
   target/value (#3), spoofed `result.Chain` (#7), nil inclusion proof (#8), malformed topic0 (#12)
   — each rejected.
5. Legacy/batch paths (#6/#11) cannot attest a contract call.
6. Multi‑leg: a failed leg blocks the whole‑intent write‑back (#10).
7. On‑chain: executed `(target,value,data)` mismatch vs signed commitment reverts (#2).

# Coverage gaps to fill (tests to add)
`result_attestation.go` (peer path, aggregation desync), `unified_orchestrator.go` (gate matching,
legacy/batch), `bft_target_chain_integration.go` (choke‑point binding, chain classification),
`external_chain_result.go` (VerifyAgainstResult chain keying, strict events),
`certen-contracts` Foundry tests for the on‑chain commitment enforcement. Keep cross‑language
commitment vectors byte‑identical across producer/validator/contract.

---

# RE‑AUDIT ADDENDUM (2026‑07) — post‑Workstream‑1 findings

A 4‑agent adversarial re‑audit of `main` after the first remediation pass surfaced new/residual
findings. Track‑1 (validator repo) items below are **IMPLEMENTED + tested + pushed**
(commits `b2e5d61`, `b7348b0`, `5769783`, `93958f0`). Track‑2 items need a deploy/cross‑repo
decision and are **specified but not yet applied**.

## Track‑1 — DONE (validator repo)
| ID | Sev | Fix | Test |
|----|-----|-----|------|
| #7 | CRIT | `VerifyAgainstResult` binds observed→committed chain; refuses non‑EVM contract calls; non‑EVM confirmation‑only branch reachable only for genuine non‑EVM *native* on the committed chain | `result_chain_bind_sec7_test.go` |
| H1 | HIGH | `peerVerifyCommittedEffect`: reject empty `IntentID`; cross‑check "native" claim against on‑chain execution calldata (`TxHasCalldata`) so a forged empty‑legs intent pointer can't skip the effect gate | `rb_sec1_peer_test.go` |
| H2 | HIGH | Quorum floor: `IsThresholdMet` + RB‑3 collector require ≥`MinValidators`(=3) distinct signers, so a single‑node/empty‑peer set can't trivially meet 2/3 | `threshold_floor_test.go` |
| M1 | MED | Commitment bound to the **routed** `leg.ChainID`, with `ep.ChainID==chainID` assertion (no chain‑redirect) | `workstream1_choke_point_test.go::TestWS1_RejectsChainIDRedirect` |
| #8 | HIGH | `VerifyAndAttest` requires tx+receipt inclusion proofs (nil ⇒ refuse), except genuine non‑EVM native | (covered via VerifyExecutedCall + attest path) |
| #12 | MED | `verifyExpectedEvents` fails on empty/malformed committed topic0 (was `continue`) | `comprehensive_event_sec12_test.go` |
| #10 | MED | Failed multi‑leg group notifies aggregator (`OnChainGroupFailed` wired); atomic aborts; timeout skips partial write‑back when a group hard‑failed | (aggregator logic) |
| #11 | MED | `verifyContractCallGate` fails closed when `rbContractCall=true` but legs parse to zero | `rb_gate_failclosed_sec11_test.go` |
| #14‑producer | — | Verifiable BLS aggregate (sig, message hash, validator‑set root, snapshot id, bitfield, total power, threshold ratio) appended to the Accumulate write‑back | `writeback_aggregate_sec14_test.go` |

#13 already closed (RB‑3 verifies the aggregate BLS sig before finalize). #6/H3 (legacy path)
substantially closed: it shares `VerifyAgainstResult`/`VerifyAndAttest`/the RB‑3 collector, so it
inherits #7/#8/#12/H2.

## Track‑2 — SPECIFIED, needs decision

### FINDING B (CRIT, on‑chain, LIVE) — permissionless replay/drain of an anchored effect
`certen-contracts/evm/src/account/CertenAccountV4.sol`.
`executeGovernanceProofDirect` (≈L291) is permissionless (only `validGovernanceProof /
sufficientAuthority / nonReentrant`). The only durable single‑use gate is
`_usedProofs[_getProofHash(proof)]`, and `_getProofHash` (≈L586) =
`keccak256(adiURL, anchorId, timestamp, nonce, requiredLevel)` where **timestamp, nonce, and
requiredLevel are caller‑supplied and NOT anchor‑bound** (nonce=0 skips the nonce gate; timestamp
only bounded `timestamp ≤ block.timestamp ≤ expiresAt`). An attacker replays the exact committed
`(target,value,data)` — which passes the CRITICAL‑001 commitment check — with a fresh `timestamp`
each call ⇒ new proof hash ⇒ `_usedProofs` never trips ⇒ the anchored transfer/call re‑executes
unboundedly. The commitment check binds *what* executes but not *how many times*.

**Fix (choose one; A preferred):**
- **A. Key single‑use to the anchor identity.** Change `_getProofHash` (or add an
  `_anchorConsumed[anchorId]` check‑and‑set consumed in `executeGovernanceProofDirect` /
  `executeWithGovernanceProof` / `batchExecuteWithGovernanceProof`) so replay protection keys on
  `proof.anchorId` alone (each anchor commits to exactly one `executionCommitment` = one
  `(target,value,data)`, so one execution per anchor is the correct invariant). Malleable
  timestamp/nonce/level can then no longer mint fresh proof hashes.
- **B. Consume the anchor's on‑chain flag.** Mirror `CertenAnchorV6_1.executeWithGovernance`
  (check‑and‑set `governanceExecuted` on the anchor) from the account path.

**Also (MED):** `proof.requiredLevel` is caller‑supplied and only checked `>= computedLevel`;
bind it to the anchor (`anchor.governanceLevel`) or drop the caller‑supplied level.

**Test plan (Foundry, `certen-contracts/evm/test/`):**
1. `test_ReplayDrainBlocked`: create anchor for `(target,value,data)`, call
   `executeGovernanceProofDirect` once (succeeds), call again with a different `proof.timestamp`
   ⇒ MUST revert (single‑use by anchor).
2. `test_PermissionlessCallerStillBoundToCommitment`: a non‑owner caller can only execute the
   exact committed `(target,value,data)` (unchanged) — and only once.
3. `test_BatchDistinctLegs`: document/behave for the batch path (currently reverts unless legs are
   byte‑identical — separate LOW correctness item E).

**Deploy:** requires redeploying `CertenAccountV4` across chains — **needs explicit authorization**
given the operator/BLS identity blast radius. Do NOT deploy from this workstream without sign‑off.

### #14‑consumer (audit layer) — web‑app must verify the aggregate
`certen-web-app` `TransactionStatusPollingService.ts` currently trusts `threshold_met==='true'`.
Now that the write‑back carries the verifiable aggregate (see #14‑producer), the consumer should
recompute `signed/total ≥ threshold_numerator/threshold_denominator` AND verify the aggregate BLS
signature over `attestation_message_hash` under the validator set at `validator_set_root` before
displaying "quorum verified". Separate repo.

### M2 (product) — non‑EVM contract calls
The choke point + `VerifyAgainstResult` now REJECT non‑EVM legs carrying calldata (fail‑closed),
consistent with "EVM legs do native/contract calls; non‑EVM is native‑only for now." Confirm this
is the intended stance, or scope trustless non‑EVM effect proofs before enabling non‑EVM calldata.
