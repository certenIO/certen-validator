# Proof v2 — a proof that needs no trust in CERTEN, any node, any provider or any retention window

Status: r2 SIGNED OFF by the owner 2026-10-04 (RB6 §1); §8, §11 and §12 carry the owner's decisions. r1 covered the Accumulate side only; r2 is the full recommendation. Nothing
in v2 ships before sign-off. v1 is frozen and keeps verifying every stored v1 proof forever.

## 1. The goal, stated as a trust base

A verifier holding a v2 proof and nothing else must be able to establish every statement in §3, trusting only:

1. **Accumulate:** the published genesis incarnation anchor, and that more than 2/3 of the voting power of each
   Accumulate validator set in force was honest.
2. **The target chain:** Ethereum's consensus (more than 2/3 of stake for finality); for Base and Arbitrum, also that
   their L1 contracts enforce the rollup's rules (the fault-proof / assertion system settled on Ethereum).
3. **Standard cryptography:** SHA-256, Keccak-256, Ed25519, BLS12-381, BN254.

Nothing else is a trust input: not CERTEN, CERTEN's validators or database, the node that served the data, an RPC
provider, agreement between providers, a CERTEN-published checkpoint, or whether any node still retains history.

These are the irreducible assumptions; no design can remove them. Stated residual assumptions:
- Sepolia's beacon validator set is permissioned (testnet); the same machinery on mainnet runs against the open set.
- A testnet incarnation restart ends that incarnation's chain of trust; a proof reaches its own incarnation's genesis.

## 2. Principles

1. **Self-contained at creation.** Every byte of evidence a v2 proof needs is captured while it is servable and stored in
   the proof: pages, receipts, the spine segment, state proofs, target-chain headers and finality evidence. Verifying it
   later needs no network. Retention windows decide whether a proof *can be built*, never whether it *stays valid*.
2. **CERTEN is not a trust input.** CERTEN's own BLS attestation (L5) is verified and reported, but §3's statements S1–S8
   hold without it. A proof that only verifies by trusting CERTEN's validators is not a v2 proof.
3. **Named states, never fallbacks.** Anything that cannot be proven is reported by name with the height, partition or
   block it was judged against; nothing is relabelled, defaulted or skipped.
4. **Staged finality, never premature.** A proof states the finality level its evidence reaches today and is upgraded,
   append-only, when stronger evidence becomes available. It never claims a level it cannot prove.
5. **Two implementations, one specification.** A written acceptance predicate; independent Go and TypeScript verifiers;
   shared conformance vectors including every adversarial case. Two implementations disagreeing is stop-the-line.

## 3. What a v2 proof proves (the acceptance predicate)

| | statement | evidence (all carried in the proof) |
|---|---|---|
| S1 | The intent's exact bytes are in Accumulate | L1 + account-state leg; one continuous receipt to a Directory root (§4.2) |
| S2 | That Directory root was certified by >2/3 of the set in force | L4 signatures; the set derived by induction from the incarnation along the spine, every window checked (§4.3) |
| S3 | The intent was authorized by the principal's key pages **as they were** at execution | G1(a) pages served `ForHeight`, proven into certified roots; G1(b) the authority set is complete; delegation on every partition at its own block (§5) |
| S4 | Accumulate's status/outcome for it | G2 bound to certified roots (§5) |
| S5 | The target transaction is exactly what was authorized | chain, target, value, calldata, nonce recomputed from S1's bytes = the execution commitment = the fields of the proven tx |
| S6 | It executed, once, successfully | tx + receipt MPT-proven into the block (L6/F16), status 1, the contract's event, and the replay-nonce slot consumed (storage proof) |
| S7 | That block is final | staged: `included` → `l1_posted` → `finalized`, each level carrying its own evidence (§7) |
| S8 | The contracts are the ones they claim to be | account + anchor code hashes and the registered BLS keys / validator set, proven by account/storage proofs against S7's finalized state root (§7) |
| S9 | CERTEN's validators attested it (supplementary) | L5 BLS aggregate, keys proven by S8 |

The verifier outputs one verdict per statement plus an overall verdict. A missing statement is named, never assumed.

## 4. Accumulate side — chained proof v2

1. **L1 + account-state leg:** L1 unchanged; plus a leg starting at `sha256(account binary)` for the principal account.
2. **L2+L3 → one continuous receipt** to a Directory root (query receipt → `anchor-receipt` → `Combine`, upstream
   !1227). An unlinked L2/L3 becomes impossible by construction.
3. **L4 from the spine.** The Directory set is derived by induction from the incarnation anchor through
   `major-header-range` / `minor-root-range` to the exact root S1 ends at:
   - each window's anchor signatures are checked against the set in force;
   - at every window, `dn.acme/network` and `dn.acme/globals` are proven against that window's certified root (closes
     update omission, stale-globals replay, window skipping, a forged major-index entry);
   - a proof-authorized (signature-less, Kourou) anchor counts only as a Merkle path to an already-verified root;
   - the proof carries its spine segment. CERTEN-published checkpoints are accelerators the verifier re-derives, never
     inputs (measured: all 473 Kermit majors verify in 1.7 s / 887 KB).
4. **One function:** the committed accRoot (RB5 Phase B) equals the root of the spine-derived set at that block.
5. **RB5-F7:** the principal BVN's `/network` + `/globals` as of the anchor block, proven against a quorum-certified root.
6. **RB5-F22:** `cmd/incarnation` proves genesis `/network`, `/globals` and `ledger/1` into a quorum-certified Directory
   root, not the serving node's current root.
7. **Adversarial suite** (lying-server simulator built on accumulate-core's simulator), each rejected: omitted set update;
   replayed stale globals; skipped window; forged major-index entry; signature-less anchor presented as signed; receipt to
   an uncertified root.

## 5. Governance proof v2

1. **G0:** the execution receipt bound to a certified Directory root (S1's receipt).
2. **G1(a) — pages as they were:** for execution block B, each signer page and the principal's authority set queried
   `ForHeight=B`, `StartsAtMainState` required, `sha256(served bytes) == receipt.start`, combined to a certified root,
   signatures judged against the pages as proven. Every delegate page on every partition at its own recorded block.
   - Shadow cross-check: v1's replayed page must equal v2's served page for every intent; a disagreement is stop-the-line.
   - RB5-F19/B4: the enumeration route reads delegate pages as of execution, its window bounded at execution.
3. **G1(b) — completeness:** proof that the authority set judged is the complete set in force at B (no omitted
   authority, no disabled one counted). Argument in `docs/proof/G1_COMPLETENESS_ARGUMENT.md`, implemented only if sound;
   until then S3 reports completeness by name as unproven.
4. **G2:** status and outcome bound to certified roots by the same receipt machinery.
5. **Adversarial tests:** served page ≠ receipt start; receipt to an uncertified root; page from a block other than B;
   a delegate page on another partition judged at the wrong block; an authority omitted from the set.

## 6. Consensus-engine independence

Accumulate is replacing CometBFT with DAG-BFT (memory/docs: `DAGBFT_MIGRATION_ANALYSIS.md`). L4 verification sits behind
one interface (`CertifiedRoot(root, evidence) → set, verdict`) with a CometBFT implementation now and a DAG-BFT one
later; G0–G2 and L1–L3 do not change. **Hard requirement raised upstream now:** the DAG-BFT certificate must commit to the
state root (the analysis found the StateHash excluded from the certificate quorum). Without it, S2 cannot be proven under
DAG-BFT and is reported by name, never weakened.

## 7. Target-chain side — finality and contract identity (Phase B)

**Finality levels (S7)**, each with the evidence carried:
- `included` — the block header and the MPT proofs (today's L6).
- `l1_posted` — Base/Arbitrum: the block's data is in an L1 batch, proven by the L1 inbox/batch transaction's inclusion
  in an L1 block.
- `finalized`:
  - **Sepolia:** a beacon light-client proof — sync-committee chain from a pinned weak-subjectivity checkpoint to a
    finalized header whose execution payload is the block (or an ancestor connected by a header chain).
  - **Base Sepolia:** the dispute game / output proposal for an L2 block ≥ ours, resolved in the proposer's favour on L1
    and past its finality delay; the output-root preimage gives the L2 block hash; a header chain connects it to ours;
    the L1 block holding the resolution is itself `finalized` as above.
  - **Arbitrum Sepolia:** a confirmed assertion in the rollup contract covering our block; its block hash; a header
    chain to ours; the L1 confirmation block `finalized` as above.

`finalized` for a rollup arrives only after its challenge period (days). The proof is built at `included`/`l1_posted`
and upgraded append-only when finality evidence exists; the original bytes never change. The gateway shows the level.

**Contract identity (S8):** against the finalized state root, account proofs give the code hashes of the CertenAccount
and anchor contracts (compared with the published, reproducible builds), and storage proofs give the registered BLS
keys / validator set and the consumed replay-nonce slot.

**To be confirmed before Phase B build (not assumed):** each rollup's current proof system and delay on its Sepolia
deployment; the beacon light-client endpoints available for Sepolia; header-chain lengths (cost) per chain.

## 8. Permanence and independence

1. **CERTEN-run archival nodes:** owner decision 2026-10-04: **not for now.** v2 proofs are built from public Kermit
   nodes; an execution block outside their retention gets the named state `g1_historical_unavailable` /
   `historical_state_unavailable`, never a fallback. Revisit if that state appears in production.
2. **Anchor the trust root publicly:** the incarnation anchor and periodic spine checkpoints are committed on Ethereum, so
   the trust root is public and timestamped (still re-derived, never trusted).
3. **Upstream asks** (owner: yes, tracked in RB7 §3C): publish the genesis anchor incl. incarnation; version `globals` writes; sign the major-block index
   entry; attach a per-window network-state proof; the DAG-BFT state-root requirement (§6).

## 9. Verification assurance

1. `docs/proof/V2_SPEC.md`: the acceptance predicate for S1–S9, precise enough to implement from.
2. Go (`proofverify`) and TypeScript verifiers, independently written, against shared vectors (valid, each adversarial
   case, each named state). CI fails on any disagreement.
3. Lying-server simulators for Accumulate (§4.7) and the target chains (forged header chain, wrong-fork block, unresolved
   or lost dispute game, unconfirmed assertion, wrong code hash, wrong storage slot).
4. Fuzzing of every decoder the verifier runs on untrusted bytes.

**Deliberately not recommended:** wrapping the whole proof in a SNARK (it adds circuit and setup risk without adding
soundness; useful only later for on-chain consumption), and treating provider agreement as evidence (it stays a read
tool, never a proof).

## 10. Versioning

1. New packages beside v1: `proof/chained_proof_v2`, `proof/governance_proof_v2` (liteclient), `pkg/proof/v2`, and
   `pkg/finality` (validator). v1 bytes and verdicts never change.
2. `proof_artifacts.proof_version = '2.0'`; the bundle carries it; `proofverify` dispatches on it; unknown → refused.
3. New domain tags, never reused: `certen:chain-proof:v2`, `certen:l4gov:v3`, `certen:g1:v2`, `certen:g2:v2`,
   `certen:finality:v1`, `certen:contract-identity:v1`. New evidence beside hashed summaries, never inside them.
4. govRoot changes → atomic fleet switch after shadow; v2 goldens are new files.
5. Named states include: `g1_historical_unavailable`, `l4_spine_unavailable`, `historical_state_unavailable`,
   `g1_completeness_unproven`, `finality_pending` (with the level reached), `consensus_engine_unsupported`.

## 11. Phases and rollout

- **Phase A — Accumulate side, self-contained:** §4, §5, §6, §8.1–8.2, the spec and both verifiers for S1–S5.
- **Phase B — target-chain side:** S6 nonce slot, §7 finality levels and contract identity, both verifiers for S6–S8.
- Each phase: shadow beside v1 (only v1 feeds govRoot) → exit → atomic switch → live e2e on all three chains → every
  stored proof and every new proof verifies.
- **Shadow exit (owner decision 2026-10-04): no time period.** A short run of live intents covering the hard cases (each
  chain; a delegated signer; multiple signers; a signer page on another partition; a multi-leg intent) with zero
  disagreements (v1 vs v2 page, Go vs TypeScript) and zero verification failures. Any failure: fix and re-run.
- **Phase B follows Phase A directly**; its research items (§7) are done while Phase A is in shadow.

Rough size: Phase A several weeks; Phase B more (light client and rollup finality are the largest single pieces);
together a matter of months, not weeks.

## 12. Owner decisions (2026-10-04)

1. Design: signed off.
2. Shadow exit: no time period; a short hard-case run, zero disagreements, zero failures (§11).
3. Archival node: not for now (§8.1). Upstream asks: yes, in RB7 §3C.
4. Phase B directly after Phase A.

## 13. Order of work after sign-off

Spec (S1–S5) → §4.2 continuous receipt → §4.3 spine L4 + lying-server suite → §4.4–4.6 → §6 engine interface →
§5 G1(a) + cross-check → G1(b) argument → evidence capture + storage → TS verifier → shadow → switch (Phase A) →
Phase B research items (§7) → spec S6–S8 → finality levels → contract identity → TS → shadow → switch.
