# Proof v2 — every layer against a certified root, governance against the key page as it was

Status: DRAFT for owner sign-off (RB6 §1). Nothing in v2 ships before this is signed off. v1 is untouched by v2 and keeps
verifying every stored v1 proof forever.

## 1. Why v2

A v1 proof (L1–L4 chained proof, G0–G2 governance proof, L5 anchor, L6 outcome) is sound for what it states, but three
of its statements rest on evidence the verifier must take on trust or that is weaker than it could be now:

| v1 | weakness | v2 |
|---|---|---|
| L2 and L3 are two receipts stitched by a linking check | a verifier relies on the check being right (bug 1 was exactly this) | one continuous receipt: query receipt → `anchor-receipt` → `Combine` (upstream !1227), ending at a Directory root |
| L4's validator set is carried by the proof | the set is unbound to genesis (`validator_set_unbound`); a lying server could serve a set | the Directory set is derived **by induction** from the published incarnation anchor along the AIP-59 spine, every window checked |
| G1 replays the key page's main chain to reconstruct the page at execution | correct, but a reconstruction | the page **as it was** at the execution block, served by `ForHeight` and proven into a certified root (AIP-58) |

Accumulate Kermit runs v1.4.6.7 with retention (BVN1 from 12,874,941; Directory from 9,834,125): historical account
state is servable for blocks inside retention. Outside it, v2 states a named state and never relabels a v1 reconstruction
as v2.

## 2. Versioning (RB6 §1.1–§1.5)

1. **New packages beside v1:** `proof/chained_proof_v2` and `proof/governance_proof_v2` (liteclient module) and
   `pkg/proof/v2` (validator). The v1 packages are frozen: no change to their bytes or verdicts.
2. **Version marker:** `proof_artifacts.proof_version` (exists, default `'1.0'`) is set to `'2.0'` for a v2 proof. The
   bundle carries `proof_version`. `proofverify` dispatches by it: `1.0` → the v1 verifier (unchanged), `2.0` → the v2
   verifier. An unknown version is refused by name.
3. **Domain tags:** every hashed summary that changes gets a new tag; a tag is never reused for different bytes:
   - `certen:l4gov:v3` (v2 L4 preimage: spine-derived set + window evidence commitment);
   - `certen:g1:v2` (G1 from served historical pages);
   - `certen:g2:v2` (G2 bound to certified roots);
   - `certen:chain-proof:v2` (the continuous L1–L3 receipt commitment).
   New evidence goes beside hashed summaries (`omitempty`), never inside an existing one.
4. **govRoot:** v2 changes govRoot inputs → atomic fleet switch (00_STANDARD §5) after the shadow period; v2 goldens are
   NEW golden files; v1 goldens stay as they are.
5. **Named states, never a fallback:**
   - `g1_historical_unavailable` — the execution block precedes the partition's retained range;
   - `l4_spine_unavailable` — the spine segment from the incarnation to the needed root cannot be served;
   - `historical_state_unavailable` — `ForHeight` cannot serve the account at the block;
   - each carries the block, partition and the retained-from height it was judged against.

## 3. Chained proof v2 (RB6 §3)

1. **L1 + account-state leg:** L1 unchanged; plus a leg whose receipt starts at `sha256(account binary)` for the principal
   account (`Account.StateReceipt`).
2. **L2+L3 → one continuous receipt** ending at a Directory root, built with the upstream two-call proof. Unlinked L2/L3
   becomes impossible by construction.
3. **L4 from the spine:** the Directory validator set is derived by induction from the incarnation anchor (RB5 Phase A,
   published, pinned in `proofverify --incarnation`) through `major-header-range` / `minor-root-range` to the exact
   Directory root the continuous receipt ends at:
   - each window's executor-layer anchor signatures are checked against the set in force;
   - **at every window**, `acc://dn.acme/network` and `acc://dn.acme/globals` are proven against the window's certified
     root (closes update omission, stale-globals replay, window skipping, and a forged major-index entry);
   - a proof-authorized (signature-less, Kourou) anchor is accepted only as a Merkle path to an already-verified root,
     never as "signed".
   - **Offline form:** the proof carries the spine segment it needs, or names a CERTEN-published checkpoint that the
     offline verifier can re-derive from the incarnation anchor (a checkpoint is a speed-up, never a trust input).
     Measured earlier: all 473 Kermit majors verify in 1.7 s / 887 KB.
4. **One function:** the committed accRoot (RB5 Phase B) must equal the root of the spine-derived set at that block.
5. **RB5-F7:** with retention live, the principal BVN's `/network` + `/globals` as of the Directory-anchor block are proven
   against a quorum-certified root, so the committed set reaches `verified` for every proof inside retention.
6. **RB5-F22:** `cmd/incarnation` proves the genesis `/network`, `/globals` and `ledger/1` into a quorum-certified
   Directory root (ForHeight → anchor-receipt → committed root → its L4 signatures), not the serving node's current root.

**Adversarial suite (lying-server simulator), each must be rejected:** omitted validator-set update; replayed stale
globals; skipped window; forged major-index entry; signature-less anchor presented as signed. Built against
accumulate-core's simulator, as `difftest` does for the key-page replay.

## 4. Governance proof v2 (RB6 §4)

1. **G0:** the execution receipt bound to a certified Directory root (the continuous receipt), as v1 binds it to L1.
2. **G1 (a) — the page as it was:** for execution block B, query each signer page and the principal's authority set with
   `ForHeight=B`, require `StartsAtMainState`, require `sha256(served bytes) == receipt.start`, combine through
   `anchor-receipt` to a certified root, judge the signatures against the pages AS PROVEN. Every delegate page on every
   partition at its own recorded block. B before retention → `g1_historical_unavailable`.
   - **Shadow cross-check:** for every intent where both exist, the replayed v1 page must equal the served v2 page; any
     disagreement is stop-the-line.
   - **RB5-F19/B4:** the secondary (enumeration) route reads delegate pages as of execution and bounds its window at the
     execution point, not the chain head; a two-read-height test pins it.
3. **G1 (b) — completeness argument:** written up in `docs/proof/G1_COMPLETENESS_ARGUMENT.md`; implemented only if sound.
4. **G2:** status and outcome bound to certified roots by the same continuous-receipt machinery.
5. **Adversarial tests:** served page not matching receipt start; receipt to an uncertified root; page served from a block
   other than B; a delegate page on another partition judged at the wrong block.

## 5. Storage, verifier, bundle (RB6 §5)

- New content in `level_json` / `layer_json` is additive; new columns only through validator migrations (after 00021),
  shipped with the binary, applied by `schema-migrate`.
- `proofverify` verifies v1 and v2 by `proof_version`; RB1's bundle v2 carries v2 evidence; the TypeScript verifier gains v2
  under the same conformance-suite discipline.

## 6. Rollout (RB6 §6)

1. **Shadow:** the fleet computes v2 beside v1; only v1 feeds govRoot; every v2 result is verified and compared (§4.2).
2. **Switch:** govRoot moves to v2 atomically, with the new domain tags; live e2e on all three chains; the stored-proof
   comparison plus every new proof verifies.

## 7. Owner decisions requested

1. Sign off this design (versioning, tags, named states, the offline spine form).
2. Shadow period: proposed **14 days and at least 50 live intents on the three chains with zero G1 cross-check
   disagreements and zero v2 verification failures** as the exit criteria.
3. Independence (RB6 §7): run CERTEN's own retaining Kermit node(s) from genesis (`bpt-history-depth` covering all
   history); and which upstream asks to post (publish the genesis anchor incl. incarnation, version `globals` writes, sign
   the major-block index entry, attach a per-window network-state proof).

## 8. Order of work after sign-off

§3.2 continuous receipt → §3.3 spine L4 with the lying-server suite → §3.4–§3.6 → §4 G1(a) + cross-check → §4.3 argument
→ §5 storage/verifier/bundle → shadow → switch.
