# Phase 7 — Delegated and multi-signature governance, end to end

**Status:** SCOPED, not started
**Date:** 2026-08-24
**Scope:** ED25519 and Delegated signature types only. Multi-sig (M-of-N) and
delegation are must-support.
**Covers:** G0–G2 governance proofs **and** L1–L4 chained proofs
**Backup taken:** `_PROOF_BACKUPS/20260824_210857` (180 files, manifest verified)

> ⚠️ **Unlike Phase 6, this phase MOVES govRoot.** See §5. Plan the atomic fleet
> upgrade before writing code, not after.

---

## 0. The one-line summary

CERTEN cannot verify a delegated or multi-signature governance proof at all
today. G1 rejects every signature whose type is not `ed25519`, and a delegated
signature's type is `delegated`. Every proof on record is 1-of-1. Making these
work is not an enhancement to the proof system — it is the first time the proof
system meets the product's central claim, that institutional governance with
real authority structures is what authorizes execution.

---

## 1. What is broken, precisely

### 1.1 Delegated signatures are refused before any cryptography runs

`consolidated_governance-proof/signature_verifier.go:438`:

```go
if strings.ToLower(sigTypeStr) != "ed25519" {
    return SignatureData{}, ValidationError{Msg: fmt.Sprintf("Not an ed25519 signature (type: %s)", sigTypeStr)}
}
```

`grep -i delegat` across the entire validator tree returns nothing but
unrelated prose. Delegation is absent, not partial.

### 1.2 Multi-sig has never been exercised

All 400 governance proof rows are `threshold_m = 1, threshold_n = 1`. The
M-of-N path is untested rather than unimplemented — `RequiredThreshold` and
`UniqueValidKeys` exist in `g1_layer.go` — but untested at 1-of-1 means the
distinct-signer accounting, the duplicate-key rejection, and the
below-threshold failure mode have no production evidence.

### 1.3 Delegation changes the signed bytes

This is the part that will break a naive implementation.

```go
// protocol/signature.go:936
func (s *DelegatedSignature) Metadata() Signature {
    r := s.Copy()
    r.Signature = r.Signature.Metadata()   // recurses
    return r
}

// protocol/signature_utils.go:26 — hashes the OUTERMOST metadata
if verify(outer.Metadata().Hash(), msgHash[:]) { return true }
```

For a delegated signature the digest is

```
digest = SHA256( SHA256(canonical(DelegatedSignature.Metadata())) || txHash )
```

and that metadata recursively contains **every `Delegator` URL in the chain**.

An implementation that verifies the inner ed25519 against a plain digest and
then separately resolves the delegation path **will fail every time**. The path
is inside the signed bytes. This is the same failure shape as the L4
`signedHash`-versus-transaction-hash confusion: a well-formed digest that never
verifies.

`DelegationDepthLimit = 20` (`protocol/protocol.go:89`).

### 1.4 There are two accepted digests, and only one is implemented

```go
if verify(outer.Metadata().Hash(), msgHash[:]) { return true }
if !merkle { return false }
h, err := us.Initiator()
return verify(h.MerkleHash(), msgHash[:])
```

A signature is valid under the metadata digest **or** the `Initiator()` merkle
hash. `ComputeAccumulateDigest` implements only the first. A signature valid
under the second is currently counted as invalid — which, because G1 fails
closed, surfaces as a governance rejection rather than an error. That is
indistinguishable from "the institution did not authorize this".

### 1.5 Signature enumeration is still half-satisfied

Governance spec §4.1 item 5 requires *"Enumeration of `P#signature` entries and
single-entry resolution for each counted candidate"*. `L4_DESIGN.md` §1.3
Defect C recorded that resolution happens and enumeration never does — the
enumeration subsystem had zero callers. Phase 4A replaced the stub with real
route-based evidence, but enumeration across **multiple signer accounts** is
exactly what multi-sig and delegation require, so this must be finished here.

---

## 2. The structural finding: governance can span partitions

`DelegatedSignature.RoutingLocation()` returns the **innermost** signer's
routing location, and Accumulate routes by account URL to a partition. So:

> A delegated signer — or a second key book in a multi-sig — may live on a
> **different BVN** than the principal.

Today `ChainedProof` carries exactly one BVN leg. The P5.7 build log reads
`Building L1-L4 chained proof for acc://certen-kermit-12.acme/data (bvn=bvn1)`,
and `Layer4BVN.Partition = "BVN1"`. One principal, one partition.

For delegated or cross-book multi-sig governance that is not sufficient. Each
**distinct signer partition** needs:

- its own **L1** leg — the signature entry's inclusion on that signer's chain
- its own **L2** leg — that BVN's anchor into the DN
- its own **L4-BVN** leg — that BVN's validator quorum over the anchor

L3 and L4-DN remain single: there is one Directory.

**This is the largest single change in Phase 7**, and it is what moves govRoot.

---

## 3. Design — governance half (G0–G2)

### 3.1 Signature model

Replace the flat `SignatureData` with a chain-aware form:

```go
type SignerLink struct {
    Delegator string // acc:// URL of the authority that delegated
}

type SignatureData struct {
    Type          string        // "ed25519" | "delegated"
    Chain         []SignerLink  // outermost → innermost; empty for a bare ed25519
    PublicKey     string
    Signature     string
    Signer        string        // innermost signer key page
    SignerVersion uint64
    Timestamp     *uint64
    // ...
}
```

`Chain` is ordered and load-bearing: it reproduces the nesting the digest
commits to.

### 3.2 Digest construction

One function, both forms, mirroring `verifySigSplit` exactly:

```go
func AcceptedDigests(sig SignatureData, txHash [32]byte) [][]byte
// returns [metadataDigest, initiatorMerkleDigest]
```

A signature counts if **either** verifies. Record which one in the evidence so
the distribution is observable — if the merkle form never appears in practice
that is worth knowing, and if it does, §1.4 was a live bug.

Build the metadata by constructing the real `protocol.DelegatedSignature`
nesting and calling `.Metadata().Hash()`, rather than reimplementing the
encoding. The canonical encoding is field-tagged with omit-if-zero and varints
(`types_gen.go:8996`); reimplementing it by hand is how the field-strictness
bugs in `project_non_evm_v6_1_recipe` happened.

### 3.3 Authority resolution

```
satisfied(page P, version V) :=
    |{ e ∈ P.Keys : satisfied_entry(e) }| ≥ P.AcceptThreshold
```

where an entry is satisfied by a direct ed25519 signature whose
`SHA256(pubkey)` equals `e.PublicKeyHash`, **or** — when `e.Delegate ≠ nil` —
by `satisfied(e.Delegate, its version)`.

Rules that must be explicit, because each is a way to over-count:

- **Distinct entries.** One key satisfies at most one entry. Two signatures from
  the same key are one acceptance. This is the duplicate-collapse rule L4
  already applies to validator signers.
- **Version binding (KPSW-EXEC).** Each signature's `SignerVersion` must equal
  the page version at execution time. A signature valid under an older page is
  not valid now.
- **Depth bound.** Refuse beyond `DelegationDepthLimit = 20`, matching
  Accumulate rather than inventing a limit.
- **Cycle refusal.** A delegation graph may cycle. Track visited page URLs and
  fail closed on revisit.
- **Path binding.** The `Chain` used to build the digest must equal the path
  walked during resolution. If they differ, the signature is not evidence for
  that path.

### 3.4 What does not change

G0 is inclusion and finality only — unaffected. G2's outcome binding
(`g2_outcome_binding.go`, `receipt_merkle.go`) is about the outcome leaf, not
the signer, and is unaffected except that its `G1Result` input grows.

---

## 4. Design — state half (L1–L4)

### 4.1 Multi-partition ChainedProof

```go
type ChainedProof struct {
    Input  ProofInput
    Layer1 []Layer1     // one per distinct signer partition (was: one)
    Layer2 []Layer2     // one per distinct signer partition (was: one)
    Layer3 Layer3       // Directory — single
    Layer4BVN []*Layer4 // one per distinct signer partition (was: one)
    Layer4DN  *Layer4   // Directory — single
    Artifacts map[string][]byte
}
```

Ordering must be canonical — sort by partition ID — for the same reason
`summarizeL4Leg` sorts signers: two validators reading identical chain data must
produce identical bytes, or govRoot diverges intermittently.

### 4.2 Per-signature inclusion

Every **counted** signature needs its own receipt-proven inclusion on its
signer's signature chain, anchored through that partition. "Counted" is the
operative word: a signature that does not contribute to the threshold does not
need a proof, and proving uncounted signatures inflates cost without adding
evidence.

This is where §1.5's enumeration finally lands — `P#signature` enumeration per
signer account, with single-entry resolution for each counted candidate.

### 4.3 Verifier

`ProofVerifier` must verify every BVN leg and reject if any fails. The existing
cross-bind protection generalises: each `Layer4BVN[i].StateTreeAnchor` must
equal the `Layer2[i]` it binds, and a leg from another proof must not be
graftable — `layer4_crossbind_test.go` already pins the two-leg case and needs
extending to N.

---

## 5. govRoot impact — read before writing code

`ConsensusProof` is the govRoot preimage and `CanonicalJSONMarshal` is
`json.Marshal`, so struct layout is the wire format.

| Change | Moves |
|---|---|
| `ConsensusProof.BVN` → a sorted list | **L4ConsensusProofH** |
| `G1Result` gains delegation evidence | **G1CanonicalHash** |
| `ReceiptData` unchanged if `Entries` already present | — |

So Phase 7 moves at least two govRoot slots. That is a **hard fleet upgrade**:
mixed-version signers produce different roots and every TX2 reverts.

Consequences for sequencing:

1. **Bump `L4GovRootVersion`** from `certen:l4gov:v1` to `v2`. The field exists
   for exactly this and a silent shape change is what it was added to prevent.
2. **Land Phase 6 first.** Do not change the proof format while stored proofs
   still cannot be verified offline — you lose the ability to audit the
   transition afterwards.
3. **One atomic upgrade** covering the whole of Phase 7. Do not ship the
   governance half and the state half as two govRoot moves.

---

## 6. Work breakdown

| # | Item | Est. |
|---|---|---|
| 7.1 | Characterization: pin current govRoot, current 1-of-1 behaviour, current digest | 1 d |
| 7.2 | Test corpus: real delegated + multi-sig traces from Kermit, with expected verdicts | 2 d |
| 7.3 | `AcceptedDigests` — both forms, delegated nesting (§3.2) | 2 d |
| 7.4 | Authority resolution — M-of-N + delegation + the five rules (§3.3) | 3 d |
| 7.5 | Signature enumeration per signer account (§1.5, §4.2) | 2 d |
| 7.6 | Multi-partition `ChainedProof` + builder (§4.1) | 3 d |
| 7.7 | Multi-partition verifier + cross-bind generalisation (§4.3) | 2 d |
| 7.8 | `L4GovRootVersion` v2 + `summarizeL4Leg` over N legs | 1 d |
| 7.9 | Live e2e with a real delegated multi-sig ADI | 2 d |
| 7.10 | Atomic fleet upgrade | 1 d |

**~19 working days.** 7.2 gates everything after it — without a corpus this is
being written blind.

---

## 7. Verification plan

| # | Gate | Method |
|---|---|---|
| P7.1 | Corpus exists and the current code fails it | delegated traces must fail today; if they pass, the corpus is wrong |
| P7.2 | Digest parity with accumulate-core | for every corpus signature, our digest == `outer.Metadata().Hash()` fed through `verifySigSplit` |
| P7.3 | Both digest forms accepted | at least one corpus case valid only under `Initiator()` merkle |
| P7.4 | M-of-N counts distinct entries | duplicate key = one acceptance; below threshold = fail closed |
| P7.5 | Delegation depth and cycles | depth 21 refused; a cycle refused, not looped |
| P7.6 | Path binding | a signature with a correct inner key but a wrong delegator chain is refused |
| P7.7 | Multi-partition proof builds and verifies offline | signers on ≥2 BVNs; network disabled |
| P7.8 | Every BVN leg is checked | corrupt leg *i* of N; must fail for every i |
| P7.9 | Cross-bind rejected at N legs | graft leg from another proof; refused |
| P7.10 | Canonical ordering | shuffle partition discovery order; bytes identical |
| P7.11 | govRoot moved deliberately, once | new value recorded; `L4GovRootVersion == certen:l4gov:v2` |
| P7.12 | Live e2e settles | real delegated multi-sig ADI, on base-sepolia |

P7.2 and P7.6 are the two that catch the failure modes §1.3 predicts.

---

## 8. Risks

| Risk | Severity | Handling |
|---|---|---|
| Digest built without the delegator chain | **critical** — every delegated signature silently fails, looking like a governance rejection | P7.2, P7.6; build via `protocol` types, never by hand |
| Only the metadata digest implemented | **high** — valid signatures rejected as unauthorized | P7.3 |
| Over-counting across delegation | **critical** — threshold satisfied by one key counted twice | P7.4, distinct-entry rule |
| Partition ordering non-deterministic | **high** — intermittent unreproducible TX2 reverts | P7.10, canonical sort |
| Two govRoot moves instead of one | high | §5.3, single atomic upgrade |
| Corpus written from our own assumptions | **high** — a self-consistent wrong implementation passes its own tests | 7.2 traces must come from Kermit and be verdicted by `accumulate-core`, not by us |

---

## 9. Explicitly out of scope

- Signature types other than ED25519 and Delegated. RCD1, BTC, ETH, RSA,
  EcdsaSha256, TypedData must **fail closed with a distinct reason code**, not
  be silently skipped.
- Any in-circuit work. Phase 7 is the reference semantics a future Tier 4
  circuit would encode; see `certen-contracts/TIER4_DUE_DILIGENCE.md`.
- Contract changes. `CertenAccountV7` / `CertenAnchorV8_1` are untouched —
  governance still enters the chain via the BLS message.
