# CERTEN L4 — Design

**Status:** Draft for implementation
**Date:** 2026-08-24
**Scope:** Replace the CometBFT consensus bind with a stored, signature-verifying `Layer4`; correct G1 signature evidence; make G2 outcome binding real; close the G2 payload fail-open.

---

## 0. One-paragraph summary

CERTEN requires all of L1–L4 and G0–G2. Today L1–L3 are sound; G0–G2 are
consensus-engine-independent but carry three correctness defects (§1.2–§1.4). L4 is not a layer at all: it is two live RPC
assertions (`bindConsensusAppHash`) that store nothing, verify no signatures,
require a live CometBFT endpoint at verify time, and will stop compiling when
Accumulate removes CometBFT. This document replaces those two assertions with a
stored `Layer4` built on Accumulate's own threshold-signed partition anchors —
symmetric across the BVN and DN legs, offline-verifiable, and identical on
CometBFT and DAG-BFT networks. It also corrects the G1 signature-evidence path (a stub returning success with
zero signatures, plus a live path that silently drops signatures on transient
errors — the actual cause of every observed G2 failure), makes G2 outcome
binding a real receipt check rather than a non-empty string test, and closes a
dormant payload fail-open.

---

## 1. What is actually broken

### 1.1 L4 does not exist as evidence

`ChainedProof` (`working-proof_do_not_edit/types.go`) has three layers:

```go
type ChainedProof struct {
    Input  ProofInput
    Layer1 Layer1
    Layer2 Layer2
    Layer3 Layer3
    Artifacts map[string][]byte
}
```

There is no `Layer4`. What is called L4 is `bindConsensusAppHash`
(`proof_builder.go:104`), invoked twice:

| Call | Where | Binds |
|---|---|---|
| BVN | `proof_builder.go:77` | `CometBVN` at `BVNMinorBlockIndex+1` → `Layer2.BVNStateTreeAnchor` |
| DN  | `proof_builder.go:88` | `CometDN` at `DNMinorBlockIndex+1` → `Layer3.DNStateTreeAnchor` |

Four defects:

1. **Stores nothing.** Returns `error` or `nil`. The proof object a verifier
   receives carries zero L4 evidence.
2. **Verifies no signatures.** Reads `commit.SignedHeader.Header.AppHash` from a
   trusted RPC. `SignedHeader.Commit.Signatures` is present and ignored.
3. **Cannot verify offline.** `proof_verifier.go` hard-fails without live comet
   clients: `"proof-grade verification requires comet clients (BVN+DN)"`. This
   contradicts the governance spec §4: *"A governance proof MUST be verifiable
   offline."*
4. **Engine-coupled.** Imports `github.com/cometbft/cometbft/rpc/client/http`.
   Accumulate's `dagbft-integration` branch (558 commits ahead of `main`) has
   merged `issue-3910-remove-cometbft`. This code will not compile against it.

### 1.2 G2 has a latent fail-open (dormant in production — verified)

`g2_layer.go:122`:

```go
g2ProofComplete := g2Complete || (payloadConfigFailure && g2CoreComplete)
```

where `payloadConfigFailure` is a **string comparison on an error message**:

```go
payloadConfigFailure := !payloadVerification.Verified &&
    payloadVerification.GoVerifierErrors == "Go verifier path not configured"
```

**What payload verification actually is.** Not an optional extra: it is the
implementation of spec §2.2 (*"Expanded JSON Is Not Evidence"*). `VerifyPayloadWithRawJSON`
pipes the raw transaction JSON to the `txhash` tool, which recomputes the
canonical Accumulate transaction hash, and compares it to the receipt-proven
hash. Without it, expanded JSON is trusted — exactly what §2.2 forbids.

**Production status — VERIFIED, and the bypass is DORMANT:**

| Check | Result |
|---|---|
| `txhash` source | `cmd/txhash/main.go` present |
| `txhash` binary deployed | `/app/txhash`, 10,962,614 bytes, in every running validator |
| Binary functional | reads stdin, parses JSON, errors correctly on malformed input |
| Env configured | `TXHASH_CLI_PATH=/app/txhash` |
| Setter called | `main.go:1371` `cliGovProofGen.SetTxHashPath(txhashPath)` |
| Flag passed | `governance_adapter.go:228` `if level == G2 && txhashPath != ""` |

**Scope of the defect.** The bypass fires **only** on the exact string
`"Go verifier path not configured"`. Every other payload failure — hash
mismatch, exec error, malformed output — does not match `payloadConfigFailure`
and already fails closed, correctly. So this is not a live correctness hole; it
is a **config-regression trap**: if `TXHASH_CLI_PATH` is ever unset, the binary
goes missing, or a deploy regresses, G2 silently downgrades to a fake G2 with
only a `[WARNING]` log line.

**Blast radius if it ever fires.** `G2ProofComplete` flows into
`CanonicalHashGovernance("certen:g2:v1", …)` → `G2CanonicalHash` →
`ComputeAccumulateGovRoot`. A config-degraded G2 emits a **non-zero `g2Hash`
indistinguishable from a real one**, satisfying any downstream `g2Hash != 0`
gate — including the proposed `CertenAccountV8` value-operation check.

**Why removing the bypass does not break anything.** The verifier is configured
and the binary works. Deleting the escape hatch changes nothing on the current
fleet; it converts a future silent downgrade into an immediate, loud failure.

### 1.3 G1 signature evidence: a stub and a silent-drop path

**This — not anything in G2 — is what actually costs G2 proofs.** Of 399 proofs,
355 reach G2; 9 stop at G1 (2026-07-03 → 2026-08-09) and never run G2 at all.
Their `level_json` reads
`{"threshold_m":1,"threshold_n":1,"attestation_count":1,"threshold_met":false}`
— arithmetically satisfied, recorded as unmet. Expected 1, validated 0.

**Defect A — the stub.** `validateSignaturesDirectFromTransaction`
(`g1_layer.go:763`) returns `[]ValidatedSignature{}, nil`. A **nil error**, so
callers see success with zero signatures. Four swallowed paths reach it, all via
`g1_layer.go:187` discarding the extraction error:

- `ExtractSignatureSetUsingMessageID` → "failed to query transaction message" (timeouts land here)
- → "failed to pick signatureSet for key page"
- → "failed to extract signature message IDs"
- → success with `len(messageIDs) == 0`

**Defect B — the live path drops signatures silently.**
`validateSignaturesFromTransaction` (`:606`) is cryptographically correct — it
binds receipts via `BuildNormativeChainQuery`, validates timing against
`ExecTerms.MBI`, and runs full ed25519 + key-page membership. But **all eleven
failure branches are `continue`**. An RPC timeout and a signature belonging to a
different transaction are treated identically: dropped from the count. Under
load, N timeouts ⇒ N fewer signatures ⇒ threshold unmet ⇒ false governance
rejection. Fixing only the stub leaves this intact, in the path handling 100% of
traffic.

**Defect C — the enumeration subsystem is dead.** Zero callers:
`enumerateSignatureEntries` (:259), `filterAndValidateSignatures` (:312), and
transitively `signatureValidationWorker` (:393), `processSignatureEntry` (:431),
`resolveSignatureEntry` (:487). A complete receipt-bound worker pool,
unreachable. Consequently spec §4.1 Required Artifacts item 5 —
*"Enumeration of `P#signature` entries and single-entry resolution for each
counted candidate"* — is only **half-satisfied**: resolution happens,
enumeration never does.

**Not a block+1 anchor race.** The failure is at G1, before any outcome leaf is
required, and correlates with **load, not recency**: 8 of 9 in the single
highest-volume week (69 proofs vs a typical 13–32), zero in the two weeks since.

### 1.4 G2 outcome binding is checked with non-empty string tests

G2's defining claim over G1 is outcome binding (§1.3, §10). Two of the four
components deciding `g2ProofComplete` do not verify it:

```go
// verifyReceiptBinding (g2_layer.go:258)
verified := g1Result.G0ProofComplete &&
            g1Result.Receipt.Start != "" && g1Result.Receipt.Anchor != ""

// verifyWitnessConsistency (g2_layer.go:280)
verified := g1Result.G1ProofComplete && g1Result.ExecWitness != ""
```

Flags set by earlier stages plus non-empty strings. No merkle recomputation, and
`verifyReceiptBinding` inspects **G0's** receipt, never an outcome leaf.

`verifyTransactionEffect` (:243) is real — except when the §1.2 bypass fires,
because `go_verifier.go:60` sets `ComputedTxHash: expectedTxHash`, so it
compares a value to itself and passes.

**This raises the severity of §1.2.** `g2CoreComplete` — the guard permitting the
bypass — is `effect && receiptBinding && witnessConsistency`. When the bypass
fires all three pass trivially. It is not a safety net. §1.2 and §1.4 are one
correctness item.

## 2. What is already sound (do not touch)

| Component | Engine-independent? | Evidence |
|---|---|---|
| **G0–G2 engine-independence** | ✅ Yes | No `cometbft`/`tendermint` import in any file. Only `pkg/url` + `protocol` + raw v3 JSON-RPC. **Engine-independence only — see §1.3/§1.4 for correctness defects.** |
| **L1–L3** | ✅ Yes | Pure v3 receipts; `ReceiptVerifier.ValidateIntegrity` does offline SHA-256 merkle recomputation. |
| **Signature machinery** | ✅ Yes | `signature_verifier.go:45` `ComputeAccumulateDigest` + `:159` `VerifyEd25519` already implement Accumulate's exact preimage. |

The L4 replacement **reuses** the existing signature machinery. No new
cryptography is introduced.

---

## 3. Design

### 3.1 Principle

> Stop asking the consensus engine what happened. Read Accumulate's own signed
> record of it.

`PartitionAnchor` carries `StateTreeAnchor` — the same BPT root CometBFT reports
as `AppHash` — and partition anchors are **threshold-signed at the Accumulate
protocol layer**:

```go
// internal/core/execute/v2/block/msg_block_anchor.go:305
if uint64(len(sigs)) < ctx.Executor.globals.Active.ValidatorThreshold(partition) {
```

Signers resolve via `core.AnchorSigner(globals.Active, partition)` →
`NetworkDefinition.Validators` — chain state, not engine state. This lives in the
**executor**, not the consensus engine, and is present on both `main` (CometBFT)
and `dagbft-integration` (post-removal).

### 3.2 Both legs are kept

The BVN leg is **not** dropped and is **not** subsumed by L2/L3.

Rationale (corrects an earlier proposal to drop it):

1. **BVN is where the data lives.** The DN carries anchors and hashes only. The
   end-to-end bind — key → signature → transaction → BVN block → BVN state →
   DN → validator set — is severed at the data layer without the BVN leg.
2. **Validator distribution is a deployment parameter, not an architectural
   property.** A testnet BVN with one validator today may have a hundred
   tomorrow. Proof structure must not be shaped by current infrastructure depth.

Both legs use the *same* mechanism, symmetrically:

| Leg | Anchor type | Source | Lands in | Signed by | Threshold |
|---|---|---|---|---|---|
| **L4-BVN** | `blockValidatorAnchor` | `acc://bvn-BVNx.acme` | `acc://dn.acme/anchors` | BVN validators | `ValidatorThreshold(BVNx)` |
| **L4-DN** | `directoryAnchor` | `acc://dn.acme` | `acc://bvn-BVNx.acme/anchors` | DN validators | `ValidatorThreshold(Directory)` |

### 3.3 Types

```go
// Layer4 binds a partition's stateTreeAnchor to a threshold-signed validator
// quorum. One instance per leg (BVN and DN). Fully self-contained: verification
// requires no network access.
type Layer4 struct {
    Partition       string            `json:"partition"`        // "BVN1" | "Directory"
    AnchorTxID      string            `json:"anchorTxId"`       // acc://<hash>@<pool>
    AnchorTxHash    string            `json:"anchorTxHash"`     // hex32 — what signatures cover
    StateTreeAnchor string            `json:"stateTreeAnchor"`  // hex32 — MUST equal the layer it binds
    RootChainAnchor string            `json:"rootChainAnchor"`  // hex32
    MinorBlockIndex uint64            `json:"minorBlockIndex"`
    Signatures      []AnchorSignature `json:"signatures"`
    ValidatorSet    []ValidatorKey    `json:"validatorSet"`     // set as of this anchor
    Threshold       uint64            `json:"threshold"`        // required unique signers
    NetworkVersion  uint64            `json:"networkVersion"`   // NetworkDefinition.Version
}

type AnchorSignature struct {
    PublicKey     string `json:"publicKey"`     // hex, ed25519
    Signature     string `json:"signature"`     // hex, 64 bytes
    Signer        string `json:"signer"`        // acc://dn.acme/network
    Timestamp     uint64 `json:"timestamp"`
    SignerVersion uint64 `json:"signerVersion"` // 0 when NetworkDefinition.Version is unset
}

type ValidatorKey struct {
    PublicKey     string   `json:"publicKey"`
    PublicKeyHash string   `json:"publicKeyHash"` // sha256(publicKey)
    ActiveOn      []string `json:"activeOn"`      // partition IDs where active
}
```

`ChainedProof` gains:

```go
Layer4BVN Layer4 `json:"layer4Bvn"`
Layer4DN  Layer4 `json:"layer4Dn"`
```

### 3.4 Verification algorithm (offline, per leg)

```
for each signature s in Layer4.Signatures:
    md     = protocol.ED25519Signature{
                 PublicKey: s.PublicKey,
                 Signer: s.Signer,
                 SignerVersion: s.SignerVersion,
                 Timestamp: s.Timestamp,
             }.Metadata().Hash()
    digest = sha256(md || AnchorTxHash)
    require ed25519.Verify(s.PublicKey, digest, s.Signature)
    require sha256(s.PublicKey) ∈ {v.PublicKeyHash : v ∈ ValidatorSet,
                                   Partition ∈ v.ActiveOn}

require |unique verified signers| >= Threshold
require Layer4BVN.StateTreeAnchor == Layer2.BVNStateTreeAnchor
require Layer4DN.StateTreeAnchor  == Layer3.DNStateTreeAnchor
require Layer4.Threshold == ValidatorAcceptThreshold.Threshold(|active on Partition|)
```

No network access. Satisfies spec §4 offline verifiability for the first time.

### 3.5 G2 fix

Make it fail closed, per the spec's own §10 fallback:

```go
// BEFORE — fails open on a string comparison
g2ProofComplete := g2Complete || (payloadConfigFailure && g2CoreComplete)

// AFTER — no partial G2 exists; degrade to G1
g2ProofComplete := payloadVerification.Verified &&
                   effectVerification.Verified &&
                   receiptBinding.Verified &&
                   witnessConsistency.Verified
if !g2ProofComplete {
    return nil, ErrFallBackToG1{Reasons: failureReasons}   // caller records G1, g2Hash = 0
}
```

An unconfigured verifier is a **misconfiguration**, and must fail loudly at
startup rather than silently downgrade a claim at proof time.

---

## 4. Empirical basis

All verified live against `https://kermit.accumulatenetwork.io/v3` on 2026-08-24.

| Claim | Method | Result |
|---|---|---|
| Validator set + keys public | `network-status` | 3 validators, full `publicKey`, per-partition `active` |
| Threshold public | `globals.validatorAcceptThreshold` | 2/3 → `Directory` threshold = 2 |
| DN anchor + state root public | `query` chain `main` on `bvn-BVN1.acme/anchors` | `directoryAnchor`, `stateTreeAnchor=e59fe47d…7395`, block 7,671,708 |
| **Quorum signatures public** | `query {scope:<txid>}` → nested `signatures.records` | **3 of 3** ed25519 |
| Signature set matches network def | compare to `kermit-describe.txt` | exact 1:1 on all three keys |
| Receipts public | `ChainQuery` + `includeReceipt` | 26 entries, `start`→`anchor` |
| **Signature verifies** | `protocol.ED25519Signature.Metadata().Hash()` + `ed25519.Verify` | **`true`** |

Receipt gotcha: `includeReceipt` is **ignored on `range` queries** and honored on
`index` or `entry`. This fails silently. Pin it in a test.

---

## 5. Engine independence

| Layer | CometBFT | DAG-BFT | Why |
|---|---|---|---|
| G0–G2 | ✅ | ✅ | No engine dependency; v3 + `protocol` only |
| L1–L3 | ✅ | ✅ | v3 receipts only |
| L4 (current) | ⚠️ works, unsigned | ❌ **will not compile** | imports `cometbft/rpc/client/http` |
| L4 (proposed) | ✅ **verified live** | ✅ code-evidenced | anchors are executor-layer, not engine-layer |

**Honest limit:** the proposed L4 is *proven* on CometBFT (Kermit, executor
`v2-jiuquan`). Its DAG-BFT behaviour rests on code reading — `msg_block_anchor.go`
and `minor_root.go` are both intact on `dagbft-integration`. No public DAG-BFT
network exists to test against. Re-run the acceptance suite when one does.

---

## 6. Out of scope (tracked separately)

- **On-chain L4.** Requires ed25519-in-SNARK; gnark v0.14.0 has no Curve25519
  emulated params and no emulated twisted-Edwards package. Blocked on a BLS
  co-signature from Accumulate core (see `ACCUMULATE_ASKS.md`).
- **Historical validator-set reconstruction.** `network-status` returns the
  *current* set. `MinorRootRange` (#4058, `dagbft-integration`) provides set
  history but is in the `private` API namespace. Interim: walk
  `acc://dn.acme/network` update transactions.
- **CertenAccountV8 / CertenAnchorV9** leaf-level `govEvidenceRoot` binding.
