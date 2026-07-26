# L3 Consensus-Proof API Requirements (for Accumulate core)

**Purpose:** complete **Layer 3** — prove that **≥2/3 of the validator set (by voting power)
actually signed** the DN block at height `H` whose `AppHash` equals the state-tree anchor that
L1–L2 bind the user's transaction to. This is the companion to
[`L4_VALIDATOR_API_REQUIREMENTS.md`](./L4_VALIDATOR_API_REQUIREMENTS.md); together the three
methods (`BlockHeaderQuery`, `ConsensusProofQuery`, plus L4's `ValidatorSetQuery` /
`ValidatorTransitionQuery`) form one package and should be implemented together.

**Today's gap:** the lite client's `bindConsensusAppHash` calls CometBFT `/commit` and only reads
`SignedHeader.Header.AppHash` to compare it to the proven state anchor. It does **not verify the
signatures**. So the chain currently trusts the RPC to have returned a real, validator-signed
header. L3 replaces that trust with an actual ≥2/3 ed25519 signature check.

---

## 0. Design principle: consensus proofs are SELF-authenticating

Unlike the L1/L2/L4 state proofs (which need Merkle receipts to an `app_hash`), an L3 consensus
proof needs **no Merkle receipt** — the **signatures themselves are the proof**. The cryptographic
closure the client performs is:

```
for each precommit signature in the Commit for H:
    reconstruct the canonical SignBytes (which commit to BlockID.Hash)
    verify ed25519(sig, SignBytes, validatorPubKey)      // pubkey from ValidatorSetQuery(H)
sum voting power of valid commit signatures  ≥  2/3 · totalVotingPower
AND  BlockID.Hash == recompute_header_hash(Header)        // ties the votes to THIS header
AND  Header.AppHash == <the DN state-tree anchor L1–L2 bound the tx to>
AND  Header.ValidatorsHash == ValidatorSetQuery(H).validatorsHash
```

Therefore the **single hardest requirement** is that the API return **exactly the fields needed to
reconstruct the canonical vote SignBytes byte-for-byte**, plus enough of the header to recompute the
header hash. If any field is missing or encoded differently than the signer used, every signature
fails. This is the #1 thing that breaks Tendermint light-client verification in practice.

### MUST be pinned and documented
1. **CometBFT/Tendermint version** and the exact `CanonicalVote` protobuf + length-prefix used for
   SignBytes (see §3). Vote-signing changed across versions (BFT Time, CometBFT v0.38 vote
   extensions); the client must reproduce the *exact* scheme this network uses.
2. **Header hash algorithm** — the field order + protobuf encoding + Merkle rule used to compute the
   Tendermint header hash (so the client recomputes `BlockID.Hash` and binds it to `AppHash`).
3. **Signature scheme** — ed25519 (confirm), and the validator **address derivation** from pubkey
   (so commit sigs, which reference validators by address, map to `ValidatorSetQuery` pubkeys).

---

## 1. `BlockHeaderQuery` — full canonical header at a height

Returns the complete CometBFT header for `H`, enough to (a) recompute the header hash and (b) read
the consensus-relevant fields.

### Request
```jsonc
{
  "partition": "Directory",   // required. DN is authoritative for the proof chain.
  "height": 4146078           // required. CometBFT block height (same domain as /commit and the L1–L2 anchor).
}
```

### Response
```jsonc
{
  "partition": "Directory",
  "height": 4146078,
  "headerHash": "….",          // = BlockID.Hash for H; client MUST be able to recompute this from the fields
  "header": {
    "version":  { "block": 11, "app": 2 },
    "chainId":  "….",          // REQUIRED — part of every vote's SignBytes
    "height":   4146078,
    "time":     "2026-06-01T10:04:48Z",
    "lastBlockId": { "hash": "….", "partSetHeader": { "total": 1, "hash": "…." } },
    "lastCommitHash":  "….",
    "dataHash":        "….",
    "validatorsHash":     "….", // == ValidatorSetQuery(H).validatorsHash
    "nextValidatorsHash": "….",
    "consensusHash":   "….",
    "appHash":         "95fdabd345b878d6...",  // == DN state-tree anchor bound by L1–L2
    "lastResultsHash": "….",
    "evidenceHash":    "….",
    "proposerAddress": "…."
  }
}
```

### Invariants the client checks
1. `recompute_header_hash(header)` == `headerHash`.
2. `header.appHash` == the DN state-tree anchor the user's L1–L2 proof resolved to.
3. `header.validatorsHash` == `ValidatorSetQuery(H).validatorsHash`.

### Notes
- This is the `Header` half of CometBFT `/commit?height=H`. If a trusted public CometBFT RPC already
  exposes `/commit`, this method can wrap/index it — but it MUST return the header in a form whose
  hash the client can recompute (don't return a pre-hashed/abridged header).

---

## 2. `ConsensusProofQuery` — the commit (signatures + canonical-vote params) for a height

Returns the set of precommits that finalized block `H` — i.e. the `.Commit` of `/commit?height=H`
(the precommits gathered in `H+1` that vote for `H`). This is the core of L3.

### Request
```jsonc
{
  "partition": "Directory",   // required
  "height": 4146078,          // required. The block being finalized (commit semantics = /commit?height=H).
  "includeHeader": true       // optional. If true, also embed the BlockHeaderQuery payload for H.
}
```

### Response
```jsonc
{
  "partition": "Directory",
  "height": 4146078,
  // --- shared canonical-vote params (same for every precommit in this commit) ---
  "chainId": "….",
  "round":   0,
  "blockId": {
    "hash": "….",                                  // == headerHash for H (the block voted for)
    "partSetHeader": { "total": 1, "hash": "…." }  // REQUIRED for SignBytes — cannot omit
  },
  "voteType": "precommit",                          // SignedMsgType = 2
  // --- per-validator commit signatures ---
  "signatures": [
    {
      "blockIdFlag": "commit",                      // commit | nil | absent
      "validatorAddress": "….",                     // maps to a pubkey in ValidatorSetQuery(H)
      "timestamp": "2026-06-01T10:04:49.123Z",      // REQUIRED per-sig — part of that vote's SignBytes
      "signature": "….(64-byte ed25519)…"
    }
    // ... one entry per validator slot, in validator-set order
  ],
  "totalVotingPower": 3,                             // convenience; client re-derives from ValidatorSetQuery
  "signedVotingPower": 3                             // convenience; client re-tallies the verified sigs
}
```

### Invariants the client checks (the actual L3 verification)
1. `blockId.hash` == `BlockHeaderQuery(H).headerHash` (votes are for THIS header).
2. For each `signatures[i]` with `blockIdFlag == "commit"`:
   - reconstruct `CanonicalVote{ voteType, height, round, blockId{hash, partSetHeader}, timestamp_i,
     chainId }`, marshal + length-prefix per §3, and `ed25519_verify(signature_i, SignBytes_i,
     pubKey_i)` where `pubKey_i` is the `validatorAddress`→pubkey from `ValidatorSetQuery(H)`.
3. Σ `votingPower` of validators with a *verified* `commit` signature ≥ ⅔ · `totalVotingPower`
   (powers from `ValidatorSetQuery(H)`, not from this response — trust the proven set, not the convenience field).
4. (For L4 skipping) the same `signatures` must be verifiable against an *arbitrary* trusted set:
   the client supplies its own set and checks the ≥⅓ overlap rule. So `validatorAddress` +
   `signature` + the shared params must be enough to verify against any set, not only `H`'s own.

### Errors
- `height` pruned → `ErrPruned` + earliest retained height.
- `height` beyond head / not yet committed → `ErrFutureHeight`.
- commit not yet available (H finalized but H+1 not produced) → `ErrCommitPending`.

---

## 3. Canonical SignBytes (the make-or-break detail)

The client reconstructs, per commit signature, the Tendermint `CanonicalVote` and verifies ed25519
over its length-prefixed protobuf encoding. The core dev must confirm this matches the network's
signer exactly:

```
CanonicalVote {
  Type      = SIGNED_MSG_TYPE_PRECOMMIT (2)        // sfixed-tagged per tendermint.types
  Height    = H                                    // sfixed64
  Round     = round                                // sfixed64
  BlockID   = CanonicalBlockID {
                Hash          = blockId.hash
                PartSetHeader = { Total = total, Hash = partSetHeader.hash }
              }
  Timestamp = signatures[i].timestamp              // per-validator
  ChainID   = chainId
}
SignBytes = uvarint(len(proto)) || proto_marshal(CanonicalVote)
verify: ed25519(signatures[i].signature, SignBytes, pubKey_i)
```

**Confirm explicitly:** (a) protobuf field order/tags (use the canonical `tendermint.types`
definitions for the pinned version); (b) the length-prefix is a protobuf uvarint; (c) per-validator
`Timestamp` is the value signed (vs a shared commit time) for this CometBFT version; (d) whether
vote **extensions** are in play (CometBFT ≥ v0.38) and, if so, that normal commit verification still
uses the non-extended canonical vote for the BlockID signature.

---

## 4. End-to-end L3 verification (how the pieces compose)

Given target height `H` and the DN state-tree anchor `A` that the user's L1–L2 proof resolved to:

1. `hdr = BlockHeaderQuery(H)` → check `recompute_header_hash(hdr) == hdr.headerHash` and
   `hdr.appHash == A`.
2. `set = ValidatorSetQuery(H)` (L4 doc) → check `set.validatorsHash == hdr.validatorsHash`.
3. `commit = ConsensusProofQuery(H)` → check `commit.blockId.hash == hdr.headerHash`.
4. For each `commit` precommit: reconstruct SignBytes (§3), ed25519-verify against `set` pubkeys.
5. Tally verified voting power ≥ ⅔ · `set.totalVotingPower`.

Result: the block carrying `AppHash == A` is proven to have been **signed into finality by ≥2/3 of
the validator set** — closing L3. L4 then proves that *set itself* chains back to a trusted
checkpoint; L1–L2 already proved the user's tx is in `A`. Full trustless chain.

---

## 5. Open questions for the core dev
1. **CometBFT version** running on DN/BVN, and the exact `CanonicalVote` encoding + length-prefix.
2. **Header hash** field order / encoding (so the client recomputes `BlockID.Hash`).
3. **Per-vote `Timestamp`** semantics for this version (signed per-validator vs shared).
4. **Vote extensions** (v0.38+): in use? If so, does it affect the BlockID-signature SignBytes?
5. **Validator address derivation** from ed25519 pubkey (so commit-sig addresses map to the set).
6. Is there already a **public CometBFT RPC** exposing `/commit` and `/validators`? If yes, these
   two methods can be thin, indexed, version-pinned wrappers; if not, they must be added natively to
   the v3 API. Either way the response shapes above are what the lite client consumes.
7. **Commit availability lag** — confirm `ConsensusProofQuery(H)` is answerable as soon as `H+1` is
   produced (since H's precommits live in H+1's `LastCommit`).
