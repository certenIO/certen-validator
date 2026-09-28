# BLS key rotation

## Why

A validator with no BLS key file derived its key from the validator ID and chain ID:
`sha256(sha256("CERTEN_BLS_KEY_V1:<validator-id>:<chain-id>"))`. That made the key re-derivable after a
data wipe, which is the point, but those inputs are public, so anyone could compute every validator's
private key.

On 2026-09-21 validator-1's startup log showed public key `88eb4560b4147983…29c90a05`, which is exactly
the key the formula gives. All 7 registered keys on the Sepolia, Base Sepolia and Arbitrum Sepolia V8.1
anchors match the formula. `executeComprehensiveProof` can be called by anyone, so anyone with the
source and the Groth16 proving key can sign a 7-of-7 quorum and attest any anchor.

This branch keeps the re-derivation and makes the input secret:
- A key file that exists is loaded unchanged.
- A missing key file (a new validator, or a wiped data volume) is **derived from the validator's
  secret**: HMAC-SHA256 keyed by `BLS_KEY_SEED` when set, otherwise by the validator's
  `ETH_PRIVATE_KEY`, over `certen:bls-key:v2:<validator-id>`.
- Both secrets live in the validator's environment, not its data volume, so a wipe re-derives the same,
  still-registered key and nothing is re-registered.
- With no secret the validator refuses to start. There is no fallback to anything computable.

Deploying this branch changes no key: every validator has a key file today and loads it. **The live
keys stay compromised until the one-time rotation below is done.** After it, wipes are harmless again.

## What does not change

`currentValidatorSetRoot` is keccak over the registry's **sorted addresses, powers and threshold**, not
the BLS keys (CertenAnchorV8_1 `_recomputeValidatorSetRoot`). Re-registering each validator at the same
address and power leaves it at `a85a69…`, so no validator configuration changes.

## One-time rotation

Done on 2026-09-26 on all three anchors (the executed plan, its rehearsal and rollback:
`runbooks/2026-09-proof-integrity/rb3-rotation/WINDOW_PLAN.md`). This section is the order to use for any
future rotation. Two facts decide it:

- The anchor never reads `validators(addr).blsPublicKey`: acceptance depends only on the authorized pubkey
  commitments. The validators' batch path DOES read it - every batch takes each signer's key from the
  registry, and a node finds its own identity by matching its key against it. So between re-registering and
  the validators' switch the batch path is down, and nothing may be in flight.
- The old commitments must stay authorized until the new keys are proven end to end. Revoking them earlier
  leaves no quorum any proof can satisfy and no way back.

### 0. Ownership

If the anchors' owner key has ever been exposed, move ownership first (anchor, verifier, factory), or anyone
holding the old owner key can undo the rotation.

### 1. Read the new public keys

Each validator derives its new key from `BLS_KEY_SEED` (set per validator on the host, never printed). Build the
tool, and on the host, for each validator N, derive the public key in a subshell that sources that validator's
env file, so the secret is never on a command line:

```
GOOS=linux GOARCH=amd64 go build -o bls-key-info ./cmd/bls-key-info
( set -a; . <env file of validator-N>; set +a; ./bls-key-info -derive validator-N )
```

Collect the 7 public keys into `new-pubkeys.json` (`{"validators":[{"validator_id":"validator-1","bls_public_key":"0x…"}, …]}`).

### 2. Compute the commitments

```
go run ./cmd/subsetcommit -keys new-pubkeys.json -json   # new29
go run ./cmd/subsetcommit -keys old-pubkeys.json -json   # old29 (old keys read from the chain)
```

Both must report 29 subsets, no collisions, and "selfcheck: fold matches the production prover".

### 3. Authorize the new commitments (harmless, can be done a day early)

On each anchor: `setAuthorizedPubkeyCommitments(new29, true)`. The old keys keep working.

### 4. The window

1. **Pause intake on all 7 validators** and wait until nothing is in flight:

   ```
   docker exec certen-validator-N touch /app/data/intake.paused
   # each validator's /health: "discovery": "paused", then wait for "discovery_intents_in_progress": 0
   ```

   While the file exists a validator queues and starts no intent (intents written directly to Accumulate
   included - the pause is at discovery, not at the gateway); intents already running finish; nothing is
   lost, discovery resumes at the first block it had not processed. The path is `INTENT_INTAKE_PAUSE_FILE`
   (default `data/intake.paused`).
2. **Re-register** on each anchor: for each validator address `removeValidator(addr)` then
   `registerValidator(addr, 100, newPubkey)`. Verify: `currentValidatorSetRoot()` unchanged,
   `validators(addr).blsPublicKey` equals the new key for all 7, `pubkeyBindingEnforced()` true.
3. **Switch all 7 validators together** (a mixed fleet's aggregate matches no commitment): in each container move
   the old key file aside, `mv /app/data/bls_key_validator-N.hex /app/data/bls_key_validator-N.retired.hex`, then
   recreate all 7 so the new `BLS_KEY_SEED` is loaded. Each logs `derived its key from its secret … (public key X)`
   with X from step 1, and `Attesting as … matched on-chain BLS registry`.
4. **Prove the new keys**: `batchpreflight -pubkeys new-pubkeys.json` passes on every anchor; lift the pause
   (`docker exec certen-validator-N rm /app/data/intake.paused` on all 7); one on-demand intent per chain settles
   (status 1) and its stored proof verifies offline.
5. **Only then revoke**: `setAuthorizedPubkeyCommitments(old29, false)` on each anchor, then `subsetaudit`.

### Rollback

- Before step 4.3: re-register the old keys (they were never revoked).
- After 4.3, before 4.5: in each container move the derived key aside and the retired one back, recreate all 7,
  re-register the old keys.
- After 4.5 there is no rollback by design; 4.4 proves the new keys first.

### Afterwards

Delete every `*.retired.hex` and any key backup file. Keys that ever appeared in git history sign nothing any
anchor accepts once revoked.

## After the rotation

A wiped data volume needs nothing: the validator re-derives the same key from its secret.

Changing a validator's `ETH_PRIVATE_KEY` does change its derived BLS key. When the EVM key must change
but the BLS key must not, either:
- keep the key file across the change, or
- set `BLS_KEY_SEED` to the old `ETH_PRIVATE_KEY` value first.
