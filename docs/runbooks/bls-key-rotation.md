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

The on-chain swap and the key switch must happen back to back. Between them the registry and the
validators' keys disagree, and no quorum forms.

Pause intent intake at the gateway for the duration. An on-demand intent that cannot reach quorum within
3 minutes is attested as failed.

### 1. Deploy this branch

### 2. Read the new public keys

The new key is the one each validator will derive from its own secret. Build the tool:

```
GOOS=linux GOARCH=amd64 go build -o bls-key-info ./cmd/bls-key-info
```

Copy it to the host. Then, for each validator N:

```
docker cp bls-key-info certen-validator-N:/tmp/bls-key-info
docker exec certen-validator-N /tmp/bls-key-info -derive validator-N
```

The tool prints only the public key. Private keys never leave the container, and nothing is written.

### 3. Compute the commitments

Build `new-pubkeys.json` from the 7 printed keys:

```
{"validators":[{"validator_id":"validator-1","bls_public_key":"0x…"}, …]}
```

Build `old-pubkeys.json` from the chain: `validators(addr).blsPublicKey` on each anchor.

Then run:

```
go run ./cmd/subsetcommit -keys new-pubkeys.json -json   # new29
go run ./cmd/subsetcommit -keys old-pubkeys.json -json   # old29
```

Both must report 29 subsets, no collisions, and "selfcheck: fold matches the production prover".

### 4. Swap on each anchor (owner key)

Run these on Sepolia `0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0`, Base Sepolia
`0xEA9eeeE42a7971792B11Fd2f682C9c1172490272` and Arbitrum Sepolia
`0x4b9eA187772E115641Fd40F35BF7a84925e7A035`:

1. `setAuthorizedPubkeyCommitments(new29, true)`. Authorize the new set first, so the authorized count
   never reaches zero while binding is enforced.
2. For each validator address, `removeValidator(addr)`, then `registerValidator(addr, 100, newPubkey)`.
3. `setAuthorizedPubkeyCommitments(old29, false)`.

Verify all four:
- `currentValidatorSetRoot()` still reads `a85a69…`.
- `validators(addr).blsPublicKey` equals the new key for all 7.
- `authorizedPubkeyCommitmentCount()` is 29.
- `pubkeyBindingEnforced()` is true.

Legacy anchors (for example Sepolia V6.1 `0x14885Fe8…`) register the same public-formula keys and have
no pubkey binding. Any account still pinned to one of them and holding value is exposed. Re-register the
new keys there too (step 4.2), or retire those accounts.

### 5. Switch the validators to the new keys

Move each old key file out of the way. The validator then derives the new key from its secret on start:

```
docker exec certen-validator-N mv /app/data/bls_key_validator-N.hex /app/data/bls_key_validator-N.public-formula-retired.hex
```

Restart all 7. Each logs `derived its key from its secret` and `BLS key initialized: <new key>`. Check it
against step 2.

### 6. Verify, then destroy

- Run one on-demand intent end to end. It must attest 5 or more of 7 and settle.
- Delete every `*.public-formula-retired.hex` and every `bls_keys_backup_MASTER.json`.
- The old keys also appear in git history (commit `cdbf40e`). After step 4 they sign nothing that any
  anchor accepts.

## After the rotation

A wiped data volume needs nothing: the validator re-derives the same key from its secret.

Changing a validator's `ETH_PRIVATE_KEY` does change its derived BLS key. When the EVM key must change
but the BLS key must not, either:
- keep the key file across the change, or
- set `BLS_KEY_SEED` to the old `ETH_PRIVATE_KEY` value first.
