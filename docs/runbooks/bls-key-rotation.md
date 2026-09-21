# BLS key rotation

## Why

Until this change, a validator with no BLS key file derived its key from public inputs:
`sha256(sha256("CERTEN_BLS_KEY_V1:<validator-id>:<chain-id>"))`. The validators saved those derived keys
to `data/bls_key_validator-N.hex`, and every live validator still loads them.

On 2026-09-21 validator-1's startup log showed public key `88eb4560b4147983…29c90a05`, which is exactly
the key the formula gives. All 7 registered keys on the Sepolia, Base Sepolia and Arbitrum Sepolia V8.1
anchors match the formula.

`executeComprehensiveProof` can be called by anyone, so anyone with the source and the Groth16 proving
key can sign a 7-of-7 quorum and attest any anchor.

The code change (this branch) removes the derivation:
- A validator loads its key file, or generates a **random** key when the file is missing.
- `bls-key-info` no longer derives keys.
- `subsetcommit` needs public keys only.
- `batchattest`, which signed with every validator's private key from one file, is deleted.

**The live keys stay compromised until the steps below are done.**

## What does not change

`currentValidatorSetRoot` is keccak over the registry's **sorted addresses, powers and threshold**, not
the BLS keys (CertenAnchorV8_1 `_recomputeValidatorSetRoot`). Re-registering each validator at the same
address and power leaves it at `a85a69…`, so no validator configuration changes.

## Steps

The on-chain swap and the key switch must happen back to back. Between them the registry and the
validators' keys disagree, and no quorum forms.

Pause intent intake at the gateway for the duration. An on-demand intent that cannot reach quorum within
3 minutes is attested as failed.

### 1. Deploy this branch first

Existing key files load unchanged, so this deploy changes no key.

### 2. Generate the new keys on the host

Build the tool:

```
GOOS=linux GOARCH=amd64 go build -o bls-key-info ./cmd/bls-key-info
```

Copy it to the host. Then, for each validator N, write a new key beside the current one inside that
validator's data volume. The tool never overwrites:

```
docker cp bls-key-info certen-validator-N:/tmp/bls-key-info
docker exec certen-validator-N /tmp/bls-key-info -generate /app/data/bls_key_validator-N.next.hex
```

Record the printed public key. Private keys never leave the container.

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

Legacy anchors (for example Sepolia V6.1 `0x14885Fe8…`) register the same derived keys and have no
pubkey binding. Any account still pinned to one of them and holding value is exposed. Re-register the
new keys there too (step 4.2), or retire those accounts.

### 5. Switch the validators to the new keys

For each N:

```
docker exec certen-validator-N sh -c 'mv /app/data/bls_key_validator-N.hex /app/data/bls_key_validator-N.derived-retired.hex && mv /app/data/bls_key_validator-N.next.hex /app/data/bls_key_validator-N.hex'
```

Then restart all 7. Each logs `BLS key initialized: <new key>`. Check it against step 2.

### 6. Verify, then destroy

- Run one on-demand intent end to end. It must attest 5 or more of 7 and settle.
- Delete every `bls_keys_backup_MASTER.json` and every `*.derived-retired.hex`.
- The old keys also appear in git history (commit `cdbf40e`). After step 4 they sign nothing that any
  anchor accepts.
