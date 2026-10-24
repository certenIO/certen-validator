# world - the honest synthetic world H0 and its mutation engine (S8 contract identity)

`world` builds, deterministically (fixed seed, no clock, no network, sorted maps), everything a verifier reads for one leg: real go-ethereum state and
storage tries, real RLP headers linked by hash, the transactions and receipts of the attestation block and the settlement block, the CIE1 container
(`contractidentity.Encode`) and the `LegContext`. It produces INPUTS only; whether H0 is `verified` is the Verify packages' business.

## Build H0

```go
m, _ := contractidentity.Embedded()                       // the profile (addresses, windows, tx types, pins) comes from the manifest
spec, _ := world.Generate(m, 11155111, world.VariantH0)   // the explicit description = the content of world.json
w, _ := world.Derive(m, spec)                             // w.Ctx, w.ContainerBytes, w.Container, w.StateRoots, w.BlockHashes
// w.PlanErr == nil && w.CheckErr == nil for H0: the container carries exactly the nodes the read plan visits (step 22b)
```

Chains: 11155111, 84532, 421614 (EIP-2935 window 393168, 133-byte ArbOS history code pin), 2017. Variants (the named base worlds of Item 5):
`h0` (S6 proven, Registry9 present, link 2: a spine of three headers), `s6silent` (the same world, `S6Status = s6_silent`), `hops` (link 1: two hop
headers across gaps W, W/2 and 7). A vector's `base` is always `H0`; it selects another profile with its FIRST mutations
`{"op":"set_field","target":"world","path":"chain","value":84532}` and `path":"variant","value":"hops"` (regenerates the world, later mutations apply on top).

## Mutations (the CLOSED vocabulary of `FORMAT.md`; nothing else is accepted)

| kind | ops | effect |
|---|---|---|
| semantic | `set_field` / `unset_field` on target `world` | edit world.json by dot path; Derive re-derives every storage root, account leaf, state root, header hash, parent link, proof, node list and container |
| raw | `set_byte` `replace_hex` `truncate` `append_hex` | edit the derived container bytes; nothing is re-derived |
| raw | `drop_node` `add_node` `reorder` | structured container edits (`reorder` re-encodes without validation) |
| raw | `set_field` / `unset_field` on `container` | edit the structured container JSON (hex bytes, decimal-string integers), re-encoded WITHOUT validation |
| raw | `set_field` / `unset_field` on `context` | one `LegContext` member: `adi_url s6_status s6_reason s6_state batch.* s6.* registry9.*`; `settlement tx receipt s7` can only be unset |
| raw | `set_field` / `unset_field` on `manifest`, `extension` | edit the manifest document (its pin is recomputed) / the extension document |

World paths: `stations.<station>.accounts.<0xaddr>.{nonce,balance,code,storage.<slot>}` with station `settle attest_pre attest_post hop.<i>`;
`blocks.<attest_parent|attest|settle|between.<i>>.{number,fields.<f>,txs}` (`fields` OVERRIDES a derived header field and is not re-derived:
parentHash stateRoot transactionsRoot receiptsRoot logsBloom timestamp gasLimit gasUsed coinbase extraData baseFee); `attestation.*` (the
executeComprehensiveProof call: blob words, powers, level, logs), `settlement.*` (legs, book, page, leaf, logs), `context.*`, `roles.*`, `carry`
(the addresses whose code the container carries). A hop station lists only OVERRIDES; the EIP-2935 ring slot is computed unless stated (a zero value
deletes it). An unknown member is an error, never ignored. Go one-liners: `SetStorage SetNonce SetBalance SetCode SetHeaderField SwapAccount Set Unset`.

## A vector in five lines

```go
A := addr(spec.Roles.Anchor)                                              // binding disabled at BOTH attest stations
muts := []contractidentity.Mutation{world.SetStorage(world.StationPre, A, contractidentity.SlotIndex(6), common.Hash{}),
    world.SetStorage(world.StationPost, A, contractidentity.SlotIndex(6), common.Hash{})}
file, _ := world.VectorFile("VS8-090.binding_off", muts, contractidentity.Expected{Headline: "refused"}) // <id>.json
// world.WriteSet(dir, spec, vectors) writes world.json, the vector files and MANIFEST (never into an existing set)
in, _ := world.Builder{}.Build(worldJSON, vector, containerFile)          // the WorldBuilder of contractidentity.RunSet
```

## Real code

`testdata/code/*.template.hex` are the live runtime bytes of the pinned builds with the immutable ranges zeroed (their keccak256 is the manifest
`maskedKeccak`, tested); `Fill` writes the chain id, the verifier link, the entry point, the account owner and book hash into a copy. README there
lists sources and sha256. The creation code of the account build is the CREATE2 input of step 8 (tested against the manifest `create2` rows).

## Add a chain profile

Add the chain to the manifest (`chains`, `deployments`, `accounts`, `policy.owner`, `eip2935`, `policy.txScan`): `Generate` reads nothing else. A new
generated-verifier build needs its template file. The attestation block carries one transaction of each `txScan` covered and system type, the
attestation and one more type-2 transaction; the settlement block two fillers and the settlement.

## Limits (stated, not hidden)

The S7 report is CONSTRUCTED (included and finalized verified at the settlement block), not produced by S7. Block `logsBloom` is the OR of the receipts'.
The owner EOA cannot sign (its key is not ours): "the owner sent a transaction" is expressed by its nonce. Receipts of L2 system types are plain typed
receipts. H0's settlement is a single-leg call (`settlement.batch` and `legs` express a batch calldata; its logs are the author's). Per-vector materialised inputs for the TS port are the
verify packages' job (this package builds them from world.json + the mutations).
