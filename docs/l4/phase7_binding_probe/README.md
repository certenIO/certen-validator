# Chain-height binding probe

Validates, against a live network, that a client can DERIVE the two state-hasher
components a `ValidatorSetProof` needs and have the derivation confirmed by the
receipt itself.

The state hasher is `[main, secondaryState, chains, pending]`, so a receipt from
element 0 has two steps: the sibling `secondaryState`, then the sibling
`H(chains || pending)`. Neither component is returned by the API. This shows
both are computable from what the API *does* return:

- `secondaryState` — 32 zero bytes for a plain data account
- `chains` — a merkle hash over each chain's DAG root, itself folded from the
  chain query's `state` (the merkle `State.Pending` list)
- `pending` — 32 zero bytes when the account has no pending transactions

Run it from inside the liteclient module, which has the `accumulate` dependency:

```sh
cd accumulate-lite-client-2/liteclient
cp -r ../../docs/l4/phase7_binding_probe ./p7
go run ./p7 kermit
rm -rf ./p7
```

Result on Kermit 2026-08-28: `CHAIN HEIGHTS BOUND: true` for both
`acc://dn.acme/network` and `acc://dn.acme/globals`.
