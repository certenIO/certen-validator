# Phase 4 probe — how much does a ValidatorSetProof cost?

Backs §9 Phase 4 of `VALIDATOR_TRUST_ROOT_RUNBOOK.md`. Builds the proposed
`ValidatorSetProof` as real JSON from live data and measures it against a real
stored proof, so the "how the artifact grows" answer is a measurement rather
than an estimate.

Needs the `accumulate` dependency, so run it from inside the liteclient module:

```sh
cd accumulate-lite-client-2/liteclient
cp -r ../../docs/l4/phase4_probe ./vsp_probe
go run ./vsp_probe kermit
go run ./vsp_probe mainnet
rm -rf ./vsp_probe
```
