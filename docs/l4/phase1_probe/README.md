# Phase 1 probes

Two programs behind §9 Phase 1 of `VALIDATOR_TRUST_ROOT_RUNBOOK.md`. Both are
read-only research. **`accumulate-core` is never modified.**

## `main.go` — is the validator set provable offline today? (Q13)

Queries `acc://dn.acme/network` with `includeReceipt`, re-derives the BPT leaf
from the returned account state, validates the merkle path, and parses the
`NetworkDefinition` out of the state.

It needs the `accumulate` dependency, so run it from inside the liteclient
module:

```sh
cd accumulate-lite-client-2/liteclient
cp -r ../../docs/l4/phase1_probe ./phase1_probe
go run ./phase1_probe kermit      # or: mainnet
rm -rf ./phase1_probe
```

## `q9_genesis_index_test.go` — is the missing hash→index map guaranteed? (Q9)

Builds a genesis from scratch in the simulator and asks whether the genesis
chain entry resolves by hash. Run it against a *copy* of `origin/main`, so the
real repo is untouched:

```sh
SP=<scratchpad>
mkdir -p "$SP/core-main"
git -C /c/Accumulate_Stuff/accumulate-core archive origin/main | tar -x -C "$SP/core-main"
mkdir -p "$SP/core-main/q9probe"
cp docs/l4/phase1_probe/q9_genesis_index_test.go "$SP/core-main/q9probe/"
cd "$SP/core-main" && GOWORK=off go test ./q9probe/ -run TestQ9 -v
```

`GOWORK=off` is required — an unrelated `go.work` in the user's home directory
otherwise breaks the build.
