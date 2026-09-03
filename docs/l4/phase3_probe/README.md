# Phase 3 probe — Q10, the path that had never run

Backs §9 Phase 3 of `VALIDATOR_TRUST_ROOT_RUNBOOK.md`. The validator set has
never changed on mainnet or Kermit, so every claim about the update timeline was
untested. This changes it for real on `origin/main`'s executor and then asks the
question the whole design rests on: **after the set changes, can the previous
set still be proven?**

Read-only with respect to the repo. **`accumulate-core` is never modified** —
run against a `git archive` copy:

```sh
SP=<scratchpad>
mkdir -p "$SP/core-main"
git -C /c/Accumulate_Stuff/accumulate-core archive origin/main | tar -x -C "$SP/core-main"
mkdir -p "$SP/core-main/q10probe"
cp docs/l4/phase3_probe/q10_test.go "$SP/core-main/q10probe/"
cd "$SP/core-main" && GOWORK=off go test ./q10probe/ -run TestQ10 -v
```

`GOWORK=off` is required — an unrelated `go.work` in the user's home directory
otherwise breaks the build.

Two notes on how the change is made, both deliberate:

- The new validator is added **inactive on the Directory**. That still mutates
  the recorded `NetworkDefinition` — which is what L4 carries and what
  `isActiveOn` filters — without altering consensus membership. Adding it
  *active* also works and the update executes, but the simulator then panics
  with `block did not complete`, because the new key has no node behind it.
  That panic is itself evidence the change took effect.
- The network is `SimpleNetwork(name, 1, 3)` so the operator page threshold is
  one signature. On a 3x3 network the same transaction stays **pending** rather
  than failing — a reminder that a validator-set change is a governance action
  needing a real operator quorum.
