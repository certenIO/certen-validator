# Phase 2 probes — Q4 and Q5 sizing

Backs §9 Phase 2 of `VALIDATOR_TRUST_ROOT_RUNBOOK.md`. Every number in that
section comes from these tests. They build **real** `private.MajorHeaderRecord`
values using the `dagbft-integration` types, populated from **live Kermit data**
(a real major-block `IndexEntry`, a real `DirectoryAnchor` in a real
`SequencedMessage`, real validator quorum signatures), then marshal and measure.

Read-only: HTTP GETs plus in-memory marshalling. **`accumulate-core` is never
modified** — run against a `git archive` copy.

```sh
SP=<scratchpad>
mkdir -p "$SP/core-dag"
git -C /c/Accumulate_Stuff/accumulate-core archive origin/dagbft-integration | tar -x -C "$SP/core-dag"
mkdir -p "$SP/core-dag/q5probe"
cp docs/l4/phase2_probe/*.go "$SP/core-dag/q5probe/"
cd "$SP/core-dag" && GOWORK=off go test ./q5probe/ -v
```

`GOWORK=off` is required — an unrelated `go.work` in the user's home directory
otherwise breaks the build.

| Test | Answers |
|---|---|
| `TestQ5_MajorHeaderRecordSize` | one spine record, and the whole spine, from real data |
| `TestQ5b_AnchorSizeDistribution` | how much the anchor body varies, and cost vs validator count |
| `TestQ4_PointQueryArtifactSize` | the CERTEN-shaped "validator set at block N" artifact |
