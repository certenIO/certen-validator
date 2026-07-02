# Certen Security — Proof‑Gated Calls

This folder tracks the security remediation of the proof‑gated contract‑call feature.

## Documents
- **[PROOF_GATED_CALLS_REMEDIATION.md](./PROOF_GATED_CALLS_REMEDIATION.md)** — the 13 confirmed
  bypass findings from the adversarial audit, each with a meticulous runbook (root cause + exact
  fix + tests + live verification), grouped into 4 workstreams and sequenced.

## Status
- Feature flag `CERTEN_ALLOW_CONTRACT_CALLS` = **ON** on the devnet fleet (pre‑real‑users; needed
  to test each fix live). **Hard gate before real users:** all 13 findings closed + re‑audited.
- Fixes: **not yet implemented** — spec first, then implement per the runbook sequence.

## Severity rollup (13 findings)
- **CRIT (7):** #1 quorum doesn't enforce effect · #2 on‑chain contract ignores executionCommitment ·
  #3 executed target/value decoupled from commitment · #4 empty commitment skips check but executes ·
  #5 non‑EVM chain name routes to EVM executor unbound · #7 VerifyAgainstResult early‑true on observed
  chain string.
- **HIGH (3):** #6 legacy orchestrator ungated · #8 nil inclusion proof fails open · #9 gate arms off
  an opt‑in flag.
- **MED (3):** #10 aggregator partial‑success on gate failure · #11 batch path no‑ops the gate ·
  #12/#13 fail‑open event matching + sig/power desync.

## Invariant (target end state)
Success is attested/written‑back only if the M‑of‑N Accumulate auth proved → the EXACT committed
`(chainId,target,value,calldata)` executed (bound in validator AND on‑chain) → status==1 →
finalized → inclusion re‑verified vs header roots → committed event/state proven → **≥2/3 quorum
independently re‑verified**. Every check fails closed. The BFT‑elected executor is assumed
potentially malicious.
