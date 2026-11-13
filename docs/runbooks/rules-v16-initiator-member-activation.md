# Execution rules v16: the initiating-signature member of evidence 2.1 (DAX-1G, G-83)

**Status:** built; every rule below is pinned by a test (named in each section). Not deployed. Deploying v16 needs **no new key and no
new environment variable on the validators**. The deploy and the activation are two separate acts, exactly as for v15: the deploy is the
owner running one command on all seven validators; the activation is an admin-signing queue item (threshold of the admin set in force)
that is signed only after every verifier that must read the member has shipped (see "Order of the whole change").

## Why

Decision 0042 of the transaction-controls lab: a transaction is initiated by a separate, non-voting `*-erp` identity (a key page of an
identity that is no authority of the principal), and the approving authority then votes. Evidence 2.1 declared that page's
`initiator-signer` role but carried no signature that proves it, so `intentcert.BindProofV21` refused the declaration and the proposers
held such intents with `g1_initiator_signature_not_carried` (`docs/proof/G1_CROSS_PARTITION.md`, the initiator-signer role and D8).

Evidence 2.1 now has one more member, `initiatingSignature` (`proofv2.Evidence.InitiatingSignature`, a `VoteHop`: the signature, its
message hash, the page it is recorded on, its receipt in that page's signature chain, the arrival proof and the block). The verifier
proves it completely or refuses the document by name (`pkg/proof/v2/xroles.go carriedInitiatorPages`; the nine steps and their refusal
names are listed in its comment), and the role becomes **proven**, not declared.

That member is a **consensus-visible change**. A rules v15 binary decodes it as an unknown JSON key, ignores it, leaves the role
declared and refuses the certificate; a v16 binary reads it and accepts what v15 refuses. By `execution_rules.go` ("WHEN TO BUMP") and
`PROOF_V2.md` section 10.4 that is a rules version, and one that switches at a **committed fact**, never at a deploy, or a staggered
deploy decides one block two ways and forks the chain.

## What the chain enforces

| Rule | Code | Why |
|---|---|---|
| `certen.g1.crosspartition.activate/v1` accepts **version 2** beside version 1 (any other version is refused by `CheckShape`, also at `CheckTx`, code 18) | 19 when a version-2 activation is refused (v15 refused it with 18, so the two are told apart by their code); 18 for version 1 | One transaction kind, one admin-signed tool; the version names which gate it opens. |
| Version 2 is accepted **only after version 1**, and **once**; version 1 is still refused once any activation exists | 19 (version 2), 18 (version 1) | The member rides evidence 2.1; neither activation can be replayed, moved or undone. |
| Authorised by at least the threshold of distinct keys of the admin set in force for the block (`AdminSetAt`), over the kind, the chain id and the version, length-prefixed | 19 (version 2), 18 (version 1) | The same authority as v15's activation; an approval of version 1 cannot be moved to version 2 (the version is signed). |
| Recorded append-only at its height H (`/certen/g1_activation` now lists up to two records), id folded into the app hash | - | A block is judged identically however often it is executed. |
| Blocks at height > H **read** the member (`G1ActivationAt(...).MemberInForce`, `G1InitiatorMemberInForce(log, h)`: a version-2 record below h) | 10 (certificate refused) when the member does not prove | After H the document is judged with the member: the role it proves is accepted, a forged or unprovable one is refused by name. |
| Blocks at height <= H are judged with the member **cleared** (`judgeProofV2`, `withoutInitiatingSignature`): the v16 binary decides them exactly as v15 did | 10 | Before H nothing changes, so v16 continues v15 history without a reset, and a v15 node and a v16 node never disagree before H. |
| The proposer attaches the member only from the same height (`Shadow.SetInitiatorMemberGate`, wired in `main.go` to `ValidatorApp.G1InitiatorMemberInForce`); an unset gate, a "no" and an error all attach nothing | - | Before H the document is built exactly as v15's proposers build it; the intent is held with `g1_initiator_signature_not_carried`, as today. |

Tests: `TestVersionTwoActivationNeedsVersionOneAndIsAcceptedOnce`, `TestInitiatorMemberIsInForceOnlyAboveItsBlock`,
`TestTheMemberActivationIsRecordedAndStampsRulesV16`, `TestEvidenceIsJudgedWithoutTheMemberUntilItsActivation`,
`TestCheckTxFiltersTheVersionTwoActivationShape`, `TestCommittedVersionTwoActivationHistoryIsChecked`,
`TestV16ContinuesV7ToV15StateAndNothingElse` and the in-process four-node rehearsal `TestRulesV15UpgradeAndG1ActivationRehearsalOnALiveNetwork`, which now also drives
the version-2 activation through the tool (consensus); the proposer gate tests in `pkg/proofv2shadow`.

## Until the activation: the v16 binary is v15

- every block is decided exactly as v15 decided it: the member is cleared from every evidence 2.1 document before it is judged;
- proposers attach no member, so **no intent changes state** by the deploy (an intent with a non-voting initiator is held as it is today);
- the persisted state stays stamped v15 until a block decides a version-2 activation, **accepted or refused** (`committedRulesVersion`,
  `rulesV16FirstVerdict`): v15 refused every version but 1 with code 18, and v16 may accept one, so the first version-2 verdict is a v16
  verdict.

## The boot history check

`IndexCommittedHistory` re-checks the whole committed history once under the history-check version this binary names. For v16 it adds:
a **committed version-2 activation that v15 refused (code 18) is a violation** (v16 might decide the same bytes the other way), v16's own
refusal of one (code 19) is not, and an accepted one without its record is divergent state. A v15 node's `CheckTx` refuses version 2 by shape, so such a transaction can only be
in a block if a proposer bypassed the mempool; run the check before the deploy (below), it must find nothing.

## Order of the whole change (verifiers first)

1. **Merge** after the validator team's sign-off and the lead's QA.
2. **Verifiers first, all of them, before a member-bearing certificate can exist:** the SDK `@certen.io/proof-verify` release with the
   twin change and the new suite's fixtures (`pkg/proof/v2/testdata/xpartition7`); `chain-check`'s pin bump; then the validators' binary.
3. **Deploy v16 on all seven validators together** (below). Behaviour is identical to v15 until step 5.
4. **Wait** until the fleet reports app version 16 everywhere and the history check is clean.
5. **Commit the version-2 activation** (below). It is an admin-sign queue item of its own.
6. **Producers:** from H+1 the collector's member is attached; new intents gain it. Intents captured by an older build carry no
   transaction or history for the page and stay held until re-captured.

## Deploy (all 7 together)

Apply every env change before any rebuild (none are needed for v16).

1. **Gate:** the v15 activation is committed and the fleet is v15: `validator-rotate g1-activate status --rpc http://<v1>:26657,...`
   shows `activated at height H1` for version 1 on all seven; `abci_info` reports `"app_version":"15"` on all seven.
2. **History check before the deploy**, against one v15 validator that holds every block from 1:

   ```
   validator-rotate history-check --rules 16 --rpc http://<validator>:26657
   ```

   It must exit 0 and end with `v16 continues this chain's history exactly`. A version-2 activation found in the history is FOUND.
3. **Stop every validator, install the v16 binary, start every validator.** Each node, before CometBFT's handshake, continues the older
   state (`compatibleContinuations`: v7..v15 continue as v16) and re-checks its history. Then verify on every node:

   ```
   curl -s http://<validator-N>:26657/abci_info                              # "app_version":"16" on all 7
   validator-rotate g1-activate status --rpc http://v1:26657,...,http://v7:26657
   ```

   `status` must print the version-1 activation, `initiating-signature member NOT yet activated` and no `DISAGREE`. Mixed versions are
   not a state to stay in: the member preflight is NO-GO unless all seven report v16.

## Commit the activation

On the admin machine, secrets read from files and never printed:

```
validator-rotate g1-activate propose --rpc http://v1:26657 --version 2 \
  --admin-key-id admin-a --admin-secret @<admin-a seed file> --out g1-member.json
validator-rotate g1-activate sign --tx g1-member.json --admin-key-id admin-b --admin-secret @<admin-b seed file>
validator-rotate g1-activate preflight --tx g1-member.json --rpc http://v1:26657,...,http://v7:26657
validator-rotate g1-activate submit    --tx g1-member.json --rpc http://v1:26657,...,http://v7:26657
```

`propose` refuses by itself when the node records no version 1, already records version 2, or runs rules older than v16. Preflight is GO
only if every node runs rules v16 (all the same, on this chain, caught up), reports the same admin set and **records version 1 and no
version 2**, requires proof v3, and the chain's own rule (`VerifyG1Activation`) accepts the transaction for the next block. Submit prints
`ACCEPTED at height H ... The initiating-signature member is read from height H+1`. **Record H.**

Two handling rules, as for v15: sign only at activation time (a signed, unsubmitted activation has no height and no nonce: it is a bearer
instrument until the admin set rotates), and keep the validator RPC firewalled until it is committed (a shape-valid version-2 transaction
refused with code 19 **counts as a v16 verdict and stamps the state v16**, which closes the v15 rollback; preflight first).

## Verify, after the activation

- `g1-activate status --rpc <all 7>` shows both records, `initiating-signature member accepted at height H ... read from height H+1`, no
  `DISAGREE`; `abci_info` still reports 16; the persisted stamp is v16 from the first version-2 verdict.
- `history-check --rules 16` exits 0 and finds the activation in its record.
- The first natural intent after H whose initiator is a separate non-voting identity settles: its stored proof is evidence 2.1 with an
  `initiatingSignature` member, lists the initiator page's `initiator-signer` role as proven, and verifies offline with `proofverify`.
  A `[INTENT-CERT] REJECTED` for a certificate whose proof carries the member at height <= H means a proposer built it early (an old build).
- Restart the whole fleet: one chain, equal app hashes, every node answering `/certen/g1_activation` with the same two records.

## Rollback

- **Before the first version-2 verdict** (state stamped v15): stop all seven, install the v15 binary, start all seven. v15 never saw a
  member and ignores the v16 watermark keys, which v15 never writes or deletes.
- **After it** (state stamped v16): **there is no rollback.** The v15 binary refuses to start (`execution rules mismatch ... NEWER v16`),
  and no transaction can move or undo the activation. A chain that accepted a member cannot go back to refusing it without invalidating
  the intents it certified. Roll forward only.

## What is not proven by this change (carried to the pull request)

- `execution.CheckIntentCertificate` (the offline check) cannot know the height: it reads the member always. A certificate that carries a
  member and was accepted by consensus below H was judged with the member cleared; the collector never emits one before H, so this
  exists only for a crafted certificate.
- A **delegated** non-voting initiator: the delegators of the signature's path are proven pages and get the role, but the delegation
  entries themselves are not re-evaluated by this member (the initiator authorises nothing; OQ-DAX1G-5, a separate package).
- A **lite-identity** initiator carries no certified history, so its member is not emitted (the intent stays held, `g1_history_unavailable`).
- The in-process four-node rehearsal covers the v14 to v16 upgrade, the version-1 activation and the version-2 activation through the tool (every node records
  both at one height, state stamped v16, the member read only from the next height, a repeat refused by name, `history-check --rules 16`, a whole-fleet
  restart). Its blocks are uncertified (no BLS registry), so the certificate rule itself is pinned by the `ValidatorApp`-level tests; a rehearsal on a
  throwaway network with real intents is an owner-run step before the activation.

## Related

- Design: `docs/proof/G1_CROSS_PARTITION.md` (D8 is this member); `docs/proof/PROOF_V2.md` sections 5 and 10.4.
- The pattern this copies: `docs/runbooks/rules-v15-g1-cross-partition-activation.md`.
- The admin quorum and the history-check watermark: `docs/runbooks/admin-set-rotation.md`.
