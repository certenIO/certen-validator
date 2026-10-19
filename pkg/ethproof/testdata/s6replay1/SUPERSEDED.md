# s6replay1 — superseded statements (RB10-F3)

The files of this set are published and pinned by `MANIFEST` (`10a36ab9dda73f8b81032c5b28c64bedea19746c729578aa489ddd6d5c3ed8ae`);
they are kept byte-identical and are never regenerated or edited. This file records which of their statements no
longer hold and where the statement that does is.

**What changed.** `CertenAccountV7_2`'s replay-guard layout is now pinned (pkg/ethproof `replayLayouts`): `_consumedLeaf`
`mapping(bytes32 => bool)` at slot **4**, settlement selectors **`0x57f8567d`** (executeGovernanceProofDirect) and
**`0xb7daa901`** (batchExecuteGovernanceProofDirect), from `forge inspect CertenAccountV7_2 storageLayout` at
certen-contracts `16c6d47` (the factory V10 deploy commit), checked on chain on Sepolia and Base Sepolia. A V7_2
settlement is proven with that layout; it is no longer `s6_replay_unproven{account_generation}`.

**Verdicts.** No verdict of this set changes: every vector and every mutation is still judged exactly as recorded
(`TestS6Replay1Vectors`). The superseded vectors below keep their recorded verdict, for a reason other than the one their
description gives; `TestS6Replay1Vectors` judges them only through its explicit superseded list, which asserts both the
recorded expectation and the verdict the current code gives.

| vector | superseded statement | still judged | why it is still that verdict | superseded by (s6replay2) |
|---|---|---|---|---|
| `029_generation_v7_2_unpinned` | description "CertenAccountV7_2 has no pinned layout" | `refused s6_replay_unproven{account_generation}` | the proof names `CertenAccountV7_2` but the transaction calls a V7_3 selector (`0x606f2c8d`): SPEC §4b step 3, calldata not a selector of the generation | `005_v7_2_proof_of_a_v7_3_call` (same verdict, true description); `001`–`004` prove V7_2 settlements |
| `047_state_unproven_account_generation` | description "a V7_2 settlement: no pinned layout" | `stated s6_replay_unproven{account_generation}` | a carried named state is held to the settlement only by tx/block (SPEC §4a); the capture no longer produces it for a V7_2 settlement | `001_v7_2_valid_execute`, `002_v7_2_valid_batch` (a V7_2 settlement is proven) |

**SPEC.md §4 constants.** "the only pinned generation is `CertenAccountV7_3`" is superseded by `../s6replay2/SPEC.md` §2
(the generation table). An implementation conformant to s6replay1 alone refuses a genuine V7_2 proof that Go proves; it
must also judge every vector of s6replay2 as stated.
