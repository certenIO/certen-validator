# finality_ethl1_v1 is superseded by finality_ethl1_v2

Superseded on 2026-10-20 by RB11-C1B. This set is frozen: no file of it changes (its manifest and `MANIFEST.sha256` still verify; this note is the only
addition and is not part of the manifest). It is kept because published evidence and the Go test `TestHeadVectors` still run it.

Why: v1 recognised the electra (Electra and Fulu) layout only by minimum size and first offset and refused it by name as
`finality_fork_unsupported{layout:"electra"}`. The verifier now implements that layout, so the one v1 case that recorded the stand-in
(`electra_link_real_fulu_update`) now yields `finality_link_invalid{check:"period_skip"}` (the real Fulu update is judged); the Go test pins the new verdict in
`supersededV1Verdicts`. v2 also corrects V-C1A review gaps (vectors for the next-committee mismatch, the signature-period rules with the next committee
known, a rotated ledger period, a non-participating invalid key, a final update with finalized slot 0) and adds the real Fulu objects, the mixed-fork chain
and the legacy-leg final update with its 4,057-header spine. The TypeScript port is written against v2, not v1.
