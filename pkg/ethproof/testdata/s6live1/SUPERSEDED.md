# s6live1 — superseded files (RB10-F9, RB10-F15)

The recorded worlds (`*.world.json.gz`) are the providers' answers and are never edited. The evidence and verdict
files beside a world are what an offline judge wrote from it; when that judge was defective, the file it wrote is kept
under a new name and a fresh one is written by the fixed judge (`go run ./cmd/s6livecapture -world <world>`).

| superseded file | what it said | why it was wrong | superseded by |
|---|---|---|---|
| `sepolia-07841e74bc47.verdict.1ms-judge.json` | `s6_replay_unproven{state_unavailable}` "the capture budget of 1ms ended" | RB10-F9: the RB10-B3 offline judge replayed the world with a 1 ms capture budget, and RB10-B4 bounds every RPC by the budget, so no provider was asked; the live capture proved After at 11950125 and Before | `sepolia-07841e74bc47.verdict.json` (proven at 11950125, before proven) |
| `sepolia-07841e74bc47.evidence.1ms-judge.json` | the named state above as the S6 evidence | RB10-F9, as above | `sepolia-07841e74bc47.evidence.json` |
| `arbitrum-sepolia-72ddae75e9b2.verdict.1ms-judge.json` | `s6_replay_unproven{state_unavailable}` "the capture budget of 1ms ended" | RB10-F9; the live capture proved After at 320818477 (N+3) and Before | `arbitrum-sepolia-72ddae75e9b2.verdict.json` (proven at 320818477, before proven) |
| `arbitrum-sepolia-72ddae75e9b2.evidence.1ms-judge.json` | the named state above as the S6 evidence | RB10-F9, as above | `arbitrum-sepolia-72ddae75e9b2.evidence.json` |
| `adiri-bdaee45e2c68.verdict.1ms-judge.json` | `s6_replay_unproven{state_unavailable}` "the capture budget of 1ms ended" | RB10-F9; the live capture proved After at 513643, Before `s6_before_unavailable` (RB10-F10) | `adiri-bdaee45e2c68.verdict.json` (proven at 513643, s6_before_unavailable) |
| `adiri-bdaee45e2c68.evidence.1ms-judge.json` | the named state above as the S6 evidence | RB10-F9, as above | `adiri-bdaee45e2c68.evidence.json` |
| `arbitrum-sepolia-b46171b58f49.evidence.pre-b4.json` | the S6 evidence in the RB10-B3 tool's snake_case encoding (`chain_id`, `settlement_block`, `proven_at`, `account_proof`, `parent_header_rlp`, ...) | V-R10B2 D4: the strict S6 decoder (RB10-B4) refuses it, `s6_replay_unproven{unknown_field}: $.proof.chain_id is no field of the format`; no test read the file | `arbitrum-sepolia-b46171b58f49.evidence.json`, written by the fixed judge (`go run ./cmd/s6livecapture -world <world>`); the world and the verdict file are unchanged |
| `base-sepolia-2e0518367a93.evidence.pre-b4.json` | the same pre-B4 encoding | V-R10B2 D4, as above | `base-sepolia-2e0518367a93.evidence.json` |
| `base-sepolia-c636e393188e.evidence.pre-b4.json` | the same pre-B4 encoding | V-R10B2 D4, as above | `base-sepolia-c636e393188e.evidence.json` |

`TestS6LiveWorldsReverifyOffline` (cmd/s6livecapture) requires, for every world, that the offline verdict equals the
verdict file and states exactly what the live capture recorded in its `live` field. The one pinned difference is
`arbitrum-sepolia-b46171b58f49`: captured by the RB10-B3 capture, which asked the parent's state once (RB10-F7), it
recorded `s6_before_unavailable` live; the world's later ask of the same block was served, and the fixed capture proves
the before-state from it. The test pins exactly that difference and requires a recorded provider answer that verifies.

`TestEveryLiveEvidenceFileDecodesAndVerifiesAgainstItsWorld` (cmd/s6livecapture) decodes every `*.evidence.json` here with
the strict S6 decoder and verifies it against the settlement its own world proves, to the verdict recorded beside it;
`TestTheSupersededLiveEvidenceFilesAreKeptAndListed` requires each `*.evidence.pre-b4.json` to be named in this file.
