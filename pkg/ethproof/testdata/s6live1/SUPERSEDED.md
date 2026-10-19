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

`TestS6LiveWorldsReverifyOffline` (cmd/s6livecapture) requires, for every world, that the offline verdict equals the
verdict file and states exactly what the live capture recorded in its `live` field. The one pinned difference is
`arbitrum-sepolia-b46171b58f49`: captured by the RB10-B3 capture, which asked the parent's state once (RB10-F7), it
recorded `s6_before_unavailable` live; the world's later ask of the same block was served, and the fixed capture proves
the before-state from it. The test pins exactly that difference and requires a recorded provider answer that verifies.
