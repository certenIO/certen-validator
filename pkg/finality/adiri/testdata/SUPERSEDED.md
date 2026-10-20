# finality_adiri1 and finality_adiri2 are superseded by finality_adiri3 (RB11-F1, after the framework's certen-finality-states/2)

`finality_adiri1/` (49 vectors, MANIFEST sha256 `3b5a19ff89d8af62a88a829b4f81881835d25a4d5932902a3b614146ef9a7dae`) and
`finality_adiri2/` (10 vectors, MANIFEST sha256 `84f7d04d5846c2b7cd6f5db2050c510e9df4657f154725eea9b284f7fadf007a`) stay byte-identical: a
vector set is specification and is never re-baselined or edited. They were published before the framework (RB11-B2B1) typed every state
`reason` and changed how byte values render, so the current code cannot reproduce their `expect` strings. `finality_adiri3/` (59
vectors, the union of the two) re-issues every vector of both sets with the same name, leg, pins, group, note and evidence (the same
bytes) and changes ONLY the `expect`, for exactly two reasons:

1. Byte values (every `[32]byte` hash in a state or verdict field) render as `0x`-prefixed lower-case hex instead of bare hex
   (`pkg/finality/state.go` canonValue, `certen-finality-states/2`). Example: `"want_hash":"ab12…"` became `"want_hash":"0xab12…"`.
2. Four expectations carried a Go sentence as a `reason`; they now carry the registered token (`states.json`
   `finality_evidence_malformed.enums.reason`):

| vector | old reason | new reason |
|---|---|---|
| `syn-kind2-leg-is-seal` | `linkKind 2 is used only when the leg block is below the seal; the seal itself is a single-header spine` | `link_kind_2_at_seal` |
| `syn2-empty-spine` | `a spine holds at least the seal header` | `spine_empty` |
| `syn2-link-kind-3` | `linkKind is 1 (spine) or 2 (history slot)` | `link_kind_unknown` |
| `syn2-body-trailing-byte` | `trailing bytes` | `trailing_bytes` |

`TestAdiri3ReissuesTheSupersededSetsChangingOnlyTheirExpectations` proves this vector by vector (every superseded expectation, with its
64-hex strings prefixed by `0x` and the four sentences replaced, equals the finality_adiri3 expectation) and
`TestManifestHashesEveryVectorFile` proves that all three directories are unchanged. A TypeScript port consumes `finality_adiri3` only.
Vector counts: live 3, adversarial 33, synthetic 23 (the 13 of finality_adiri1 plus the 10 of finality_adiri2 that are not adversarial,
see `vectors.json` `group`).
