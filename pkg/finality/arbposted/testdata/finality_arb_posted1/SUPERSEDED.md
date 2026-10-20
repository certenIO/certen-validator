# finality_arb_posted1 - superseded expectations

The files of this set are unchanged. Two expectations describe a verifier that treated the zero-heavy flag 0x20 as an unknown
header; Nitro (nitro@ccc5c82 arbstate/inbox.go, Stage 2) decodes that layer once and then reads the result as an ordinary payload, and
the verifier now does the same (RB11-E2B). The two cases carry bytes that are not a zero-heavy payload (a Brotli stream behind the flag),
which decode to garbage whose first byte is 77, not the Brotli header byte:

| case | recorded expectation | verdict now |
|---|---|---|
| adv_synth_calldata_flag_zeroheavy | `l1_batch_header_unknown{batch:77, byte:32}` | `l1_batch_header_unknown{batch:77, byte:77}` |
| adv_synth_blob_payload_zeroheavy | `l1_batch_header_unknown{batch:77, byte:32}` | `l1_batch_header_unknown{batch:77, byte:77}` |

finality_arb_posted2 holds proper zero-heavy payloads (a valid one, and the decode edge cases). A consumer of this set judges these two
cases by the "verdict now" column.
