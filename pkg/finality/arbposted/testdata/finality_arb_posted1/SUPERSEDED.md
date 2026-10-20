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

## Second supersession (RB11-E2-FIX, review V-E2-A1): Kind.Verify binds the BlockRef

The files of this set are still unchanged. `Kind.Verify` now refuses a BlockRef whose hash or number is not the container header's, or
whose own `header_rlp` does not hash to / carry them (`finality_block_mismatch`, as arbfinal and baseposted). Seven cases give the
verifier a SYNTHETIC leg (the live block's header with its `transactionsRoot` replaced for the case's transaction list, hence another
hash) next to the RECORDED container, whose header still carries the live block's hash 0x83d81943...ca0c9f4. They were written for the
match logic and relied on the absence of the binding; they now stop at the binding:

| case | recorded expectation | verdict now |
|---|---|---|
| adv_tx_altered | `l1_posted_content_not_found{reason:no_matching_message}` | `finality_block_mismatch{field:blockHash, want:<the case leg's hash>, got:0x83d81943...ca0c9f4}` |
| adv_tx_order_swapped | `l1_posted_content_not_found{reason:no_matching_message}` | the same code, `want` = the case leg's hash |
| adv_tx_missing | `l1_posted_content_not_found{reason:no_matching_message}` | the same code, `want` = the case leg's hash |
| adv_tx_extra | `l1_posted_content_not_found{reason:no_matching_message}` | the same code, `want` = the case leg's hash |
| adv_no_standard_transactions | `l1_posted_content_not_found{reason:no_standard_transactions}` | the same code, `want` = the case leg's hash |
| adv_unsupported_tx_type | `l1_posted_content_not_found{reason:unsupported_tx_type}` | the same code, `want` = the case leg's hash |
| adv_delayed_origin_without_proof | `l1_posted_delayed_origin_unproven` | the same code, `want` = the case leg's hash |

`want` is the case's own `leg.hash` in each file. finality_arb_posted4 carries the seven cases again as `<id>_container_bound`: the same
evidence with ONLY the container header's block hash replaced by the case leg's hash, under the recorded expectation (the match logic they
test is unchanged). A consumer of this set judges the seven cases by the "verdict now" column.
