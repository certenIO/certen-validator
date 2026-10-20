# finality_e2e_pos1 - the Settlements of the published vectors' leg blocks (RB11-E2E-POS)

The published finality vector sets (`finality_base_posted1`, `finality_base_final1`, `finality_arb_posted1`, `finality_arb_final1`,
`finality_eth_sepolia1`) carry, for each case, the leg's block HEADER and the evidence about that block, never the Settlement (a
transaction and its receipt proven into the header's roots) that the database path needs: `finality.DeriveIncluded` verifies that
Settlement before an addendum is judged or stored, and D0 is derived from it.

Each file here is the `ethproof.Settlement` of the LAST transaction of the real leg block of one vector's valid case, read from
2-3 independent public providers that agree (`ethrpc.AgreeingReader`), with every transaction and receipt of the block checked against the
header's roots (`ethproof.ReadBlock`) and the proof verified before it was written. `cmd/finalitye2erecord` writes them; the file
names the providers, the capture time and the transaction index. The test (`cmd/proofverify/finality_e2e_pos_test.go`) hashes each file
against `MANIFEST.json` and refuses a Settlement whose block hash is not the vector's leg hash.

| file | vector | leg block |
|---|---|---|
| base_posted_a / base_posted_b | finality_base_posted1 valid_a / valid_b | Base Sepolia 48357661 / 48357729 |
| base_final_47604755 / base_final_47898494 | finality_base_final1 valid_leg_47604755 / valid_leg_47898494 | Base Sepolia 47604755 / 47898494 |
| arb_posted | finality_arb_posted1 valid_live | Arbitrum Sepolia 320996260 |
| arb_final_real | finality_arb_final1 real_valid (group `live`) | Arbitrum Sepolia 321003593 |
| eth_gloas_latest / eth_gloas_period / eth_legacy | finality_eth_sepolia1 valid_gloas_latest / valid_gloas_period / valid_legacy | Sepolia 11950125 / 11862203 / 11845679 |

Not bound, and why: the synthetic valid vectors of `finality_arb_final1` judge a synthetic L2 header (block 400000000) that no chain holds, so
no Settlement can exist for it; the Adiri control (`finality_adiri3`) is on a chain with a single public host, and the agreeing reader requires
two independent hosts (`ethrpc.MinAgreeingProviders`). Those are covered by their own vector tests and, for Adiri, by the replay test in
`pkg/finality/runtime`.

This is test data, not a golden: no hashed input of the finality chain or of any proof depends on it.

Regenerate (network, read-only): `go run ./cmd/finalitye2erecord -out cmd/proofverify/testdata/finality_e2e_pos1`
