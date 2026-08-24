# probe

Small operator tools used by the L4 work.

- `baseline/` — builds L1-L3 for a fixed set of live transactions and prints
  canonical JSON. Used to prove L1-L3 did not drift across the refactor.
- `dump/` — builds full L1-L4 proofs and writes them to a directory. Used to
  regenerate `proof/working-proof_do_not_edit/testdata/proof_*.json`, the
  fixtures the offline verification tests read.

Both talk to Kermit and are not part of the proof system itself.
