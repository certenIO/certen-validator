# finality_arb_final4 - RB12-OPS-A1 vectors for arb-sepolia/finalized/v1: which L1 header the framework header reader judges

Supplements finality_arb_final1, finality_arb_final2, finality_arb_final3 and finality_arb_force1 (never edited; nothing in this set
supersedes a verdict of theirs). Same file layout, vector format and canonical verdict text as finality_arb_final1 (see its README); the
format tag is finality_arb_final4/1. The Go verifier is pkg/finality/arbfinal; the TypeScript verifier consumes a byte-identical copy of this
directory and must return the same canonical verdict bytes on every vector. MANIFEST.json lists vectors.json, evidence/ and pins/ (not this
README).

What it pins (BETA finding B-ARB-2). The light-client spine reader of the L1 head verifier reads four items of an L1 header: parent hash,
state root, number and timestamp. The framework's positional header reader (finality.ReadHeader) reads parent, state root, transactions root,
receipts root, number, timestamp and, from 17 items, the withdrawals root, and refuses a header whose items are not what it expects. The verifier
finds K (the L1 block that holds the confirmation transaction) with headerNumbered, which walks the spine in order, SKIPS a header the framework
reader cannot read and returns the one numbered K; the framework reader never judges another header. So, in a world whose spine the light-client
reader accepts:

- an odd header ANYWHERE BUT K - the finalized head, S (the block of the state proof), or any other spine header - does not stop the proof: the
  leg is finalized, whatever the odd header's transactions root, receipts root or withdrawals slot holds (five vectors);
- an odd header AT K is finality_block_not_covered{block_number: K, finalized_exec_number: F}: K cannot be read, so it is not found (three vectors).

The eight worlds: a 31-byte transactions-root item, a 33-byte receipts-root item and a list in the withdrawals slot, each at K and in the
headers other than K; and a 31-byte transactions-root item at S alone and at the finalized head alone.

Provenance. The worlds were built by a throwaway Go program (a six-line hook in synthworld.header that edits the items of an L1 header before it
is encoded; never committed) at pv2/rb11-e1-raise cbb6373 in the BETA session and carried by certen-sdk as the TS-held supplement arb_final_x. This
set is that supplement judged and written by this package: vectorgen -set4 <out> -from <dir> reads the worlds, judges EVERY vector with the
verifier of the checkout, refuses to write a vector whose expected literal differs from the verdict, and writes the layout and the manifest. Run
with -from on this directory it reproduces it byte for byte (gen4_test.go). The pins file of the worlds (pins/synth.json) is a full pins file that
carries the wallet pins. The verifier is unchanged by this set: it is test data only.
