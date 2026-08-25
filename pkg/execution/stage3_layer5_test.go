// Copyright 2026 Certen Protocol
//
// Stage 3 Gates 3a-3d — the external anchor binding, checked rather than
// asserted.
//
// L5 claims: this proof's leaf is under a batch root, and that batch root was
// written to an external chain at a stated block. Only the FIRST HALF is
// verifiable offline, and only the first half is tested here. The step from
// batch root to external chain is coordinates plus an optional online check, and
// treating it as proved is the overclaim this stage must not make.
//
//	go test ./pkg/execution/ -run 'TestS3_' -count=1 -v
//
// The pure-Go gates run anywhere. The round trip needs CERTEN_TEST_DB with the
// live schema plus migration 016, and SKIPS without it — a skipped gate is not a
// green gate.
package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
	certenproof "github.com/certen/independant-validator/pkg/proof"
	"github.com/google/uuid"
)

// =============================================================================
// Harness
// =============================================================================

// s3Leaf builds a real batch-form leaf through the SAME function the validator and the
// account contract use, so the fixture is the document the chain would accept.
func s3Leaf(adi string, execByte, opByte byte) [32]byte {
	var exec, op [32]byte
	exec[0], op[0] = execByte, opByte
	return ComputeBatchLeaf(84532, BatchLeafInput{
		ADIURL: adi, ExecutionCommitment: exec, OperationID: op,
	})
}

func s3Hex(h [32]byte) string { return hex.EncodeToString(h[:]) }

// s3FourLeafBatch builds a REAL four-member batch through BuildBatchTree/MerkleBranch and
// returns the layer for leaf 0.
//
// Four members, not one: with a single leaf the root IS the leaf, so a gate built only on
// that shape passes even with the walk deleted. Four means the branch is actually walked —
// and walked with keccak256(sorted(a,b)), which is what the stored roots were built with.
// The earlier version of this fixture hand-rolled a sha256 tree and therefore tested a rule
// the system does not use.
func s3FourLeafBatch(t *testing.T) *Layer5 {
	t.Helper()
	leaves := [][32]byte{
		s3Leaf("acc://a.acme", 1, 1),
		s3Leaf("acc://b.acme", 2, 2),
		s3Leaf("acc://c.acme", 3, 3),
		s3Leaf("acc://d.acme", 4, 4),
	}
	root, err := MerkleRoot(leaves)
	if err != nil {
		t.Fatalf("MerkleRoot: %v", err)
	}
	branch, err := MerkleBranch(leaves, 0)
	if err != nil {
		t.Fatalf("MerkleBranch: %v", err)
	}
	if !VerifyBranch(branch, root, leaves[0]) {
		t.Fatal("fixture does not verify against the batch tree's own walk")
	}

	steps := make([]MerkleStep, 0, len(branch))
	for _, b := range branch {
		steps = append(steps, MerkleStep{Hash: s3Hex(b)})
	}
	return &Layer5{
		ChainID: 84532, Network: "base-sepolia",
		AnchorTx: "0xfeedface", BlockNumber: 45943270,
		BatchRoot: s3Hex(root), LeafHash: s3Hex(leaves[0]), LeafIndex: 0, Path: steps,
	}
}

// =============================================================================
// GATE 3a — leaf -> root recomputes, with the network disabled
// =============================================================================

func TestS3_Layer5VerifiesOffline(t *testing.T) {
	p6CutTheNetwork(t)

	l5 := s3FourLeafBatch(t)
	if err := l5.VerifyOffline(); err != nil {
		t.Fatalf("GATE 3a FAILED: a well-formed L5 does not verify offline: %v", err)
	}
	t.Logf("verified offline: %s", l5.ExternalClaim())

	// The claim must state its own boundary. An operator reading a passing L5
	// must not come away believing the Accumulate validator set was
	// independently established — nothing in this stage does that.
	claim := l5.ExternalClaim()
	for _, want := range []string{"COORDINATES", "NOT", "validator set"} {
		if !contains(claim, want) {
			t.Errorf("the L5 claim omits its own boundary (%q missing): %s", want, claim)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// =============================================================================
// GATE 3b — the single-leaf case, BOTH directions
// =============================================================================
//
// This is where a vacuous pass hides. An empty path is legitimate for a
// one-member batch — the Phase 6 e2e proof's stored path is exactly [] — and it
// is legitimate ONLY when the leaf IS the root. Accept it otherwise and every
// proof in the system verifies by carrying no evidence at all.
func TestS3_SingleLeafBothDirections(t *testing.T) {
	p6CutTheNetwork(t)

	leaf := s3Hex(s3Leaf("acc://solo.acme", 9, 9))

	// Direction 1: empty path, leaf == root. MUST PASS.
	ok := &Layer5{
		ChainID: 84532, Network: "base-sepolia",
		AnchorTx: "0xabc", BlockNumber: 1,
		BatchRoot: leaf, LeafHash: leaf,
	}
	if err := ok.VerifyOffline(); err != nil {
		t.Fatalf("a one-member batch (empty path, leaf == root) must verify: %v", err)
	}

	// Direction 2: empty path, leaf != root. MUST REJECT.
	bad := &Layer5{
		ChainID: 84532, Network: "base-sepolia",
		AnchorTx: "0xabc", BlockNumber: 1,
		BatchRoot: s3Hex(s3Leaf("acc://other.acme", 8, 8)), LeafHash: leaf,
	}
	if err := bad.VerifyOffline(); err == nil {
		t.Fatal("CRITICAL DEFECT: an empty merkle path was accepted with leafHash != batchRoot. " +
			"Every proof now 'verifies' by carrying no evidence.")
	} else {
		t.Logf("empty-path-with-mismatch rejected: %v", err)
	}
}

// =============================================================================
// GATE 3c — every mutation rejected
// =============================================================================

func TestS3_Layer5MutationsRejected(t *testing.T) {
	p6CutTheNetwork(t)

	otherPath := []MerkleStep{
		{Hash: s3Hex(s3Leaf("acc://x1.acme", 11, 11))},
		{Hash: s3Hex(s3Leaf("acc://x2.acme", 12, 12))},
	}

	cases := []struct {
		name   string
		mutate func(*Layer5)
		why    string
	}{
		{
			name:   "flip a path hash",
			mutate: func(l *Layer5) { l.Path[0].Hash = s3Hex(s3Leaf("acc://nope.acme", 7, 7)) },
			why:    "a sibling that was not the sibling cannot reach the root",
		},
		{
			name:   "drop a step",
			mutate: func(l *Layer5) { l.Path = l.Path[:1] },
			why:    "a short path lands on an intermediate node, not the root",
		},
		{
			name:   "empty the path entirely",
			mutate: func(l *Layer5) { l.Path = nil },
			why:    "THE VACUOUS PASS — an empty path is valid only when leaf == root",
		},
		{
			name:   "alter the batch root",
			mutate: func(l *Layer5) { l.BatchRoot = s3Hex(s3Leaf("acc://wrong.acme", 6, 6)) },
			why:    "the walk must reach the root the layer itself claims",
		},
		{
			name:   "alter the leaf",
			mutate: func(l *Layer5) { l.LeafHash = s3Hex(s3Leaf("acc://notme.acme", 5, 5)) },
			why:    "a different leaf under the same path reaches a different root",
		},
		{
			name:   "graft another proof's path",
			mutate: func(l *Layer5) { l.Path = otherPath },
			why:    "a whole well-formed path from elsewhere still does not reach THIS root",
		},
		{
			name:   "drop the external coordinates",
			mutate: func(l *Layer5) { l.AnchorTx = "" },
			why:    "a batch root nobody can point at a chain is not an anchor binding",
		},
		{
			name:   "block number zero",
			mutate: func(l *Layer5) { l.BlockNumber = 0 },
			why:    "coordinates that cannot be looked up are not actionable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l5 := s3FourLeafBatch(t)
			if err := l5.VerifyOffline(); err != nil {
				t.Fatalf("the unmutated layer does not verify, so this case is meaningless: %v", err)
			}
			tc.mutate(l5)
			if err := l5.VerifyOffline(); err == nil {
				t.Fatalf("CRITICAL DEFECT: mutation %q was ACCEPTED.\n  %s\n"+
					"The recomputation is not running.", tc.name, tc.why)
			} else {
				t.Logf("rejected: %v", err)
			}
		})
	}
}

// BuildLayer5 must refuse to store what VerifyOffline would refuse to read.
//
// The write path and the read path have to agree, and the cheapest guarantee is
// that the writer runs the reader's check. Without it a row lands in the
// database that looks like an anchor binding and fails later with a message that
// reads like tampering rather than like a plumbing bug.
func TestS3_BuildLayer5RefusesAnUnverifiableBinding(t *testing.T) {
	leaf := make([]byte, 32)
	leaf[0] = 1
	root := make([]byte, 32)
	root[0] = 2

	// No batch binding and leaf != root: there is no path, so this proof cannot
	// be shown to be under that root. It must be refused, not stored.
	_, err := BuildLayer5(nil, testObservation("0xabc", 42), leaf, root, 84532)
	if err == nil {
		t.Fatal("CRITICAL DEFECT: BuildLayer5 accepted a leaf that is not under the root it names, " +
			"with no path to bridge them")
	}
	t.Logf("refused: %v", err)

	// Same leaf and root: a legitimate one-member batch. Must build.
	l5, err := BuildLayer5(nil, testObservation("0xabc", 42), leaf, leaf, 84532)
	if err != nil {
		t.Fatalf("a one-member batch must build: %v", err)
	}
	if l5 == nil || len(l5.Path) != 0 {
		t.Fatalf("expected a one-member binding with an empty path, got %+v", l5)
	}

	// No external transaction: nothing to bind to, so nothing is written. Not an
	// error — an absent L5 is honest, a fabricated one is not.
	l5, err = BuildLayer5(nil, testObservation("", 0), leaf, leaf, 84532)
	if err != nil || l5 != nil {
		t.Fatalf("with no external coordinates BuildLayer5 must return (nil, nil), got (%v, %v)", l5, err)
	}
}

// =============================================================================
// GATE 3d — six layer rows per new proof: 1, 2, 3, 4-BVN, 4-DN, 5
// =============================================================================

func TestS3_SixLayerRowsPerProof(t *testing.T) {
	db := p6OpenDB(t)
	ctx := context.Background()
	p6CutTheNetwork(t)

	cp := p6LoadFixture(t, "proof_bvn1.json")
	proofID := p6Store(ctx, t, db, cp) // writes L1, L2, L3, L4-BVN, L4-DN

	// L5, through the shared writer, for a one-member batch.
	leaf := make([]byte, 32)
	leaf[0] = 7
	l5, err := BuildLayer5(nil, testObservation("0xfeedface", 45937480), leaf, leaf, 84532)
	if err != nil || l5 == nil {
		t.Fatalf("build layer 5: %v", err)
	}
	repo := database.NewProofArtifactRepository(db)
	if err := WriteLayer5Row(ctx, repo, proofID, l5, nil, t.Logf); err != nil {
		t.Fatalf("write layer 5: %v", err)
	}

	store := certenproof.NewPostgresProofStorage(db)
	rows, err := store.LayerRows(ctx, proofID)
	if err != nil {
		t.Fatalf("read layer rows: %v", err)
	}
	if len(rows) != 6 {
		names := make([]string, 0, len(rows))
		for _, r := range rows {
			names = append(names, r.LayerName)
		}
		t.Fatalf("GATE 3d FAILED: expected 6 layer rows (1, 2, 3, 4-BVN, 4-DN, 5), got %d: %v",
			len(rows), names)
	}

	// L1-L4 must still verify with L5 present. Adding a layer must not disturb
	// the ones under it — the reassembly reads by layer number and a new number
	// it does not recognise has to be ignored, not tripped over.
	if _, err := certenproof.VerifyStoredProof(ctx, store, proofID); err != nil {
		t.Fatalf("adding an L5 row broke L1-L4 verification from storage: %v", err)
	}

	// And L5 itself recomputes from storage.
	got, err := VerifyStoredLayer5(ctx, store, proofID)
	if err != nil {
		t.Fatalf("stored L5 does not verify: %v", err)
	}
	if got.AnchorTx != "0xfeedface" || got.BlockNumber != 45937480 {
		t.Errorf("stored L5 came back with different coordinates: %+v", got)
	}
	t.Logf("six rows, L1-L4 verified, L5 recomputed: %s", got.ExternalClaim())
}

// A proof with no L5 row must read as summary-only for L5 — not as a failure.
// Every proof written before Stage 3 is in this state.
func TestS3_MissingLayer5ReadsSummaryOnly(t *testing.T) {
	db := p6OpenDB(t)
	ctx := context.Background()
	p6CutTheNetwork(t)

	cp := p6LoadFixture(t, "proof_bvn1.json")
	proofID := p6Store(ctx, t, db, cp) // L1-L4 only

	store := certenproof.NewPostgresProofStorage(db)
	if _, err := certenproof.VerifyStoredProof(ctx, store, proofID); err != nil {
		t.Fatalf("L1-L4 must still verify: %v", err)
	}

	_, err := VerifyStoredLayer5(ctx, store, proofID)
	if err == nil {
		t.Fatal("CRITICAL DEFECT: a proof with no L5 row reported an anchor binding")
	}
	if !errors.Is(err, ErrNoLayer5) {
		t.Fatalf("expected ErrNoLayer5, got a different failure: %v", err)
	}
	t.Logf("L1-L4 verified, L5 absent — reported as summary-only, not failed: %v", err)
}

// The batch joins that were 0/418 and 0/67,847.
func TestS3_BatchJoinsArePopulated(t *testing.T) {
	db := p6OpenDB(t)
	ctx := context.Background()

	batchID := uuid.New()
	root := make([]byte, 32)
	root[0] = 9
	if _, err := db.ExecContext(ctx, `
		INSERT INTO anchor_batches (id, batch_type, status, tx_count, transaction_count, target_chain, merkle_root)
		VALUES ($1, 'on_demand', 'pending', 1, 1, 'base-sepolia', $2)`, batchID, root); err != nil {
		t.Fatalf("insert anchor_batches: %v", err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM anchor_batches WHERE id = $1`, batchID) })

	repo := database.NewProofArtifactRepository(db)

	// anchor_batches.anchor_tx_hash: written once.
	if err := repo.SetAnchorBatchTxHash(ctx, batchID, "0xdeadbeef", 45937480); err != nil {
		t.Fatalf("record anchor tx: %v", err)
	}
	var got string
	if err := db.QueryRow(`SELECT anchor_tx_hash FROM anchor_batches WHERE id = $1`, batchID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "0xdeadbeef" {
		t.Fatalf("anchor_tx_hash not recorded: %q", got)
	}

	// A second, different hash must NOT overwrite the first. A re-anchor and a
	// bug look identical once the original is gone.
	err := repo.SetAnchorBatchTxHash(ctx, batchID, "0xcafebabe", 1)
	if !errors.Is(err, database.ErrAnchorTxAlreadyRecorded) {
		t.Fatalf("expected ErrAnchorTxAlreadyRecorded on a second write, got %v", err)
	}
	if err := db.QueryRow(`SELECT anchor_tx_hash FROM anchor_batches WHERE id = $1`, batchID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "0xdeadbeef" {
		t.Fatalf("the first anchor tx was overwritten: %q", got)
	}
}

// testObservation builds the minimum ObservationResult BuildLayer5 reads.
func testObservation(txHash string, block uint64) *chain.ObservationResult {
	return &chain.ObservationResult{
		TxHash:         txHash,
		BlockNumber:    block,
		ChainName:      "base-sepolia",
		ChainIDNumeric: 84532,
		Status:         1,
		IsFinalized:    true,
	}
}

// Position is not a mutation, and that is a property worth pinning rather than an omission.
//
// The batch tree pairs with keccak256(sorted(a,b)), so a sibling's recorded side cannot
// change the computed root. An earlier version of this file mutated Position and expected a
// rejection — which only "passed" because the walk was sha256/positional, i.e. because it was
// verifying against a rule the system does not use.
func TestS3_PositionIsNotConsultedByTheWalk(t *testing.T) {
	l5 := s3FourLeafBatch(t)
	if err := l5.VerifyOffline(); err != nil {
		t.Fatalf("baseline must verify: %v", err)
	}
	for i := range l5.Path {
		l5.Path[i].Position = "left"
	}
	if err := l5.VerifyOffline(); err != nil {
		t.Fatalf("flipping Position changed the outcome, so something is consulting it: %v", err)
	}
	for i := range l5.Path {
		l5.Path[i].Position = "nonsense"
	}
	if err := l5.VerifyOffline(); err != nil {
		t.Fatalf("an unrecognised Position changed the outcome: %v", err)
	}
	t.Log("Position is inert, as sorted-pair hashing requires")
}

// The stored leaf must be the BATCH-FORM leaf, not the operationCommitment. This is the
// live defect from intent 50376476 in miniature.
func TestS3_BuildLayer5UsesTheBatchLeafNotTheOperationCommitment(t *testing.T) {
	leafArr := s3Leaf("acc://certen-demo.acme", 1, 1)
	root := leafArr // one-member batch: MerkleRoot returns the leaf itself

	opCommitment := make([]byte, 32)
	opCommitment[0] = 0x4b // stands in for 4b0149…, which is NOT the leaf

	binding := &database.Layer5Binding{
		BatchID:   uuid.New(),
		LeafHash:  leafArr[:],
		BatchRoot: root[:],
		TreeIndex: 0,
	}

	l5, err := BuildLayer5(binding, testObservation("0xabc", 42), opCommitment, opCommitment, 84532)
	if err != nil {
		t.Fatalf("BuildLayer5: %v", err)
	}
	if l5 == nil {
		t.Fatal("expected a binding from a valid batch row")
	}
	if l5.LeafHash != s3Hex(leafArr) {
		t.Fatalf("BuildLayer5 used %s, want the batch leaf %s — the operationCommitment is an "+
			"INPUT to the leaf, not the leaf", l5.LeafHash, s3Hex(leafArr))
	}
	if err := l5.VerifyOffline(); err != nil {
		t.Fatalf("the binding built from the batch leaf must verify: %v", err)
	}
}
