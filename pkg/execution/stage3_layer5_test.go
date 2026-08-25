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
	"crypto/sha256"
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

func s3Hash(b ...byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func s3HashPair(t *testing.T, left, right string) string {
	t.Helper()
	l, err := hex.DecodeString(left)
	if err != nil || len(l) != 32 {
		t.Fatalf("bad left %q", left)
	}
	r, err := hex.DecodeString(right)
	if err != nil || len(r) != 32 {
		t.Fatalf("bad right %q", right)
	}
	sum := sha256.Sum256(append(append([]byte{}, l...), r...))
	return hex.EncodeToString(sum[:])
}

// s3FourLeafBatch builds a real four-member batch and returns the layer for leaf
// 0, with a genuine two-step path.
//
// A batch of four rather than of one: the single-leaf case verifies whenever
// leaf == root, so a gate built only on it would pass with the walk deleted.
// Four members mean the path is actually walked.
//
//	       root
//	     /      \
//	  n01        n23
//	 /   \      /   \
//	L0    L1   L2    L3
//
// Leaf 0's path is [L1 (sibling right), n23 (sibling right)].
func s3FourLeafBatch(t *testing.T) (*certenproof.Layer5, []string) {
	t.Helper()
	l0 := s3Hash('l', '0')
	l1 := s3Hash('l', '1')
	l2 := s3Hash('l', '2')
	l3 := s3Hash('l', '3')

	n01 := s3HashPair(t, l0, l1)
	n23 := s3HashPair(t, l2, l3)
	root := s3HashPair(t, n01, n23)

	return &certenproof.Layer5{
		ChainID:     84532,
		Network:     "base-sepolia",
		AnchorTx:    "0xfeedface",
		BlockNumber: 45937480,
		BatchRoot:   root,
		LeafHash:    l0,
		LeafIndex:   0,
		Path: []certenproof.MerkleStep{
			{Hash: l1, Position: "right"},
			{Hash: n23, Position: "right"},
		},
	}, []string{l0, l1, l2, l3}
}

// =============================================================================
// GATE 3a — leaf -> root recomputes, with the network disabled
// =============================================================================

func TestS3_Layer5VerifiesOffline(t *testing.T) {
	p6CutTheNetwork(t)

	l5, _ := s3FourLeafBatch(t)
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

	leaf := s3Hash('s', 'o', 'l', 'o')

	// Direction 1: empty path, leaf == root. MUST PASS.
	ok := &certenproof.Layer5{
		ChainID: 84532, Network: "base-sepolia",
		AnchorTx: "0xabc", BlockNumber: 1,
		BatchRoot: leaf, LeafHash: leaf,
	}
	if err := ok.VerifyOffline(); err != nil {
		t.Fatalf("a one-member batch (empty path, leaf == root) must verify: %v", err)
	}

	// Direction 2: empty path, leaf != root. MUST REJECT.
	bad := &certenproof.Layer5{
		ChainID: 84532, Network: "base-sepolia",
		AnchorTx: "0xabc", BlockNumber: 1,
		BatchRoot: s3Hash('o', 't', 'h', 'e', 'r'), LeafHash: leaf,
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

	otherPath := []certenproof.MerkleStep{
		{Hash: s3Hash('x', '1'), Position: "right"},
		{Hash: s3Hash('x', '2'), Position: "right"},
	}

	cases := []struct {
		name   string
		mutate func(*certenproof.Layer5)
		why    string
	}{
		{
			name:   "flip a path hash",
			mutate: func(l *certenproof.Layer5) { l.Path[0].Hash = s3Hash('n', 'o', 'p', 'e') },
			why:    "a sibling that was not the sibling cannot reach the root",
		},
		{
			name:   "flip a position",
			mutate: func(l *certenproof.Layer5) { l.Path[0].Position = "left" },
			why:    "hashing the pair in the other order yields a different node",
		},
		{
			name:   "drop a step",
			mutate: func(l *certenproof.Layer5) { l.Path = l.Path[:1] },
			why:    "a short path lands on an intermediate node, not the root",
		},
		{
			name:   "empty the path entirely",
			mutate: func(l *certenproof.Layer5) { l.Path = nil },
			why:    "THE VACUOUS PASS — an empty path is valid only when leaf == root",
		},
		{
			name:   "alter the batch root",
			mutate: func(l *certenproof.Layer5) { l.BatchRoot = s3Hash('w', 'r', 'o', 'n', 'g') },
			why:    "the walk must reach the root the layer itself claims",
		},
		{
			name:   "alter the leaf",
			mutate: func(l *certenproof.Layer5) { l.LeafHash = s3Hash('n', 'o', 't', 'm', 'e') },
			why:    "a different leaf under the same path reaches a different root",
		},
		{
			name:   "graft another proof's path",
			mutate: func(l *certenproof.Layer5) { l.Path = otherPath },
			why:    "a whole well-formed path from elsewhere still does not reach THIS root",
		},
		{
			name:   "an unrecognised position",
			mutate: func(l *certenproof.Layer5) { l.Path[0].Position = "middle" },
			why:    "an unknown side must be refused, not silently treated as one of the two",
		},
		{
			name:   "drop the external coordinates",
			mutate: func(l *certenproof.Layer5) { l.AnchorTx = "" },
			why:    "a batch root nobody can point at a chain is not an anchor binding",
		},
		{
			name:   "block number zero",
			mutate: func(l *certenproof.Layer5) { l.BlockNumber = 0 },
			why:    "coordinates that cannot be looked up are not actionable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l5, _ := s3FourLeafBatch(t)
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
	got, err := certenproof.VerifyStoredLayer5(ctx, store, proofID)
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

	_, err := certenproof.VerifyStoredLayer5(ctx, store, proofID)
	if err == nil {
		t.Fatal("CRITICAL DEFECT: a proof with no L5 row reported an anchor binding")
	}
	if !errors.Is(err, certenproof.ErrNoLayer5) {
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
