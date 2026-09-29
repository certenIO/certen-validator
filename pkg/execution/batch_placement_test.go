// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/database"
)

// RB3-F85: a member's proof artifact states its own place in its anchored batch - its leaf, index,
// path and the batch root - from its canonical row. It used to store the operation commitment as both
// leaf and root, index 0, no path, for every member.

func TestTheArtifactStatesTheMembersPlaceInItsBatch(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	repos := database.NewRepositories(database.NewClientFromDB(db))

	c, intentID := f73Cycle(t, nil, nil)
	t.Cleanup(func() { cleanupProofArtifacts(db, intentID) })

	// A three-member batch; this intent is member 1.
	leaf := func(b byte) [32]byte { return crypto.Keccak256Hash([]byte{b, 0xf8, 0x5}) }
	l0, l1, l2 := leaf(0), leaf(1), leaf(2)
	root := hashPair(hashPair(l1, l0), l2)
	nonce := strings.ReplaceAll(fmt.Sprintf("%032x", time.Now().UnixNano()), "-", "")
	rec := &database.AnchorQuorumRecord{
		ChainID: 84532, BundleID: "0x" + nonce + nonce, Root: root[:], BatchOperationID: testBatchOperationID("0x" + strings.Repeat("77", 32)),
		BatchOperationIDVersion: "v2",
		MessageHash:             "0x" + strings.Repeat("88", 32), AnchorCreateTx: "0x" + strings.Repeat("5a", 32), AnchorCreateBlock: 90,
		VerifyTx: "0x" + strings.Repeat("5b", 32), VerifyBlock: 100, VerifiedAt: time.Now().UTC(),
		AggregateSignature: []byte{1}, AggregatePubKey: []byte{2},
		Signers:           []database.AnchorQuorumSigner{{Address: "0xaaa", VotingPower: big.NewInt(100)}},
		SignedVotingPower: big.NewInt(500), TotalVotingPower: big.NewInt(700),
		Lane: "on_cadence", EvidenceSource: "live", TargetChain: "base-sepolia",
		Members: []database.AnchorQuorumMemberRecord{{
			IntentID: intentID, ADIURL: "acc://harbor.acme", OperationID: "0x" + strings.Repeat("77", 32),
			GovernanceCommitment: "0x" + hex.EncodeToString(testGov[:]),
			Leaf:                 l1[:], LeafIndex: 1,
			Branch: []database.MerklePathNode{{Hash: hex.EncodeToString(l0[:]), Position: "left"}, {Hash: hex.EncodeToString(l2[:]), Position: "right"}},
		}},
	}
	if _, err := repos.Batches.RecordAnchorQuorum(ctx, rec); err != nil {
		t.Fatal(err)
	}

	o := f73Orchestrator(db)
	if err := o.generateAndPersistBundle(ctx, c); err != nil {
		t.Fatal(err)
	}
	var gotRoot, gotLeaf []byte
	var gotIndex sql.NullInt64
	if err := db.QueryRow(`SELECT merkle_root, leaf_hash, leaf_index FROM proof_artifacts WHERE intent_id=$1`, intentID).
		Scan(&gotRoot, &gotLeaf, &gotIndex); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotRoot, root[:]) || !bytes.Equal(gotLeaf, l1[:]) || !gotIndex.Valid || gotIndex.Int64 != 1 {
		t.Fatalf("artifact states root %x… leaf %x… index %v; the member is leaf %x… at index 1 under root %x…",
			head(gotRoot), head(gotLeaf), gotIndex, l1[:4], root[:4])
	}

	// RB3-F135: the anchor columns state where the root was published - layer 5's create transaction and
	// block - and the settlement has its own; they used to hold the settlement under the anchor's name.
	createTx, settleTx := "0x"+strings.Repeat("5a", 32), c.SettlementTx
	var paAnchor, paSettle sql.NullString
	var paAnchorBlock, paSettleBlock sql.NullInt64
	if err := db.QueryRow(`SELECT anchor_tx_hash, anchor_block_number, settlement_tx_hash, settlement_block_number FROM proof_artifacts WHERE intent_id=$1`, intentID).
		Scan(&paAnchor, &paAnchorBlock, &paSettle, &paSettleBlock); err != nil {
		t.Fatal(err)
	}
	if paAnchor.String != createTx || paAnchorBlock.Int64 != 90 || paSettle.String != settleTx || paSettleBlock.Int64 != 100 {
		t.Fatalf("proof_artifacts anchor %v @ %v, settlement %v @ %v", paAnchor, paAnchorBlock, paSettle, paSettleBlock)
	}
	var refAnchor, refSettle string
	var refConfirmed bool
	if err := db.QueryRow(`SELECT ar.anchor_tx_hash, ar.settlement_tx_hash, ar.is_confirmed FROM anchor_references ar JOIN proof_artifacts pa ON pa.proof_id = ar.proof_id WHERE pa.intent_id=$1`, intentID).
		Scan(&refAnchor, &refSettle, &refConfirmed); err != nil {
		t.Fatal(err)
	}
	if refAnchor != createTx || refSettle != settleTx || !refConfirmed {
		t.Fatalf("anchor_references anchor %s settlement %s confirmed %v", refAnchor, refSettle, refConfirmed)
	}
	var attAnchor, attSettle sql.NullString
	if err := db.QueryRow(`SELECT va.anchor_tx_hash, va.settlement_tx_hash FROM validator_attestations va JOIN proof_artifacts pa ON pa.proof_id = va.proof_id WHERE pa.intent_id=$1`, intentID).
		Scan(&attAnchor, &attSettle); err != nil {
		t.Fatal(err)
	}
	if attAnchor.String != createTx || attSettle.String != settleTx {
		t.Fatalf("validator_attestations anchor %v settlement %v", attAnchor, attSettle)
	}
}

func TestAPlacementWhosePathMissesItsRootIsRefused(t *testing.T) {
	l0 := crypto.Keccak256Hash([]byte("a"))
	l1 := crypto.Keccak256Hash([]byte("b"))
	good := hashPair(l0, l1)
	ok := &database.Layer5Binding{LeafHash: l0[:], BatchRoot: good[:],
		MerklePath: []database.MerklePathNode{{Hash: hex.EncodeToString(l1[:]), Position: "right"}}}
	if err := checkBatchPlacement(ok); err != nil {
		t.Fatal(err)
	}
	bad := *ok
	bad.BatchRoot = l1[:]
	if err := checkBatchPlacement(&bad); err == nil {
		t.Fatal("a path that does not reach the root it names was accepted")
	}
	short := *ok
	short.MerklePath = nil
	if err := checkBatchPlacement(&short); err == nil {
		t.Fatal("a leaf with no path to a different root was accepted")
	}
}

func head(b []byte) []byte {
	if len(b) > 4 {
		return b[:4]
	}
	return b
}
