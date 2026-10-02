// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

// RB3-F76: a proof's details state what the independent checkers were held to - the verified quorum of
// the anchor its member settled under - so no reader has to take the key page's M-of-N for it.
func TestProofDetailsStateTheCheckersQuorum(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	repos := database.NewRepositories(database.NewClientFromDB(db))

	c, intentID := f73Cycle(t, nil, nil)
	t.Cleanup(func() { cleanupProofArtifacts(db, intentID) })
	leaf := crypto.Keccak256Hash([]byte("f76"))
	nonce := fmt.Sprintf("%032x", time.Now().UnixNano())
	verifyTx := "0x" + strings.Repeat("7b", 32)
	if _, err := repos.Batches.RecordAnchorQuorum(ctx, &database.AnchorQuorumRecord{
		AnchorVersion: "v8_1", BatchLeafCount: 1,
		ChainID: 84532, BundleID: "0x" + nonce + nonce, Root: leaf[:], BatchOperationID: testBatchOperationID("0x" + strings.Repeat("77", 32)),
		BatchOperationIDVersion: "v2",
		MessageHash:             "0x" + strings.Repeat("88", 32), AnchorCreateTx: "0x" + strings.Repeat("7a", 32), AnchorCreateBlock: 99,
		VerifyTx: verifyTx, VerifyBlock: 100, VerifiedAt: time.Now().UTC(),
		AggregateSignature: []byte{1}, AggregatePubKey: []byte{2},
		Signers: []database.AnchorQuorumSigner{
			{Address: "0xaaa", VotingPower: big.NewInt(100)}, {Address: "0xbbb", VotingPower: big.NewInt(100)},
			{Address: "0xccc", VotingPower: big.NewInt(100)}, {Address: "0xddd", VotingPower: big.NewInt(100)},
			{Address: "0xeee", VotingPower: big.NewInt(100)},
		},
		SignedVotingPower: big.NewInt(500), TotalVotingPower: big.NewInt(700),
		Lane: "on_cadence", EvidenceSource: "live", TargetChain: "base-sepolia",
		Members: []database.AnchorQuorumMemberRecord{{IntentID: intentID, ADIURL: "acc://harbor.acme",
			OperationID: "0x" + strings.Repeat("77", 32), Leaf: leaf[:], LeafIndex: 0,
			GovernanceCommitment: "0x" + hex.EncodeToString(testGov[:])}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := f73Orchestrator(db).generateAndPersistBundle(ctx, c); err != nil {
		t.Fatal(err)
	}
	var proofID uuid.UUID
	if err := db.QueryRow(`SELECT proof_id FROM proof_artifacts WHERE intent_id=$1`, intentID).Scan(&proofID); err != nil {
		t.Fatal(err)
	}
	details, err := repos.ProofArtifacts.GetProofWithDetails(ctx, proofID)
	if err != nil {
		t.Fatal(err)
	}
	want := database.ValidatorQuorum{ChainID: 84532, Signers: 5, SignedVotingPower: "500", TotalVotingPower: "700",
		ThresholdNumerator: 2, ThresholdDenominator: 3, VerifyTx: verifyTx}
	if details.ValidatorQuorum == nil || *details.ValidatorQuorum != want {
		t.Fatalf("proof details state the checkers' quorum as %+v; the anchor was verified with %+v", details.ValidatorQuorum, want)
	}

	if q, err := repos.ProofArtifacts.GetValidatorQuorum(ctx, nil); q != nil || err != nil {
		t.Fatalf("a proof in no batch has no checkers' quorum, got (%+v, %v)", q, err)
	}
}
