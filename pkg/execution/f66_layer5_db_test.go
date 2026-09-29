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

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
)

// RB4-F66, end to end through the database: a v2 anchor's canonical rows state every member's governance
// commitment, the layer-5 binding reads them back, and the layer 5 built from it recomputes the anchored batch
// operation id - and refuses when a stored member's commitment was altered.
func TestF66_Layer5CarriesTheAnchoredGovernance(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	repos := database.NewRepositories(database.NewClientFromDB(db))

	nonce := fmt.Sprintf("%032x", time.Now().UnixNano())
	intentID := "f66-" + nonce[16:]
	inputs := []BatchLeafInput{
		{ADIURL: "acc://f66-a.acme", ExecutionCommitment: [32]byte{1}, OperationID: crypto.Keccak256Hash([]byte("f66-a" + nonce)), GovernanceCommitment: [32]byte{0xA1}},
		{ADIURL: "acc://f66-b.acme", ExecutionCommitment: [32]byte{2}, OperationID: crypto.Keccak256Hash([]byte("f66-b" + nonce)), GovernanceCommitment: [32]byte{0xB2}},
	}
	for i := range inputs {
		inputs[i].Provenance.AccumTxHash = fmt.Sprintf("%x", crypto.Keccak256Hash([]byte(fmt.Sprintf("accum-%d-%s", i, nonce))))
	}
	tree, err := BuildBatchTree(84532, withAccSet(inputs), 100, testIncarnation)
	if err != nil {
		t.Fatal(err)
	}
	members, err := membersFromTree(tree, map[[32]byte]string{inputs[1].OperationID: intentID})
	if err != nil {
		t.Fatal(err)
	}
	ev := &AnchorQuorumEvidence{
		ChainID: 84532, BundleID: tree.BundleID, Root: tree.Root, BatchOperationID: tree.BatchOperationID,
		BatchOperationIDVersion: tree.BatchOperationIDVersion, MessageHash: [32]byte{0x88},
		AccumulateBlockHeight: tree.BlockHeight, AccumulateSetRoot: tree.AccumulateSetRoot, Incarnation: tree.Incarnation,
		VerifyTx: "0x" + strings.Repeat("6b", 32), VerifyBlock: 100, VerifyBlockTime: time.Now().UTC(),
		AnchorCreateTx: "0x" + strings.Repeat("6a", 32), AnchorCreateBlock: 99,
		AggregateSignatureHex: "0x01", AggregatePublicKeyHex: "0x02",
		Signers: []string{"0xaaa"}, SignerPowers: []*big.Int{big.NewInt(500)},
		SignedVotingPower: big.NewInt(500), TotalVotingPower: big.NewInt(700),
		Lane: AnchorLaneOnCadence, Members: members,
	}
	if _, err := repos.Batches.RecordAnchorQuorum(ctx, AnchorQuorumRecordFrom(ev)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM batch_transactions WHERE batch_id IN (SELECT id FROM anchor_batches WHERE bundle_id = $1)`,
			hexPrefixed(tree.BundleID[:]))
		_, _ = db.Exec(`DELETE FROM anchor_batches WHERE bundle_id = $1`, hexPrefixed(tree.BundleID[:]))
	})

	binding, err := repos.ProofArtifacts.GetLayer5Binding(ctx, intentID, "", 84532)
	if err != nil {
		t.Fatal(err)
	}
	if binding.BatchOperationIDVersion != "v2" || len(binding.BatchMembers) != 2 ||
		binding.MemberGovernanceCommitment != "0x"+hex.EncodeToString(inputs[1].GovernanceCommitment[:]) {
		t.Fatalf("binding %+v", binding)
	}
	obs := &chain.ObservationResult{TxHash: "0x" + strings.Repeat("6c", 32), BlockNumber: 101}
	l5, err := BuildLayer5(binding, obs, 84532)
	if err != nil || l5 == nil || l5.Governance == nil {
		t.Fatalf("layer 5 %+v: %v", l5, err)
	}
	if l5.Governance.BatchOperationID != hexPrefixed(tree.BatchOperationID[:]) {
		t.Fatalf("layer 5 states batch operation id %s, the anchor %x", l5.Governance.BatchOperationID, tree.BatchOperationID)
	}

	// A stored member whose commitment was altered no longer recomputes to the anchored id.
	if _, err := db.Exec(`UPDATE batch_transactions SET governance_commitment = $2
		WHERE batch_id IN (SELECT id FROM anchor_batches WHERE bundle_id = $1) AND tree_index = 0`,
		hexPrefixed(tree.BundleID[:]), "0x"+strings.Repeat("cc", 32)); err != nil {
		t.Fatal(err)
	}
	binding, err = repos.ProofArtifacts.GetLayer5Binding(ctx, intentID, "", 84532)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildLayer5(binding, obs, 84532); err == nil {
		t.Fatal("a layer 5 whose members were altered was built")
	}
}
