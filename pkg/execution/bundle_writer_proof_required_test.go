// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/database"
)

type failingGenerator struct{ err error }

func (g failingGenerator) GenerateChainedProofForTx(context.Context, string, string, string) (*ChainedProofResult, error) {
	return nil, g.err
}

// RB3-F93: the bundle is not stored without its chained proof. With no generator it was stored with no
// L1-L5 layers after a "skipping" note; when generation failed, after a "Warning" line.
func TestNoBundleIsStoredWithoutItsChainedProof(t *testing.T) {
	db := s1OpenDB(t)
	for name, gen := range map[string]ChainedProofGenerator{
		"no generator":          nil,
		"generation failed":     failingGenerator{errors.New("DN not anchored yet")},
		"no proof and no error": failingGenerator{},
	} {
		c, intentID := f73Cycle(t, nil, nil)
		t.Cleanup(func() { cleanupProofArtifacts(db, intentID) })
		o := f73Orchestrator(db)
		o.config.ProofGenerator = gen
		if err := o.generateAndPersistBundle(context.Background(), c); err == nil {
			t.Errorf("%s: the bundle was stored", name)
		}
		var layers int
		if err := db.QueryRow(`SELECT count(*) FROM chained_proof_layers l JOIN proof_artifacts a ON a.proof_id=l.proof_id
			WHERE a.intent_id=$1 AND l.layer_number > 0`, intentID).Scan(&layers); err != nil {
			t.Fatal(err)
		}
		if layers != 0 {
			t.Errorf("%s: %d proof layers stored", name, layers)
		}
	}
}

// RB3-F91: a layer-5 binding the database refuses fails the bundle, the rule RB3-F73 set for the
// governance rows. writeLayer5 used to drop the error ("Never fatal").
func TestBundleWriterFailsWhenTheLayer5RowIsRefused(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	repos := database.NewRepositories(database.NewClientFromDB(db))
	if _, err := db.Exec(`CREATE OR REPLACE FUNCTION f91_refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'f91: L5 row refused'; END $$;
		CREATE TRIGGER f91_refuse BEFORE INSERT ON chained_proof_layers FOR EACH ROW WHEN (NEW.layer_number = 5) EXECUTE FUNCTION f91_refuse();`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(`DROP TRIGGER IF EXISTS f91_refuse ON chained_proof_layers; DROP FUNCTION IF EXISTS f91_refuse();`)
	})

	c, intentID := f73Cycle(t, nil, nil)
	t.Cleanup(func() { cleanupProofArtifacts(db, intentID) })
	leaf := crypto.Keccak256Hash([]byte("f91"))
	nonce := fmt.Sprintf("%032x", time.Now().UnixNano())
	rec := &database.AnchorQuorumRecord{
		AnchorVersion: "v8_1",
		ChainID:       84532, BundleID: "0x" + nonce + nonce, Root: leaf[:], BatchOperationID: testBatchOperationID("0x" + strings.Repeat("77", 32)),
		BatchOperationIDVersion: "v2",
		MessageHash:             "0x" + strings.Repeat("88", 32), AnchorCreateTx: "0x" + strings.Repeat("9a", 32), AnchorCreateBlock: 99,
		VerifyTx: "0x" + strings.Repeat("9b", 32), VerifyBlock: 100, VerifiedAt: time.Now().UTC(),
		AggregateSignature: []byte{1}, AggregatePubKey: []byte{2},
		Signers:           []database.AnchorQuorumSigner{{Address: "0xaaa", VotingPower: big.NewInt(500)}},
		SignedVotingPower: big.NewInt(500), TotalVotingPower: big.NewInt(700),
		Lane: "on_cadence", EvidenceSource: "live", TargetChain: "base-sepolia",
		Members: []database.AnchorQuorumMemberRecord{{IntentID: intentID, ADIURL: "acc://harbor.acme",
			OperationID: "0x" + strings.Repeat("77", 32), Leaf: leaf[:], LeafIndex: 0,
			GovernanceCommitment: "0x" + hex.EncodeToString(testGov[:])}},
	}
	asV8_2Anchor(t, rec, 1, uint64(time.Now().UnixNano()%1_000_000_000))
	if _, err := repos.Batches.RecordAnchorQuorum(ctx, rec); err != nil {
		t.Fatal(err)
	}
	err := f73Orchestrator(db).generateAndPersistBundle(ctx, c)
	if err == nil || !strings.Contains(err.Error(), "f91: L5 row refused") {
		t.Fatalf("the database refused the layer-5 row and the bundle writer reported %v", err)
	}
}
