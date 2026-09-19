package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

// fakeAnchorChain answers for the anchor transactions it holds.
type fakeAnchorChain map[string]*AnchorTxReading

func (c fakeAnchorChain) ReadAnchorTx(_ context.Context, _ int64, txHash string) (*AnchorTxReading, error) {
	if r, ok := c[strings.ToLower(txHash)]; ok {
		copied := *r
		return &copied, nil
	}
	return &AnchorTxReading{}, nil
}

func createBatchAnchorCall(t *testing.T, bundle, root [32]byte) []byte {
	t.Helper()
	args, err := createBatchAnchorMethod.Inputs.Pack(bundle, root, big.NewInt(1), levelHash("operation-"+hex.EncodeToString(bundle[:])), big.NewInt(9360888))
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte{}, createBatchAnchorMethod.ID...), args...)
}

// repairFixture is production on 2026-09-18: a canonical on-demand anchor whose row has no create block,
// a layer-5 row and a Certen proof stating the verify transaction's block, and a second proof of the same
// anchor signed by another validator.
type repairFixture struct {
	db          *sql.DB
	repos       *database.Repositories
	repair      *database.EvidenceRepair
	chain       fakeAnchorChain
	batchID     uuid.UUID
	anchorTx    string
	bundle      [32]byte
	root        [32]byte
	verifyBlock int64
	chainBlock  uint64
	chainHash   string
	layerID     uuid.UUID
	mine, other *database.CertenAnchorProof
	publicKey   ed25519.PublicKey
	signers     map[string]func([]byte) []byte
}

const repairValidator = "repair-validator"

func newRepairFixture(t *testing.T) *repairFixture {
	t.Helper()
	ctx := context.Background()
	db := openMigratedTestDB(t, "anchor repair")
	repos := database.NewRepositories(database.NewClientFromDB(db))
	f := &repairFixture{
		db: db, repos: repos, repair: database.NewEvidenceRepair(database.NewClientFromDB(db)),
		verifyBlock: 47002149, chainBlock: 47002138,
	}
	tag := uuid.NewString()
	f.bundle, f.root = levelHash("bundle-"+tag), levelHash("root-"+tag)
	f.anchorTx = "0x" + hex.EncodeToString(levelBytes("create-"+tag))
	f.chainHash = "0x" + hex.EncodeToString(levelBytes("block-"+tag))
	f.batchID = uuid.New()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO anchor_batches (id, batch_type, status, merkle_root, target_chain, chain_id, bundle_id,
			anchor_create_tx, anchor_tx_hash, verify_block, quorum_reached, evidence_source, lane)
		VALUES ($1, 'on_demand', 'confirmed', $2, 'base-sepolia', 84532, $3, $4, $4, $5, TRUE, 'live', 'on_demand')`,
		f.batchID, f.root[:], "0x"+hex.EncodeToString(f.bundle[:]), f.anchorTx, f.verifyBlock); err != nil {
		t.Fatalf("canonical row: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM evidence_corrections WHERE chain_evidence->>'tx_hash' = $1`, f.anchorTx)
		_, _ = db.ExecContext(bg, `DELETE FROM anchor_batches WHERE id = $1`, f.batchID)
	})

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.publicKey = publicKey
	f.signers = map[string]func([]byte) []byte{"ed25519": func(h []byte) []byte { return ed25519.Sign(privateKey, h) }}
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)

	f.mine = f.newProof(t, "mine-"+tag, repairValidator, privateKey, true)
	f.other = f.newProof(t, "other-"+tag, "validator-elsewhere", otherKey, false)

	f.chain = fakeAnchorChain{strings.ToLower(f.anchorTx): {
		Found: true, Succeeded: true, BlockNumber: f.chainBlock, BlockHash: f.chainHash,
		Head: f.chainBlock + 100, Input: createBatchAnchorCall(t, f.bundle, f.root),
	}}
	return f
}

// newProof stores an artifact with a layer-5 row (when withLayer) and a signed Certen proof, both stating
// the verify block, as the pre-fix writers did.
func (f *repairFixture) newProof(t *testing.T, label, validator string, key ed25519.PrivateKey, withLayer bool) *database.CertenAnchorProof {
	t.Helper()
	ctx := context.Background()
	accumTx := hex.EncodeToString(levelBytes("accum-" + label))
	artifact, err := f.repos.ProofArtifacts.CreateProofArtifact(ctx, &database.NewProofArtifact{
		ProofType: database.ProofTypeCertenAnchor, AccumTxHash: accumTx, AccountURL: "acc://repair.acme/data",
		ProofClass: database.ProofClassOnDemand, ValidatorID: validator, ArtifactJSON: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = f.db.ExecContext(bg, `DELETE FROM certen_anchor_proofs WHERE proof_artifact_id = $1`, artifact.ProofID)
		_, _ = f.db.ExecContext(bg, `UPDATE chained_proof_layers SET superseded_by = NULL WHERE proof_id = $1`, artifact.ProofID)
		_, _ = f.db.ExecContext(bg, `DELETE FROM chained_proof_layers WHERE proof_id = $1`, artifact.ProofID)
		_, _ = f.db.ExecContext(bg, `DELETE FROM proof_artifacts WHERE proof_id = $1`, artifact.ProofID)
	})
	if withLayer {
		layer, _ := json.Marshal(Layer5{
			ChainID: 84532, Network: "chain-84532", AnchorTx: f.anchorTx, BlockNumber: uint64(f.verifyBlock),
			BatchRoot: hex.EncodeToString(f.root[:]), LeafHash: hex.EncodeToString(f.root[:]),
		})
		row, err := f.repos.ProofArtifacts.CreateChainedProofLayer(ctx, &database.NewChainedProofLayer{
			ProofID: artifact.ProofID, LayerNumber: Layer5LayerNumber, LayerName: Layer5RowName, LayerJSON: layer,
		})
		if err != nil {
			t.Fatal(err)
		}
		f.layerID = row.LayerID
	}
	proof, err := f.repos.Proofs.CreateProof(ctx, &database.NewCertenAnchorProof{
		ProofArtifactID: artifact.ProofID, BatchID: f.batchID, AccumTxHash: accumTx, AccountURL: artifact.AccountURL,
		MerkleRoot: f.root[:], LeafHash: f.root[:], AnchorChain: "chain-84532", AnchorTxHash: f.anchorTx,
		AnchorBlockNumber: f.verifyBlock, GovLevel: database.GovLevelG2, GovValid: true, ValidatorID: validator,
		GovProof: json.RawMessage(`{"level":"G2","signers":["a","b"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repos.Proofs.UpdateValidatorSignature(ctx, proof.ProofID, ed25519.Sign(key, proof.ProofHash)); err != nil {
		t.Fatal(err)
	}
	if err := f.repos.Proofs.UpdateVerification(ctx, proof.ProofID, true, json.RawMessage(`{"threshold_met":true,"signature_scheme":"ed25519"}`)); err != nil {
		t.Fatal(err)
	}
	stored, err := f.repos.Proofs.GetProof(ctx, proof.ProofID)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func (f *repairFixture) run(t *testing.T, apply bool) *AnchorRepairReport {
	t.Helper()
	report, err := RepairAnchorBlocks(context.Background(), AnchorRepairConfig{
		Repair: f.repair, Proofs: f.repos.Proofs, Reader: f.chain, ValidatorID: repairValidator,
		Signers: f.signers, Apply: apply, Logf: t.Logf,
	})
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	return report
}

func (f *repairFixture) anchorBlock(t *testing.T) sql.NullInt64 {
	t.Helper()
	var block sql.NullInt64
	if err := f.db.QueryRow(`SELECT anchor_block_num FROM anchor_batches WHERE id = $1`, f.batchID).Scan(&block); err != nil {
		t.Fatal(err)
	}
	return block
}

func (f *repairFixture) corrections(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM evidence_corrections WHERE chain_evidence->>'tx_hash' = $1`, f.anchorTx).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *repairFixture) mentions(report []string, id string) bool {
	for _, line := range report {
		if strings.Contains(line, id) {
			return true
		}
	}
	return false
}

func TestAnchorRepairDryRunChangesNothing(t *testing.T) {
	f := newRepairFixture(t)
	report := f.run(t, false)
	if !f.mentions(report.Actions, f.batchID.String()) || !f.mentions(report.Actions, f.layerID.String()) || !f.mentions(report.Actions, f.mine.ProofID.String()) {
		t.Fatalf("the dry run does not report the anchor row, the layer and the proof: %+v", report.Actions)
	}
	if f.anchorBlock(t).Valid || f.corrections(t) != 0 {
		t.Fatal("a dry run changed the database")
	}
	proof, _ := f.repos.Proofs.GetProof(context.Background(), f.mine.ProofID)
	if proof.AnchorBlockNumber != f.verifyBlock || string(proof.ProofHash) != string(f.mine.ProofHash) {
		t.Fatal("a dry run revised a proof")
	}
}

func TestAnchorRepairCorrectsWhatTheChainContradicts(t *testing.T) {
	f := newRepairFixture(t)
	ctx := context.Background()
	report := f.run(t, true)
	// The shared test database holds other tests' anchors, which this chain does not know and refuses.
	if report.BlocksFilled != 1 || report.Layer5Replaced != 1 || report.ProofsRevised != 1 || f.mentions(report.Refused, f.anchorTx) {
		t.Fatalf("report: %+v", report)
	}

	// The canonical row now names the create transaction's own block.
	if block := f.anchorBlock(t); block.Int64 != int64(f.chainBlock) {
		t.Fatalf("anchor_block_num = %v, want %d", block, f.chainBlock)
	}

	// The false layer is withdrawn, kept and linked to its replacement; readers see only the replacement.
	var supersededBy uuid.NullUUID
	var reason sql.NullString
	var oldVerified bool
	if err := f.db.QueryRow(`SELECT superseded_by, superseded_reason, verified FROM chained_proof_layers WHERE layer_id = $1`, f.layerID).
		Scan(&supersededBy, &reason, &oldVerified); err != nil {
		t.Fatal(err)
	}
	if !supersededBy.Valid || !strings.Contains(reason.String, "verify transaction") || oldVerified {
		t.Fatalf("the false layer was not withdrawn with its reason: %v %q %v", supersededBy, reason.String, oldVerified)
	}
	layers, err := f.repos.ProofArtifacts.GetChainedProofLayers(ctx, f.mine.ProofArtifactID.UUID)
	if err != nil || len(layers) != 1 || layers[0].LayerID != supersededBy.UUID {
		t.Fatalf("readers see %d layers, want only the replacement: %v", len(layers), err)
	}
	var corrected Layer5
	if err := json.Unmarshal(layers[0].LayerJSON, &corrected); err != nil {
		t.Fatal(err)
	}
	if corrected.BlockNumber != f.chainBlock || corrected.BlockHash != f.chainHash || corrected.Network != "base-sepolia" ||
		corrected.AnchorTx != f.anchorTx || corrected.BatchRoot != hex.EncodeToString(f.root[:]) || corrected.VerifyOffline() != nil {
		t.Fatalf("replacement layer: %+v", corrected)
	}

	// The proof is revised: the chain's block, hash and depth, a hash over the new document, re-signed by
	// the validator that signed it, still verified; the old claim is kept in its correction.
	proof, err := f.repos.Proofs.GetProof(ctx, f.mine.ProofID)
	if err != nil {
		t.Fatal(err)
	}
	if proof.AnchorBlockNumber != int64(f.chainBlock) || proof.AnchorBlockHash.String != f.chainHash ||
		proof.AnchorChain != "base-sepolia" || proof.AnchorConfirms != 101 {
		t.Fatalf("revised anchor: block %d hash %v chain %s depth %d", proof.AnchorBlockNumber, proof.AnchorBlockHash, proof.AnchorChain, proof.AnchorConfirms)
	}
	sum := sha256.Sum256(proof.FullProof)
	if !proof.VerifyProofHash() || string(sum[:]) == string(f.mine.ProofHash) || !proof.Verified {
		t.Fatal("the revised proof's hash does not cover its new document, or it lost its verification")
	}
	if !ed25519.Verify(f.publicKey, proof.ProofHash, proof.ValidatorSig) {
		t.Fatal("the revised proof is not signed by the validator that signed it")
	}
	var document struct {
		Inclusion json.RawMessage `json:"transaction_inclusion"`
		Authority json.RawMessage `json:"authority_proof"`
		Anchor    struct {
			Chain       string `json:"chain"`
			BlockNumber int64  `json:"block_number"`
			BlockHash   string `json:"block_hash"`
		} `json:"anchor_reference"`
	}
	var before struct {
		Inclusion json.RawMessage `json:"transaction_inclusion"`
		Authority json.RawMessage `json:"authority_proof"`
	}
	_ = json.Unmarshal(proof.FullProof, &document)
	_ = json.Unmarshal(f.mine.FullProof, &before)
	if document.Anchor.BlockNumber != int64(f.chainBlock) || document.Anchor.BlockHash != f.chainHash || document.Anchor.Chain != "base-sepolia" ||
		string(document.Inclusion) != string(before.Inclusion) || string(document.Authority) != string(before.Authority) {
		t.Fatal("the revision changed more of the proof than its anchor reference")
	}
	corrections, err := f.repair.GetCorrections(ctx, database.CorrectionRecordCertenProof, f.mine.ProofID.String())
	if err != nil || len(corrections) != 1 {
		t.Fatalf("proof corrections: %d, %v", len(corrections), err)
	}
	var previous struct {
		ProofHash string `json:"proof_hash"`
		Signature string `json:"validator_signature"`
		Document  string `json:"full_proof_json"`
	}
	if err := json.Unmarshal(corrections[0].Previous, &previous); err != nil {
		t.Fatal(err)
	}
	if previous.ProofHash != hex.EncodeToString(f.mine.ProofHash) || previous.Signature != hex.EncodeToString(f.mine.ValidatorSig) ||
		previous.Document != string(f.mine.FullProof) {
		t.Fatal("the correction does not keep the proof as it was published")
	}
	if f.corrections(t) != 3 {
		t.Fatalf("%d corrections recorded, want the anchor row, the layer and the proof", f.corrections(t))
	}

	// Another validator's proof is left for that validator, untouched.
	other, _ := f.repos.Proofs.GetProof(ctx, f.other.ProofID)
	if string(other.ProofHash) != string(f.other.ProofHash) || !f.mentions(report.LeftForOwner, f.other.ProofID.String()) {
		t.Fatal("another validator's proof was revised, or not reported as left for it")
	}

	// A second run has nothing to do.
	again := f.run(t, true)
	if f.mentions(again.Actions, f.anchorTx) || again.BlocksFilled+again.Layer5Replaced+again.ProofsRevised != 0 || f.corrections(t) != 3 {
		t.Fatalf("the repair is not idempotent: %+v", again)
	}
}

func TestAnchorRepairRefusesWhatTheChainDoesNotProve(t *testing.T) {
	for name, adjust := range map[string]func(f *repairFixture, r *AnchorTxReading){
		"another root": func(f *repairFixture, r *AnchorTxReading) {
			r.Input = createBatchAnchorCall(t, f.bundle, levelHash("other root"))
		},
		"another bundle": func(f *repairFixture, r *AnchorTxReading) {
			r.Input = createBatchAnchorCall(t, levelHash("other bundle"), f.root)
		},
		"not an anchor call": func(_ *repairFixture, r *AnchorTxReading) { r.Input = []byte{1, 2, 3, 4, 5} },
		"another method, same arguments": func(f *repairFixture, r *AnchorTxReading) {
			call := createBatchAnchorCall(t, f.bundle, f.root)
			r.Input = append([]byte{0xde, 0xad, 0xbe, 0xef}, call[4:]...)
		},
		"reverted":             func(_ *repairFixture, r *AnchorTxReading) { r.Succeeded = false },
		"no such transaction":  func(_ *repairFixture, r *AnchorTxReading) { r.Found = false },
		"not final (depth 11)": func(f *repairFixture, r *AnchorTxReading) { r.Head = f.chainBlock + 10 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRepairFixture(t)
			adjust(f, f.chain[strings.ToLower(f.anchorTx)])
			report := f.run(t, true)
			if !f.mentions(append(report.Refused, report.NotYetFinal...), f.anchorTx) {
				t.Fatalf("not refused: %+v", report)
			}
			if f.anchorBlock(t).Valid || f.corrections(t) != 0 {
				t.Fatal("something was corrected without chain proof")
			}
		})
	}
}

// A stored proof whose document does not re-serialise to its own bytes cannot be revised without changing
// more than its anchor reference, so it is refused.
func TestAnchorRepairRefusesAProofItCannotReviseExactly(t *testing.T) {
	f := newRepairFixture(t)
	spaced := strings.Replace(string(f.mine.FullProof), `":`, `": `, 1)
	sum := sha256.Sum256([]byte(spaced))
	if _, err := f.db.Exec(`UPDATE certen_anchor_proofs SET full_proof_json = $2, proof_hash = $3 WHERE id = $1`, f.mine.ProofID, spaced, sum[:]); err != nil {
		t.Fatal(err)
	}
	report := f.run(t, true)
	if !f.mentions(report.Refused, f.mine.ProofID.String()) || report.ProofsRevised != 0 {
		t.Fatalf("a non-canonical document was revised: %+v", report)
	}
	proof, _ := f.repos.Proofs.GetProof(context.Background(), f.mine.ProofID)
	if string(proof.FullProof) != spaced {
		t.Fatal("the refused proof was changed")
	}
}

// A revision keeps what the proof was verified on; it does not make an unverified proof verified.
func TestAnchorRepairKeepsAnUnverifiedProofUnverified(t *testing.T) {
	f := newRepairFixture(t)
	if err := f.repos.Proofs.UpdateVerification(context.Background(), f.mine.ProofID, false, json.RawMessage(`{"threshold_met":false,"signature_scheme":"ed25519"}`)); err != nil {
		t.Fatal(err)
	}
	if report := f.run(t, true); report.ProofsRevised != 1 {
		t.Fatalf("report: %+v", report)
	}
	proof, _ := f.repos.Proofs.GetProof(context.Background(), f.mine.ProofID)
	if proof.Verified || proof.AnchorBlockNumber != int64(f.chainBlock) {
		t.Fatalf("revised proof verified=%v block=%d", proof.Verified, proof.AnchorBlockNumber)
	}
}

// A layer-5 row that names this anchor transaction with a root the anchor did not publish is a different
// false claim; the repair does not dress it up with the right block.
func TestAnchorRepairDoesNotCorrectALayerNamingAnotherRoot(t *testing.T) {
	f := newRepairFixture(t)
	other := levelHash("a root this anchor never published")
	// A self-consistent one-member layer (leaf = root) under another root: it verifies on its own terms.
	if _, err := f.db.Exec(`UPDATE chained_proof_layers
		SET layer_json = jsonb_set(jsonb_set(layer_json, '{batchRoot}', to_jsonb($2::text)), '{leafHash}', to_jsonb($2::text))
		WHERE layer_id = $1`, f.layerID, hex.EncodeToString(other[:])); err != nil {
		t.Fatal(err)
	}
	report := f.run(t, true)
	if !f.mentions(report.Refused, f.layerID.String()) || report.Layer5Replaced != 0 {
		t.Fatalf("report: %+v", report)
	}
	var superseded sql.NullTime
	if err := f.db.QueryRow(`SELECT superseded_at FROM chained_proof_layers WHERE layer_id = $1`, f.layerID).Scan(&superseded); err != nil || superseded.Valid {
		t.Fatalf("the row was replaced: %v %v", superseded, err)
	}
}
