package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// fakeAnchorChain answers for the anchor transactions it holds, and locates the create transactions of
// the anchors it knows (by bundle, at their contract).
type fakeAnchorChain struct {
	txs     map[string]*AnchorTxReading
	creates map[string]*AnchorCreateLocation
}

func (c fakeAnchorChain) ReadAnchorTx(_ context.Context, _ int64, txHash string) (*AnchorTxReading, error) {
	if r, ok := c.txs[strings.ToLower(txHash)]; ok {
		copied := *r
		return &copied, nil
	}
	return &AnchorTxReading{}, nil
}

func (c fakeAnchorChain) LocateAnchorCreate(_ context.Context, _ int64, anchor string, bundle, _ [32]byte, _ uint64) (*AnchorCreateLocation, error) {
	if loc, ok := c.creates[strings.ToLower(anchor)+"/"+hex.EncodeToString(bundle[:])]; ok {
		copied := *loc
		return &copied, nil
	}
	return nil, errors.New("no BatchAnchorCreated log for this anchor")
}

// Addresses the fixture's transactions come from: the anchor contract, the validator that created the
// anchor and the one that verified it.
const (
	repairContract = "0x00000000000000000000000000000000000a1c40"
	repairCreator  = "0xd4a3dbbae0c04d4307c5e00a5e05b66acc289f5d"
	repairVerifier = "0x0000000000000000000000000000000000000002"
	// repairVerifyTime is the verify block's timestamp: when the quorum was confirmed on-chain.
	repairVerifyTime = 1_790_000_000
)

// executeComprehensiveProofCall is verify calldata proving bundle and root, packed with the submitter's ABI.
func executeComprehensiveProofCall(t *testing.T, bundle, root [32]byte) []byte {
	t.Helper()
	parsed, err := contracts.CertenAnchorV4MetaData.GetAbi()
	if err != nil {
		t.Fatal(err)
	}
	var signer common.Address
	signer[19] = 1
	packed, err := parsed.Pack("executeComprehensiveProof", bundle, contracts.CertenAnchorV4CertenProof{
		TransactionHash: bundle, MerkleRoot: root, ProofHashes: [][32]byte{},
		GovernanceProof: contracts.CertenAnchorV4GovernanceProofData{KeyPageProofs: [][32]byte{}, Nonce: big.NewInt(1),
			RequiredSignatures: big.NewInt(1), ProvidedSignatures: big.NewInt(1)},
		BlsProof: contracts.CertenAnchorV4BLSProofData{AggregateSignature: []byte{1}, ValidatorAddresses: []common.Address{signer},
			VotingPowers: []*big.Int{big.NewInt(1)}, TotalVotingPower: big.NewInt(1), SignedVotingPower: big.NewInt(1)},
		Commitments:    contracts.CertenAnchorV4CommitmentData{SourceBlockHeight: big.NewInt(0)},
		ExpirationTime: big.NewInt(0), Metadata: []byte{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return packed
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
	verifyTx    string
	bundle      [32]byte
	root        [32]byte
	verifyBlock int64
	statedBlock int64  // the block the stored layer and proofs state (the verify block, unless set)
	statedTx    string // the transaction the stored layer and proofs name as the anchor's (anchorTx, unless set)
	settleTx    string // the member's settlement transaction
	chainBlock  uint64
	chainHash   string
	layerID     uuid.UUID
	mine, other *database.CertenAnchorProof
	publicKey   ed25519.PublicKey
	signers     map[string]func([]byte) []byte
	// otherSigners sign as "validator-elsewhere", the other proof's validator.
	otherSigners map[string]func([]byte) []byte
	otherPublic  ed25519.PublicKey
}

const repairValidator = "repair-validator"

func newRepairFixture(t *testing.T) *repairFixture {
	t.Helper()
	return newRepairFixtureStating(t, false)
}

// newRepairFixtureStating builds the fixture; with rightBlock the canonical row, the layer and the proofs
// state the anchor's true block but no block hash - what an anchor read-back failure leaves (RB3-F119).
func newRepairFixtureStating(t *testing.T, rightBlock bool) *repairFixture {
	t.Helper()
	return newRepairFixtureWith(t, rightBlock, false)
}

// newRepairFixtureMisnamed is the RB3-F134 shape, live on 2026-09-19..21: a canonical row with no create
// transaction whose anchor_tx_hash, layer-5 row and Certen proofs all name the member's SETTLEMENT
// transaction, at the settlement's block, as where the root was published.
func newRepairFixtureMisnamed(t *testing.T) *repairFixture {
	t.Helper()
	f := newRepairFixtureWith(t, false, true)
	if _, err := f.db.Exec(`UPDATE anchor_batches SET anchor_create_tx = NULL, anchor_tx_hash = $2, anchor_block_num = $3 WHERE id = $1`,
		f.batchID, f.settleTx, f.statedBlock); err != nil {
		t.Fatal(err)
	}
	return f
}

func newRepairFixtureWith(t *testing.T, rightBlock, misnamed bool) *repairFixture {
	t.Helper()
	ctx := context.Background()
	db := openMigratedTestDB(t, "anchor repair")
	repos := database.NewRepositories(database.NewClientFromDB(db))
	f := &repairFixture{
		db: db, repos: repos, repair: database.NewEvidenceRepair(database.NewClientFromDB(db)),
		verifyBlock: 47002149, statedBlock: 47002149, chainBlock: 47002138,
	}
	if rightBlock {
		f.statedBlock = int64(f.chainBlock)
	}
	tag := uuid.NewString()
	f.bundle, f.root = levelHash("bundle-"+tag), levelHash("root-"+tag)
	f.anchorTx = "0x" + hex.EncodeToString(levelBytes("create-"+tag))
	f.verifyTx = "0x" + hex.EncodeToString(levelBytes("verify-"+tag))
	f.settleTx = "0x" + hex.EncodeToString(levelBytes("settle-"+tag))
	f.statedTx = f.anchorTx
	if misnamed {
		f.statedTx, f.statedBlock = f.settleTx, f.verifyBlock+1 // the settlement follows the verify
	}
	f.chainHash = "0x" + hex.EncodeToString(levelBytes("block-"+tag))
	f.batchID = uuid.New()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO anchor_batches (id, batch_type, status, merkle_root, target_chain, chain_id, bundle_id,
			anchor_create_tx, anchor_tx_hash, verify_tx, verify_block, quorum_reached, evidence_source, lane)
		VALUES ($1, 'on_demand', 'confirmed', $2, 'base-sepolia', 84532, $3, $4, $4, $6, $5, TRUE, 'live', 'on_demand')`,
		f.batchID, f.root[:], "0x"+hex.EncodeToString(f.bundle[:]), f.anchorTx, f.verifyBlock, f.verifyTx); err != nil {
		t.Fatalf("canonical row: %v", err)
	}
	if rightBlock {
		if _, err := db.ExecContext(ctx, `UPDATE anchor_batches SET anchor_block_num = $2 WHERE id = $1`, f.batchID, f.chainBlock); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM evidence_corrections WHERE chain_evidence->>'tx_hash' IN ($1, $2) OR record_id = $3`, f.anchorTx, f.verifyTx, f.batchID.String())
		_, _ = db.ExecContext(bg, `DELETE FROM anchor_batches WHERE id = $1`, f.batchID)
	})

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.publicKey = publicKey
	f.signers = map[string]func([]byte) []byte{"ed25519": func(h []byte) []byte { return ed25519.Sign(privateKey, h) }}
	otherPublic, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	f.otherPublic = otherPublic
	f.otherSigners = map[string]func([]byte) []byte{"ed25519": func(h []byte) []byte { return ed25519.Sign(otherKey, h) }}

	f.mine = f.newProof(t, "mine-"+tag, repairValidator, privateKey, true)
	f.other = f.newProof(t, "other-"+tag, "validator-elsewhere", otherKey, false)

	f.chain = fakeAnchorChain{
		txs: map[string]*AnchorTxReading{
			strings.ToLower(f.anchorTx): {
				Found: true, Succeeded: true, BlockNumber: f.chainBlock, BlockHash: f.chainHash,
				Head: f.chainBlock + 100, Input: createBatchAnchorCall(t, f.bundle, f.root),
				From: repairCreator, To: repairContract, BlockTime: repairVerifyTime - 22,
			},
			// The settlement: a successful call that published no root.
			strings.ToLower(f.settleTx): {
				Found: true, Succeeded: true, BlockNumber: uint64(f.verifyBlock + 1), BlockHash: "0x" + hex.EncodeToString(levelBytes("sblock-"+tag)),
				Head: f.chainBlock + 100, Input: []byte{0xa9, 0x05, 0x9c, 0xbb, 0x00}, From: repairVerifier, To: "0x00000000000000000000000000000000000acc00",
			},
			strings.ToLower(f.verifyTx): {
				Found: true, Succeeded: true, BlockNumber: uint64(f.verifyBlock), BlockHash: "0x" + hex.EncodeToString(levelBytes("vblock-"+tag)),
				Head: f.chainBlock + 100, Input: executeComprehensiveProofCall(t, f.bundle, f.root),
				From: repairVerifier, To: repairContract, BlockTime: repairVerifyTime,
			},
		},
		creates: map[string]*AnchorCreateLocation{
			repairContract + "/" + hex.EncodeToString(f.bundle[:]): {
				TxHash: f.anchorTx, Block: f.chainBlock, Validator: common.HexToAddress(repairCreator),
			},
		},
	}
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
			ChainID: 84532, Network: "chain-84532", AnchorTx: f.statedTx, BlockNumber: uint64(f.statedBlock),
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
		MerkleRoot: f.root[:], LeafHash: f.root[:], AnchorChain: "chain-84532", AnchorTxHash: f.statedTx,
		AnchorBlockNumber: f.statedBlock, GovLevel: database.GovLevelG2, GovValid: true, ValidatorID: validator,
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

// senders are the anchor row's recorded create and verify senders ("" where none).
func (f *repairFixture) senders(t *testing.T) (create, verify string) {
	t.Helper()
	var c, v sql.NullString
	if err := f.db.QueryRow(`SELECT anchor_create_sender, verify_sender FROM anchor_batches WHERE id = $1`, f.batchID).Scan(&c, &v); err != nil {
		t.Fatal(err)
	}
	return c.String, v.String
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
	// The anchor row's block, the layer, the proof, and the create transaction's sender (RB3-F127).
	if f.corrections(t) != 4 {
		t.Fatalf("%d corrections recorded, want the anchor row's block and create sender, the layer and the proof", f.corrections(t))
	}
	if create, verify := f.senders(t); create != repairCreator || verify != repairVerifier {
		t.Fatalf("senders recorded create=%q verify=%q", create, verify)
	}

	// Another validator's proof is left for that validator, untouched.
	other, _ := f.repos.Proofs.GetProof(ctx, f.other.ProofID)
	if string(other.ProofHash) != string(f.other.ProofHash) || !f.mentions(report.LeftForOwner, f.other.ProofID.String()) {
		t.Fatal("another validator's proof was revised, or not reported as left for it")
	}

	// A second run has nothing to do.
	again := f.run(t, true)
	if f.mentions(again.Actions, f.anchorTx) || again.BlocksFilled+again.Layer5Replaced+again.ProofsRevised+again.SendersRecorded != 0 || f.corrections(t) != 4 {
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
			adjust(f, f.chain.txs[strings.ToLower(f.anchorTx)])
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

// RB3-F119: a layer and a proof written while the anchor could not be read back state the right block but
// no block hash. The repair completes them from the chain - it used to act only on a hash that was present
// and wrong, so a missing one stayed missing for ever.
func TestAnchorRepairCompletesAMissingBlockHash(t *testing.T) {
	f := newRepairFixtureStating(t, true)
	report := f.run(t, true)
	if !f.mentions(report.Actions, f.layerID.String()) || !f.mentions(report.Actions, f.mine.ProofID.String()) {
		t.Fatalf("the layer and the proof stated without a block hash were not completed: %+v", report)
	}
	if report.BlocksFilled+report.BlocksCorrected != 0 || report.Layer5Replaced != 1 || report.ProofsRevised != 1 {
		t.Fatalf("report %+v; want the layer replaced and the proof revised, the canonical row untouched", report)
	}

	var layerJSON []byte
	if err := f.db.QueryRow(`SELECT layer_json FROM chained_proof_layers WHERE proof_id = $1 AND superseded_by IS NULL AND layer_number = $2`,
		f.mine.ProofArtifactID, Layer5LayerNumber).Scan(&layerJSON); err != nil {
		t.Fatal(err)
	}
	var completed Layer5
	if err := json.Unmarshal(layerJSON, &completed); err != nil {
		t.Fatal(err)
	}
	if completed.BlockNumber != f.chainBlock || !sameHex(completed.BlockHash, f.chainHash) {
		t.Fatalf("completed layer states block %d hash %q; want %d %s", completed.BlockNumber, completed.BlockHash, f.chainBlock, f.chainHash)
	}
	var reason sql.NullString
	if err := f.db.QueryRow(`SELECT superseded_reason FROM chained_proof_layers WHERE layer_id = $1`, f.layerID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reason.String, "without its hash") {
		t.Fatalf("the completed layer's reason does not say what was missing: %q", reason.String)
	}

	mine, err := f.repos.Proofs.GetProof(context.Background(), f.mine.ProofID)
	if err != nil {
		t.Fatal(err)
	}
	if !mine.AnchorBlockHash.Valid || !sameHex(mine.AnchorBlockHash.String, f.chainHash) || mine.AnchorBlockNumber != int64(f.chainBlock) {
		t.Fatalf("my proof states block %d hash %v", mine.AnchorBlockNumber, mine.AnchorBlockHash)
	}
	if !ed25519.Verify(f.publicKey, mine.ProofHash, mine.ValidatorSig) {
		t.Fatal("the completed proof is not signed over its new hash")
	}
	if !f.mentions(report.LeftForOwner, f.other.ProofID.String()) {
		t.Fatalf("another validator's proof without a hash is not left for it: %+v", report.LeftForOwner)
	}

	// Complete now: a second run finds nothing.
	again := f.run(t, true)
	if again.Layer5Replaced+again.ProofsRevised != 0 || f.mentions(again.Actions, f.anchorTx) {
		t.Fatalf("second run still acts: %+v", again)
	}
}

// withoutCreate makes the fixture's canonical row one that does not name its create transaction, as 235 of
// 289 production rows did (RB3-F33): anchorTxHash is what anchor_tx_hash holds ("" for NULL, the
// chain_backfill shape; the create transaction itself, the shape of three live rows).
func (f *repairFixture) withoutCreate(t *testing.T, anchorTxHash string) {
	t.Helper()
	if _, err := f.db.Exec(`UPDATE anchor_batches SET anchor_create_tx = NULL, anchor_tx_hash = NULLIF($2, ''), anchor_block_num = NULL WHERE id = $1`,
		f.batchID, anchorTxHash); err != nil {
		t.Fatal(err)
	}
}

func (f *repairFixture) createColumns(t *testing.T) (createTx, anchorTx sql.NullString, block sql.NullInt64) {
	t.Helper()
	if err := f.db.QueryRow(`SELECT anchor_create_tx, anchor_tx_hash, anchor_block_num FROM anchor_batches WHERE id = $1`, f.batchID).
		Scan(&createTx, &anchorTx, &block); err != nil {
		t.Fatal(err)
	}
	return
}

// RB3-F33: a row that does not name its create transaction gets the one the chain says created the anchor,
// with its block and both senders, each recorded as a correction; a second run has nothing to do.
func TestAnchorRepairCompletesTheCreateTransactionARowLacks(t *testing.T) {
	for name, stored := range map[string]func(f *repairFixture) string{
		"nothing stored (chain_backfill)":        func(*repairFixture) string { return "" },
		"anchor_tx_hash already names it (live)": func(f *repairFixture) string { return f.anchorTx },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRepairFixture(t)
			f.withoutCreate(t, stored(f))

			dry := f.run(t, false)
			if !f.mentions(dry.Actions, "anchor_create_tx NULL -> "+f.anchorTx) || !f.mentions(dry.Actions, "anchor_create sender -> "+repairCreator) {
				t.Fatalf("the dry run does not report the completion: %+v", dry.Actions)
			}
			if c, _, _ := f.createColumns(t); c.Valid || f.corrections(t) != 0 {
				t.Fatal("a dry run changed the database")
			}

			report := f.run(t, true)
			if report.CreatesCompleted != 1 || report.SendersRecorded != 2 || f.mentions(report.Refused, f.batchID.String()) {
				t.Fatalf("report: %+v", report)
			}
			createTx, anchorTx, block := f.createColumns(t)
			if createTx.String != f.anchorTx || anchorTx.String != f.anchorTx || block.Int64 != int64(f.chainBlock) {
				t.Fatalf("row: create %v, anchor_tx_hash %v, block %v", createTx, anchorTx, block)
			}
			if create, verify := f.senders(t); create != repairCreator || verify != repairVerifier {
				t.Fatalf("senders create=%q verify=%q", create, verify)
			}
			corrections, err := f.repair.GetCorrections(context.Background(), database.CorrectionRecordAnchorBatch, f.batchID.String())
			if err != nil {
				t.Fatal(err)
			}
			var completion *database.EvidenceCorrection
			for i := range corrections {
				if strings.Contains(corrections[i].Reason, "was created by transaction") {
					completion = &corrections[i]
				}
			}
			var previous map[string]any
			if completion != nil {
				_ = json.Unmarshal(completion.Previous, &previous)
			}
			if v, ok := previous["anchor_create_tx"]; completion == nil || !ok || v != nil {
				t.Fatalf("the completion has no correction record keeping what was stored: %d corrections, previous %v", len(corrections), previous)
			}
			if again := f.run(t, true); again.CreatesCompleted+again.SendersRecorded+again.BlocksFilled != 0 || f.mentions(again.Actions, f.batchID.String()) {
				t.Fatalf("the repair is not idempotent: %+v", again)
			}
		})
	}
}

// What the chain does not establish exactly is refused, and nothing is written.
func TestAnchorRepairRefusesACreateTransactionTheChainDoesNotEstablish(t *testing.T) {
	for name, adjust := range map[string]func(f *repairFixture){
		"the row names another publishing transaction": func(f *repairFixture) {
			f.withoutCreate(t, "0x"+strings.Repeat("ee", 32))
		},
		"signed by someone other than the anchor's recorded creator": func(f *repairFixture) {
			f.withoutCreate(t, "")
			f.chain.txs[strings.ToLower(f.anchorTx)].From = repairVerifier
		},
		"created at another contract": func(f *repairFixture) {
			f.withoutCreate(t, "")
			f.chain.txs[strings.ToLower(f.anchorTx)].To = "0x00000000000000000000000000000000000b0b00"
		},
		"not located": func(f *repairFixture) {
			f.withoutCreate(t, "")
			f.chain.creates = nil
		},
		"a verify transaction proving another bundle": func(f *repairFixture) {
			f.withoutCreate(t, "")
			f.chain.txs[strings.ToLower(f.verifyTx)].Input = executeComprehensiveProofCall(t, levelHash("other bundle"), f.root)
		},
		"a verify transaction that reverted": func(f *repairFixture) {
			f.withoutCreate(t, "")
			f.chain.txs[strings.ToLower(f.verifyTx)].Succeeded = false
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRepairFixture(t)
			adjust(f)
			report := f.run(t, true)
			if !f.mentions(report.Refused, f.batchID.String()) || report.CreatesCompleted != 0 {
				t.Fatalf("not refused: %+v", report)
			}
			if c, _, _ := f.createColumns(t); c.Valid || f.corrections(t) != 0 {
				t.Fatal("something was written without chain proof")
			}
			if create, verify := f.senders(t); create != "" || verify != "" {
				t.Fatalf("senders recorded on a refused anchor: %q %q", create, verify)
			}
		})
	}
}

// RB3-F127: a recorded sender the signature contradicts is corrected, and what was recorded is kept.
func TestAnchorRepairCorrectsASenderTheSignatureContradicts(t *testing.T) {
	f := newRepairFixture(t)
	wrong := "0x00000000000000000000000000000000000000ff"
	if _, err := f.db.Exec(`UPDATE anchor_batches SET verify_sender = $2 WHERE id = $1`, f.batchID, wrong); err != nil {
		t.Fatal(err)
	}
	report := f.run(t, true)
	if report.SendersCorrected != 1 || report.SendersRecorded != 1 {
		t.Fatalf("report: %+v", report)
	}
	if _, verify := f.senders(t); verify != repairVerifier {
		t.Fatalf("verify_sender = %q", verify)
	}
	var previous string
	if err := f.db.QueryRow(`SELECT previous->>'verify_sender' FROM evidence_corrections WHERE record_id = $1 AND corrected ? 'verify_sender'`,
		f.batchID.String()).Scan(&previous); err != nil || previous != wrong {
		t.Fatalf("the contradicted sender was not kept: %q (%v)", previous, err)
	}
}

// RB3-F131/F133: a completion time that is not the verify block's - the anchor's creation time, or a
// validator's clock - is corrected to it, with the signer attestations stamped with it.
func TestAnchorRepairCorrectsACompletionTimeThatIsNotTheVerifyBlocks(t *testing.T) {
	f := newRepairFixture(t)
	stated := time.Unix(repairVerifyTime, 0).UTC().Add(2*time.Second + 345*time.Millisecond)
	if _, err := f.db.Exec(`UPDATE anchor_batches SET consensus_completed_at = $2 WHERE id = $1`, f.batchID, stated); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO batch_attestations (batch_id, validator_id, evm_address, voting_power, merkle_root, bls_public_key, tx_count, block_height, attestation_time, signature_valid)
		VALUES ($1, 'v1', 'v1', 100, $2, $4, 1, $5, $3, TRUE)`, f.batchID, f.root[:], stated, []byte{1}, f.verifyBlock); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM batch_attestations WHERE batch_id = $1`, f.batchID) })
	report := f.run(t, true)
	if report.CompletionTimesCorrected != 1 {
		t.Fatalf("report %+v", report)
	}
	var completed, attested time.Time
	if err := f.db.QueryRow(`SELECT consensus_completed_at FROM anchor_batches WHERE id = $1`, f.batchID).Scan(&completed); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT attestation_time FROM batch_attestations WHERE batch_id = $1`, f.batchID).Scan(&attested); err != nil {
		t.Fatal(err)
	}
	want := time.Unix(repairVerifyTime, 0)
	if !completed.Equal(want) || !attested.Equal(want) {
		t.Fatalf("completed %v attested %v, want the verify block's %v", completed, attested, want)
	}
	var previous string
	if err := f.db.QueryRow(`SELECT previous->>'consensus_completed_at' FROM evidence_corrections WHERE record_id = $1 AND corrected ? 'consensus_completed_at'`,
		f.batchID.String()).Scan(&previous); err != nil || previous != stated.Format(time.RFC3339Nano) {
		t.Fatalf("the stated time was not kept: %q (%v)", previous, err)
	}
	if again := f.run(t, true); again.CompletionTimesCorrected != 0 {
		t.Fatalf("not idempotent: %+v", again)
	}
}

// RB3-F134: a row, its layer 5 and its Certen proofs that name the settlement's transaction as the anchor's
// are corrected to the anchor's own create transaction and block - the proof revised and re-signed by the
// validator that signed it, what was stated kept in the corrections.
func TestAnchorRepairCorrectsTheSettlementNamedAsTheAnchor(t *testing.T) {
	f := newRepairFixtureMisnamed(t)
	ctx := context.Background()

	dry := f.run(t, false)
	if !f.mentions(dry.Actions, "anchor_tx_hash "+f.settleTx+", which did not publish the root") || !f.mentions(dry.Actions, f.layerID.String()) {
		t.Fatalf("the dry run does not report the correction: %+v %+v", dry.Actions, dry.Refused)
	}

	report := f.run(t, true)
	if report.CreatesCompleted != 1 || report.Layer5Replaced != 1 || report.ProofsRevised != 1 || f.mentions(report.Refused, f.batchID.String()) {
		t.Fatalf("report %+v", report)
	}
	createTx, anchorTx, block := f.createColumns(t)
	if createTx.String != f.anchorTx || anchorTx.String != f.anchorTx || block.Int64 != int64(f.chainBlock) {
		t.Fatalf("row: create %v anchor_tx_hash %v block %v", createTx, anchorTx, block)
	}
	layers, err := f.repos.ProofArtifacts.GetChainedProofLayers(ctx, f.mine.ProofArtifactID.UUID)
	if err != nil || len(layers) != 1 {
		t.Fatalf("readers see %d layers (%v)", len(layers), err)
	}
	var corrected Layer5
	if err := json.Unmarshal(layers[0].LayerJSON, &corrected); err != nil {
		t.Fatal(err)
	}
	if corrected.AnchorTx != f.anchorTx || corrected.BlockNumber != f.chainBlock || corrected.BlockHash != f.chainHash || corrected.VerifyOffline() != nil {
		t.Fatalf("replacement layer %+v", corrected)
	}
	proof, err := f.repos.Proofs.GetProof(ctx, f.mine.ProofID)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Anchor struct {
			TxHash      string `json:"tx_hash"`
			BlockNumber int64  `json:"block_number"`
		} `json:"anchor_reference"`
	}
	_ = json.Unmarshal(proof.FullProof, &document)
	if proof.AnchorTxHash != f.anchorTx || document.Anchor.TxHash != f.anchorTx || document.Anchor.BlockNumber != int64(f.chainBlock) ||
		!proof.VerifyProofHash() || !ed25519.Verify(f.publicKey, proof.ProofHash, proof.ValidatorSig) {
		t.Fatalf("revised proof names %s / %s @ %d", proof.AnchorTxHash, document.Anchor.TxHash, document.Anchor.BlockNumber)
	}
	corrections, err := f.repair.GetCorrections(ctx, database.CorrectionRecordCertenProof, f.mine.ProofID.String())
	if err != nil || len(corrections) != 1 || !strings.Contains(string(corrections[0].Previous), f.settleTx) {
		t.Fatalf("the proof as published is not kept: %d corrections (%v)", len(corrections), err)
	}
	// The other validator's proof names the settlement too: left for that validator's own run.
	if !f.mentions(report.LeftForOwner, f.other.ProofID.String()) {
		t.Fatalf("another validator's proof is not left for it: %+v", report.LeftForOwner)
	}
	if again := f.run(t, true); again.CreatesCompleted+again.Layer5Replaced+again.ProofsRevised != 0 {
		t.Fatalf("not idempotent: %+v", again)
	}
}

// A row naming a transaction that IS this anchor's createBatchAnchor call, while the chain locates another,
// contradicts the chain and is refused.
func TestAnchorRepairRefusesARowNamingAnotherCreationOfItsAnchor(t *testing.T) {
	f := newRepairFixtureMisnamed(t)
	f.chain.txs[strings.ToLower(f.settleTx)].Input = createBatchAnchorCall(t, f.bundle, f.root)
	report := f.run(t, true)
	if !f.mentions(report.Refused, f.batchID.String()) || report.CreatesCompleted != 0 {
		t.Fatalf("report %+v", report)
	}
	if c, _, _ := f.createColumns(t); c.Valid {
		t.Fatal("a contradiction was written")
	}
}

// RB3-F136, production 2026-09-28: validator-1's run completed the row and corrected its own proof; each
// other validator's run must then still find and revise the proof it signed, which names the settlement -
// found by the batch now that the row no longer names the settlement to look for.
func TestAnchorRepairRevisesEachSignersProofAfterAnotherRunCompletedTheRow(t *testing.T) {
	f := newRepairFixtureMisnamed(t)
	first := f.run(t, true)
	if first.CreatesCompleted != 1 || first.ProofsRevised != 1 || !f.mentions(first.LeftForOwner, f.other.ProofID.String()) {
		t.Fatalf("first run: %+v", first)
	}
	second, err := RepairAnchorBlocks(context.Background(), AnchorRepairConfig{
		Repair: f.repair, Proofs: f.repos.Proofs, Reader: f.chain, ValidatorID: "validator-elsewhere",
		Signers: f.otherSigners, Apply: true, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.ProofsRevised != 1 {
		t.Fatalf("the other validator's run did not revise its proof: %+v", second)
	}
	other, err := f.repos.Proofs.GetProof(context.Background(), f.other.ProofID)
	if err != nil {
		t.Fatal(err)
	}
	if other.AnchorTxHash != f.anchorTx || other.AnchorBlockNumber != int64(f.chainBlock) || !ed25519.Verify(f.otherPublic, other.ProofHash, other.ValidatorSig) {
		t.Fatalf("the other validator's proof names %s @ %d", other.AnchorTxHash, other.AnchorBlockNumber)
	}
}
