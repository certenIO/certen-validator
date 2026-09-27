package execution

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// The per-intent createAnchor of the generation the bindings carry is recognised as an anchor-create call.
func TestTheAnchorCreateSelectorsIncludeTheBindingsCreateAnchor(t *testing.T) {
	parsed, err := contracts.CertenAnchorV4MetaData.GetAbi()
	if err != nil {
		t.Fatal(err)
	}
	if !isAnchorCreateCall(append(parsed.Methods["createAnchor"].ID, 0)) || !isAnchorCreateCall(append(createBatchAnchorMethod.ID, 0)) {
		t.Fatal("an anchor-create call is not recognised")
	}
	if isAnchorCreateCall([]byte{0xa9, 0x05, 0x9c, 0xbb, 0}) {
		t.Fatal("a transfer was recognised as an anchor-create call")
	}
}

// projectionFixture is one proof artifact on base-sepolia whose anchor columns state txHash, with an anchor
// reference and an attestation stating the same, and optionally a standing layer 5.
type projectionFixture struct {
	db      *sql.DB
	repair  *database.EvidenceRepair
	chain   fakeAnchorChain
	proofID uuid.UUID
	stated  string
	l5Tx    string
}

func newProjectionFixture(t *testing.T, withLayer5 bool) *projectionFixture {
	t.Helper()
	db := openMigratedTestDB(t, "projection repair")
	tag := uuid.NewString()
	f := &projectionFixture{db: db, repair: database.NewEvidenceRepair(database.NewClientFromDB(db)), proofID: uuid.New(),
		stated: "0x" + hex.EncodeToString(levelBytes("settle-"+tag)), chain: fakeAnchorChain{txs: map[string]*AnchorTxReading{}}}
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO proof_artifacts (proof_id, proof_type, accum_tx_hash, account_url, proof_class, validator_id,
		                             artifact_json, artifact_hash, anchor_tx_hash, anchor_block_number, anchor_chain, created_at)
		VALUES ($1, 'certen_anchor', $2, 'acc://p.acme/data', 'on_demand', 'v', '{}'::jsonb, '\x00', $3, 501, '84532', NOW())`,
		f.proofID, strings.Repeat("ab", 32), f.stated); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO anchor_references (proof_id, target_chain, chain_id, anchor_tx_hash, anchor_block_number, gas_used, is_confirmed, confirmations)
		VALUES ($1, 'evm', '84532', $2, 501, 77000, TRUE, 12)`, f.proofID, f.stated); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO validator_attestations (proof_id, validator_id, validator_pubkey, attested_hash, signature, anchor_tx_hash, block_number, attested_at)
		VALUES ($1, 'v1', '\x01', '\x02', '\x03', $2, 501, NOW())`, f.proofID, f.stated); err != nil {
		t.Fatal(err)
	}
	if withLayer5 {
		f.l5Tx = "0x" + hex.EncodeToString(levelBytes("create-"+tag))
		layer, _ := json.Marshal(map[string]any{"anchorTx": f.l5Tx, "blockNumber": 490, "blockHash": "0x" + strings.Repeat("cd", 32)})
		if _, err := db.ExecContext(ctx, `INSERT INTO chained_proof_layers (proof_id, layer_number, layer_name, layer_json, verified) VALUES ($1, 5, 'L5', $2::jsonb, TRUE)`,
			f.proofID, string(layer)); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM evidence_corrections WHERE record_id = $1`, f.proofID.String())
		_, _ = db.ExecContext(bg, `DELETE FROM validator_attestations WHERE proof_id = $1`, f.proofID)
		_, _ = db.ExecContext(bg, `DELETE FROM anchor_references WHERE proof_id = $1`, f.proofID)
		_, _ = db.ExecContext(bg, `DELETE FROM chained_proof_layers WHERE proof_id = $1`, f.proofID)
		_, _ = db.ExecContext(bg, `DELETE FROM proof_artifacts WHERE proof_id = $1`, f.proofID)
	})
	return f
}

// stateOnChain makes the stated transaction a mined call with the given calldata.
func (f *projectionFixture) stateOnChain(input []byte) {
	f.chain.txs[strings.ToLower(f.stated)] = &AnchorTxReading{Found: true, Succeeded: true, BlockNumber: 501,
		BlockHash: "0x" + strings.Repeat("ef", 32), Head: 600, Input: input, From: repairVerifier, To: "0x00000000000000000000000000000000000acc00"}
}

func (f *projectionFixture) run(t *testing.T, apply bool) *ProjectionRepairReport {
	t.Helper()
	report, err := RepairProofProjections(context.Background(), ProjectionRepairConfig{Repair: f.repair, Reader: f.chain, ValidatorID: repairValidator, Apply: apply})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func (f *projectionFixture) columns(t *testing.T) (paAnchor, paSettle, refAnchor, refSettle, attAnchor, attSettle sql.NullString) {
	t.Helper()
	if err := f.db.QueryRow(`SELECT pa.anchor_tx_hash, pa.settlement_tx_hash, ar.anchor_tx_hash, ar.settlement_tx_hash, va.anchor_tx_hash, va.settlement_tx_hash
		FROM proof_artifacts pa JOIN anchor_references ar ON ar.proof_id = pa.proof_id JOIN validator_attestations va ON va.proof_id = pa.proof_id
		WHERE pa.proof_id = $1`, f.proofID).Scan(&paAnchor, &paSettle, &refAnchor, &refSettle, &attAnchor, &attSettle); err != nil {
		t.Fatal(err)
	}
	return
}

func (f *projectionFixture) mentioned(report *ProjectionRepairReport) bool {
	for _, l := range append(append([]string{}, report.Actions...), report.Refused...) {
		if strings.Contains(l, f.proofID.String()) {
			return true
		}
	}
	return false
}

// RB3-F135: a settlement stated as the anchor moves to the settlement columns of all three tables, and the
// anchor columns state the proof's layer-5 anchor.
func TestProjectionRepairMovesTheSettlementAndStatesLayer5sAnchor(t *testing.T) {
	f := newProjectionFixture(t, true)
	f.stateOnChain([]byte{0xa9, 0x05, 0x9c, 0xbb, 0})
	if dry := f.run(t, false); !f.mentioned(dry) {
		t.Fatal("the dry run does not report the move")
	}
	if pa, _, _, _, _, _ := f.columns(t); pa.String != f.stated {
		t.Fatal("a dry run changed the database")
	}
	f.run(t, true)
	paAnchor, paSettle, refAnchor, refSettle, attAnchor, attSettle := f.columns(t)
	if paAnchor.String != f.l5Tx || refAnchor.String != f.l5Tx || attAnchor.String != f.l5Tx {
		t.Fatalf("anchors %v %v %v; want layer 5's %s", paAnchor, refAnchor, attAnchor, f.l5Tx)
	}
	if paSettle.String != f.stated || refSettle.String != f.stated || attSettle.String != f.stated {
		t.Fatalf("settlements %v %v %v; want %s", paSettle, refSettle, attSettle, f.stated)
	}
	var gas sql.NullInt64
	var settleGas int64
	if err := f.db.QueryRow(`SELECT gas_used, settlement_gas_used FROM anchor_references WHERE proof_id = $1`, f.proofID).Scan(&gas, &settleGas); err != nil || gas.Valid || settleGas != 77000 {
		t.Fatalf("the settlement's gas stayed on the anchor: anchor %v settlement %d (%v)", gas, settleGas, err)
	}
	var records int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM evidence_corrections WHERE record_id = $1`, f.proofID.String()).Scan(&records); err != nil || records != 3 {
		t.Fatalf("%d correction records, want one per table (%v)", records, err)
	}
	if again := f.run(t, true); f.mentioned(again) {
		t.Fatal("not idempotent")
	}
}

// Without a layer 5 the anchor is not established: the settlement moves out and the anchor columns are empty.
func TestProjectionRepairStatesNoAnchorWithoutLayer5(t *testing.T) {
	f := newProjectionFixture(t, false)
	f.stateOnChain([]byte{0xa9, 0x05, 0x9c, 0xbb, 0})
	f.run(t, true)
	paAnchor, paSettle, refAnchor, refSettle, _, _ := f.columns(t)
	if paAnchor.Valid || refAnchor.Valid || paSettle.String != f.stated || refSettle.String != f.stated {
		t.Fatalf("anchor %v/%v settlement %v/%v", paAnchor, refAnchor, paSettle, refSettle)
	}
	var confirmed bool
	if err := f.db.QueryRow(`SELECT is_confirmed FROM anchor_references WHERE proof_id = $1`, f.proofID).Scan(&confirmed); err != nil || confirmed {
		t.Fatalf("an unestablished anchor is still stated confirmed (%v)", err)
	}
}

// An anchor-create call is an anchor: left as it is - and refused where layer 5 names another anchor.
func TestProjectionRepairLeavesAnAnchorAndRefusesAContradiction(t *testing.T) {
	create := createBatchAnchorCall(t, levelHash("b"), levelHash("r"))
	f := newProjectionFixture(t, false)
	f.stateOnChain(create)
	if r := f.run(t, true); f.mentioned(r) {
		t.Fatalf("an anchor was moved: %+v", r)
	}
	if pa, ps, _, _, _, _ := f.columns(t); pa.String != f.stated || ps.Valid {
		t.Fatal("an anchor-create transaction was moved out of the anchor columns")
	}
	g := newProjectionFixture(t, true)
	g.stateOnChain(create)
	if r := g.run(t, true); !g.mentioned(r) || len(r.Refused) == 0 {
		t.Fatalf("a contradiction was not refused: %+v", r)
	}
	// Not mined: refused, nothing changed.
	h := newProjectionFixture(t, true)
	if r := h.run(t, true); !h.mentioned(r) {
		t.Fatalf("an unread transaction was not reported: %+v", r)
	}
	if pa, _, _, _, _, _ := h.columns(t); pa.String != h.stated {
		t.Fatal("an unread transaction was moved")
	}
}
