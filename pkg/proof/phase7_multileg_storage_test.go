// Copyright 2026 Certen Protocol
//
// Phase 7, gate P7.9b — a multi-partition proof survives storage.
//
// PHASE7_DELEGATION_PLAN section 4.4: widening ChainedProof to N BVN legs
// breaks Phase 6's persistence unless both move together. The layer-4 writer
// must emit N + 1 rows, and ChainedProofFromStorage must reassemble a variable
// number of legs and FAIL CLOSED - never truncate - if the record names a leg
// that has no stored row.
//
// Truncation is the failure worth naming, because it does not look like one. A
// proof missing a leg still VERIFIES: the verifier checks the legs it is handed,
// so a proof quietly reassembled without its second partition passes while the
// evidence for that partition is gone.
package proof

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/google/uuid"
)

// fakeStore serves rows straight from memory, so this is offline and the
// reassembly logic is what is under test rather than a database.
type fakeStore struct {
	rows []StoredLayerRow
	blob json.RawMessage
}

func (s fakeStore) LayerRows(context.Context, uuid.UUID) ([]StoredLayerRow, error) {
	return s.rows, nil
}
func (s fakeStore) ProofBlob(context.Context, uuid.UUID) (json.RawMessage, error) {
	return s.blob, nil
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// twoPartitionProof is a proof whose signers span BVN1 and BVN2.
//
// The values are structurally consistent - each leg's L4 binds its own L1/L2,
// and both legs share the Directory anchor - because the claim under test is
// about STORAGE, and a fixture that failed verification for an unrelated reason
// would hide whether the round trip worked.
func twoPartitionProof(t *testing.T) *chained_proof.ChainedProof {
	t.Helper()
	cp := p6ShapeFixture()
	cp.Input.BVN = cp.Layer4BVN.Partition

	// The second leg is a copy of the first with its partition relabelled. A
	// field-by-field rebuild would quietly drop whatever fields Layer4 grows
	// later, and the claim under test is about storage, not about Layer4's
	// shape.
	secondL4 := *cp.Layer4BVN
	secondL4.Partition = "BVN2"

	second := chained_proof.PartitionLeg{
		Partition: "BVN2",
		Account:   "acc://certen-p7f-omega.acme/book/1",
		Layer1:    cp.Layer1,
		Layer2:    cp.Layer2,
		Layer4BVN: &secondL4,
	}
	if err := cp.AddLeg(second); err != nil {
		t.Fatalf("add leg: %v", err)
	}
	return cp
}

// storeFor renders a proof into the rows the writer would produce.
func storeFor(t *testing.T, cp *chained_proof.ChainedProof, dropPartition string) fakeStore {
	t.Helper()

	l1 := map[string]any{"input": cp.Input, "layer1": cp.Layer1}
	if len(cp.AdditionalLegs) > 0 {
		stripped := make([]chained_proof.PartitionLeg, 0, len(cp.AdditionalLegs))
		for _, leg := range cp.AdditionalLegs {
			leg.Layer4BVN = nil
			stripped = append(stripped, leg)
		}
		l1["additionalLegs"] = stripped
	}

	rows := []StoredLayerRow{
		{LayerNumber: 1, LayerName: "L1", LayerJSON: mustJSON(t, l1)},
		{LayerNumber: 2, LayerName: "L2", LayerJSON: mustJSON(t, map[string]any{"layer2": cp.Layer2})},
		{LayerNumber: 3, LayerName: "L3", LayerJSON: mustJSON(t, map[string]any{"layer3": cp.Layer3})},
	}
	for _, leg := range cp.Legs() {
		if leg.Layer4BVN == nil || strings.EqualFold(leg.Partition, dropPartition) {
			continue
		}
		rows = append(rows, StoredLayerRow{
			LayerNumber: 4,
			LayerName:   "L4-BVN (" + leg.Partition + ")",
			LayerJSON:   mustJSON(t, leg.Layer4BVN),
		})
	}
	rows = append(rows, StoredLayerRow{
		LayerNumber: 4, LayerName: "L4-DN", LayerJSON: mustJSON(t, cp.Layer4DN),
	})
	return fakeStore{rows: rows}
}

// TestP7_9b_MultiPartitionProofRoundTrips is the positive half.
func TestP7_9b_MultiPartitionProofRoundTrips(t *testing.T) {
	cp := twoPartitionProof(t)
	if len(cp.Legs()) != 2 {
		t.Fatalf("fixture has %d legs, expected 2", len(cp.Legs()))
	}

	got, err := ChainedProofFromStorage(context.Background(), storeFor(t, cp, ""), uuid.New())
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}

	if len(got.Legs()) != 2 {
		t.Fatalf("a two-partition proof came back with %d leg(s) - the second partition's "+
			"evidence was dropped, and the result would still verify", len(got.Legs()))
	}
	for _, leg := range got.Legs() {
		if leg.Layer4BVN == nil {
			t.Fatalf("leg %s came back with no quorum evidence", leg.Partition)
		}
		if !strings.EqualFold(leg.Layer4BVN.Partition, leg.Partition) {
			t.Fatalf("leg %s carries a quorum from %s", leg.Partition, leg.Layer4BVN.Partition)
		}
	}

	// Canonical order survives the round trip, which is what makes two
	// validators reading the same stored proof produce the same bytes.
	parts := got.SignerPartitions()
	for i := 1; i < len(parts); i++ {
		if strings.ToLower(parts[i-1]) > strings.ToLower(parts[i]) {
			t.Fatalf("legs came back out of canonical order: %v", parts)
		}
	}
}

// TestP7_9b_MissingLegFailsClosed is the half that matters.
//
// The record says two partitions signed; only one has a stored layer-4 row. The
// reassembly must refuse, because the alternative - returning the one leg it
// found - produces a proof that VERIFIES while the evidence for the other
// partition is missing.
func TestP7_9b_MissingLegFailsClosed(t *testing.T) {
	cp := twoPartitionProof(t)

	_, err := ChainedProofFromStorage(context.Background(), storeFor(t, cp, "BVN2"), uuid.New())
	if err == nil {
		t.Fatal("a proof whose second partition has no stored layer-4 row was reassembled " +
			"anyway. It would then verify, because the verifier only checks the legs it is " +
			"handed - silently proving less than the record claims")
	}
	if !strings.Contains(err.Error(), "BVN2") {
		t.Fatalf("the failure does not name the missing partition: %v", err)
	}
	t.Logf("refused, as it must be: %v", err)
}

// TestP7_9b_OrphanLegFailsClosed is the other direction.
//
// A stored layer-4 row for a partition the proof does not record as a signer is
// evidence for something this proof does not claim to cover. Accepting it would
// mean the stored record disagrees with itself and nothing noticed.
func TestP7_9b_OrphanLegFailsClosed(t *testing.T) {
	cp := twoPartitionProof(t)
	store := storeFor(t, cp, "")

	// Add a third layer-4 row that no leg claims.
	orphan := *cp.AdditionalLegs[0].Layer4BVN
	orphan.Partition = "BVN3"
	store.rows = append(store.rows, StoredLayerRow{
		LayerNumber: 4, LayerName: "L4-BVN (BVN3)", LayerJSON: mustJSON(t, &orphan),
	})

	_, err := ChainedProofFromStorage(context.Background(), store, uuid.New())
	if err == nil {
		t.Fatal("a layer-4 row for a partition this proof does not record as a signer was " +
			"accepted; the stored record disagrees with itself")
	}
	if !strings.Contains(err.Error(), "BVN3") {
		t.Fatalf("the failure does not name the orphan partition: %v", err)
	}
	t.Logf("refused, as it must be: %v", err)
}

// TestP7_9b_SinglePartitionProofsStillReassemble is the regression guard.
//
// Every proof on record is single-partition, with one L4-BVN row whose name
// carries no partition suffix and no additionalLegs key at all. Nothing in
// Phase 7 may change how those read back.
func TestP7_9b_SinglePartitionProofsStillReassemble(t *testing.T) {
	cp := p6ShapeFixture()
	cp.Input.BVN = cp.Layer4BVN.Partition

	store := fakeStore{rows: []StoredLayerRow{
		{LayerNumber: 1, LayerName: "L1", LayerJSON: mustJSON(t,
			map[string]any{"input": cp.Input, "layer1": cp.Layer1})},
		{LayerNumber: 2, LayerName: "L2", LayerJSON: mustJSON(t, map[string]any{"layer2": cp.Layer2})},
		{LayerNumber: 3, LayerName: "L3", LayerJSON: mustJSON(t, map[string]any{"layer3": cp.Layer3})},
		{LayerNumber: 4, LayerName: "L4-BVN - Quorum Signature", LayerJSON: mustJSON(t, cp.Layer4BVN)},
		{LayerNumber: 4, LayerName: "L4-DN - Quorum Signature", LayerJSON: mustJSON(t, cp.Layer4DN)},
	}}

	got, err := ChainedProofFromStorage(context.Background(), store, uuid.New())
	if err != nil {
		t.Fatalf("a single-partition proof no longer reassembles: %v", err)
	}
	if len(got.Legs()) != 1 {
		t.Fatalf("came back with %d legs", len(got.Legs()))
	}
	if len(got.AdditionalLegs) != 0 {
		t.Fatal("a single-partition proof gained an additional leg")
	}
	if got.Layer4BVN == nil || got.Layer4DN == nil {
		t.Fatal("a leg is missing after reassembly")
	}
}

// TestP7_9b_PrincipalPartitionMismatchFailsClosed guards the case where the
// proof's own input and its stored evidence disagree about which partition it
// is anchored on. Picking one silently would mean the reassembled proof's
// principal leg is not the one the proof says it is.
func TestP7_9b_PrincipalPartitionMismatchFailsClosed(t *testing.T) {
	cp := twoPartitionProof(t)
	store := storeFor(t, cp, "")

	// Rewrite the input so it names a partition no stored row is for.
	for i, row := range store.rows {
		if row.LayerNumber != 1 {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(row.LayerJSON, &obj); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		in := cp.Input
		in.BVN = "BVN7"
		obj["input"] = mustJSON(t, in)
		store.rows[i].LayerJSON = mustJSON(t, obj)
	}

	if _, err := ChainedProofFromStorage(context.Background(), store, uuid.New()); err == nil {
		t.Fatal("a proof whose input names a partition none of its stored legs is for was " +
			"reassembled anyway")
	} else {
		t.Logf("refused, as it must be: %v", err)
	}
}
