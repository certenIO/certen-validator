// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// fixtureSource serves a real fixture's chain facts as an OutcomeEvidenceSource: the inclusions of its record and
// settlement transactions and the anchor's validator registry.
type fixtureSource struct {
	ev *OutcomeEvidence
}

func (f fixtureSource) Anchor() common.Address { return common.HexToAddress(f.ev.Anchor.Address) }

func (f fixtureSource) TransactionInclusion(_ context.Context, tx common.Hash) (*ChainInclusionEvidence, *types.Header, error) {
	for _, c := range []struct {
		hash string
		in   *ChainInclusionEvidence
	}{{f.ev.Record.Tx, &f.ev.Record.Inclusion}, {f.ev.Member.Leaf.Tx, f.ev.Member.Transaction}} {
		if c.in != nil && common.HexToHash(c.hash) == tx {
			hdr, err := decodeEvidenceHeader(c.in.Header, "fixture")
			if err != nil {
				return nil, nil, err
			}
			cp := *c.in
			return &cp, hdr, nil
		}
	}
	return nil, nil, fmt.Errorf("no transaction %s in the fixture", tx.Hex())
}

func (f fixtureSource) StateProofsAt(context.Context, *types.Header, []ExpectedStateSlot) ([]*StateProof, error) {
	return nil, errors.New("the fixture member committed no state")
}

func (f fixtureSource) QuorumRegistryAt(context.Context, *types.Header) (*OutcomeQuorumRegistry, error) {
	reg := &OutcomeQuorumRegistry{ThresholdNumerator: f.ev.Quorum.ThresholdNumerator, ThresholdDenominator: f.ev.Quorum.ThresholdDenominator}
	// Served in the anchor's list order, not sorted: the builder orders them as the set root does.
	for i := len(f.ev.Quorum.Validators) - 1; i >= 0; i-- {
		reg.Validators = append(reg.Validators, f.ev.Quorum.Validators[i])
	}
	return reg, nil
}

func (f fixtureSource) HeaderAt(context.Context, uint64) (*types.Header, error) {
	return nil, errors.New("the fixture serves no headers by height")
}

// fixtureInput is what the recorder holds for the fixture's anchor: its kept tree, the derived leaf, its view and the
// record transaction read from the chain.
func fixtureInput(t *testing.T, ev *OutcomeEvidence) OutcomeEvidenceInput {
	t.Helper()
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(ev.Record.Inclusion.Transaction); err != nil {
		t.Fatal(err)
	}
	bundle, root, proof, err := decodeRecordBatchOutcome(tx.Data())
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := decodeEvidenceHeader(ev.Record.Inclusion.Header, "record")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ev.Member.Leaf.decode(ev.ChainID, bundle)
	if err != nil {
		t.Fatal(err)
	}
	a := ev.Anchor
	m := OutcomeTreeMember{LeafIndex: leaf.LeafIndex, Leaf: leaf.BatchLeaf, OperationID: leaf.OperationID, Account: common.HexToAddress(ev.Member.Account),
		ADIURL: ev.Member.ADIURL, AuthorityBook: common.HexToHash(ev.Member.AuthorityBook), AuthorityPage: ev.Member.AuthorityPage,
		Legs: ev.Member.Legs, Deadline: ev.Member.Deadline}
	tree := &OutcomeTree{ChainID: ev.ChainID, BundleID: bundle, Root: common.HexToHash(a.BatchRoot), BatchOperationID: common.HexToHash(a.BatchOperationID),
		BlockHeight: a.AccumulateBlockHeight, AccumulateSetRoot: common.HexToHash(a.AccumulateSetRoot), Incarnation: common.HexToHash(a.Incarnation),
		Members: []OutcomeTreeMember{m}}
	view := &OutcomeAnchorView{At: hdr, LeafCount: a.LeafCount, CurrentSetRoot: common.HexToHash(a.CertenSetRoot), RecordedRoot: root,
		Anchor: &contracts.AnchorState{Version: contracts.BatchAnchorV8_2, BundleID: bundle, MerkleRoot: tree.Root, OperationID: tree.BatchOperationID,
			AccumulateBlockHeight: new(big.Int).SetUint64(a.AccumulateBlockHeight), Valid: true, ProofExecuted: true,
			AccumulateSetRoot: tree.AccumulateSetRoot, Incarnation: tree.Incarnation}}
	rec := &RecordedOutcomeTx{BundleID: bundle, Tx: tx.Hash(), Block: hdr.Number.Uint64(), BlockHash: hdr.Hash(),
		Recorder: common.HexToAddress(ev.Record.Recorder), Root: root, MessageHash: proof.MessageHash, Proof: *proof}
	return OutcomeEvidenceInput{Registry: common.HexToAddress(ev.Registry), Anchor: common.HexToAddress(a.Address), Tree: tree,
		Leaves: []OutcomeLeaf{leaf}, View: view, Record: rec}
}

// The builder reproduces the real evidence exactly from what the recorder holds and reads.
func TestBuildingTheEvidenceOfARealRecordReproducesIt(t *testing.T) {
	for _, chain := range outcomeFixtureChains {
		t.Run(fmt.Sprint(chain), func(t *testing.T) {
			want := loadOutcomeFixture(t, chain)
			got, err := BuildOutcomeEvidence(context.Background(), fixtureSource{want}, fixtureInput(t, want))
			if err != nil {
				t.Fatal(err)
			}
			a, _ := json.Marshal(got[0])
			b, _ := json.Marshal(want)
			if !bytes.Equal(a, b) {
				t.Fatalf("the built evidence differs from the real one:\n%s\n%s", a, b)
			}
		})
	}
}

// A record the builder cannot reproduce is refused, never kept: a leaf that is not the recorded root's, a set root
// that does not reproduce the record's message.
func TestTheBuilderRefusesARecordItCannotReproduce(t *testing.T) {
	ev := loadOutcomeFixture(t, 11155111)
	in := fixtureInput(t, ev)
	in.Leaves[0].EffectsHash = [32]byte{0x1}
	if _, err := BuildOutcomeEvidence(context.Background(), fixtureSource{ev}, in); !errors.Is(err, ErrOutcomeContradiction) {
		t.Fatalf("a leaf of another root: %v", err)
	}
	in = fixtureInput(t, ev)
	in.View.CurrentSetRoot = [32]byte{0x2}
	if _, err := BuildOutcomeEvidence(context.Background(), fixtureSource{ev}, in); err == nil || !strings.Contains(err.Error(), "does not reproduce") {
		t.Fatalf("a set root that moved: %v", err)
	}
}

// memLayers is a ProofStorageReader over in-memory layer rows.
type memLayers map[uuid.UUID][]certenproof.StoredLayerRow

func (m memLayers) LayerRows(_ context.Context, id uuid.UUID) ([]certenproof.StoredLayerRow, error) {
	return m[id], nil
}
func (m memLayers) ProofBlob(context.Context, uuid.UUID) (json.RawMessage, error) { return nil, nil }

// fixtureLayer5 is the layer 5 a proof of the fixture's member carries.
func fixtureLayer5(ev *OutcomeEvidence) *Layer5 {
	trim := func(s string) string { return strings.TrimPrefix(s, "0x") }
	a := ev.Anchor
	return &Layer5{ChainID: ev.ChainID, Network: "fixture", AnchorTx: "0x" + strings.Repeat("ab", 32), BlockNumber: 1,
		BatchRoot: trim(a.BatchRoot), LeafHash: trim(ev.Member.Leaf.BatchLeaf), LeafIndex: ev.Member.Leaf.LeafIndex,
		Commitment: &AnchorCommitment{Version: "v8_2", BundleID: a.BundleID, LeafCount: a.LeafCount, BatchOperationID: a.BatchOperationID,
			AccumulateBlockHeight: a.AccumulateBlockHeight, CertenSetRoot: a.CertenSetRoot, AccumulateSetRoot: a.AccumulateSetRoot,
			Incarnation: a.Incarnation}}
}

func storedProof(t *testing.T, l5 *Layer5, ev *OutcomeEvidence) (memLayers, uuid.UUID) {
	t.Helper()
	id := uuid.New()
	m := memLayers{}
	if l5 != nil {
		raw, _ := json.Marshal(l5)
		m[id] = append(m[id], certenproof.StoredLayerRow{LayerNumber: 5, LayerName: Layer5RowName, LayerJSON: raw})
	}
	if ev != nil {
		raw, _ := json.Marshal(ev)
		m[id] = append(m[id], certenproof.StoredLayerRow{LayerNumber: Layer6LayerNumber, LayerName: Layer6RowName, LayerJSON: raw})
	}
	return m, id
}

func TestAStoredProofsOutcomeIsVerifiedAndBoundToItsLayer5(t *testing.T) {
	ev := loadOutcomeFixture(t, 84532)
	store, id := storedProof(t, fixtureLayer5(ev), ev)
	_, chk, err := VerifyStoredOutcome(context.Background(), store, id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(chk.Established, "\n"), "bound to this proof") {
		t.Fatalf("not bound: %v", chk.Established)
	}

	t.Run("a proof without its outcome evidence is a named weaker state", func(t *testing.T) {
		store, id := storedProof(t, fixtureLayer5(ev), nil)
		if _, _, err := VerifyStoredOutcome(context.Background(), store, id); !errors.Is(err, ErrNoOutcomeEvidence) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("outcome evidence with no layer 5 to bind it is a named weaker state", func(t *testing.T) {
		store, id := storedProof(t, nil, ev)
		if _, _, err := VerifyStoredOutcome(context.Background(), store, id); !errors.Is(err, ErrNoOutcomeEvidence) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("the outcome of another leaf fails", func(t *testing.T) {
		l5 := fixtureLayer5(ev)
		l5.LeafHash = strings.Repeat("ab", 32)
		store, id := storedProof(t, l5, ev)
		if _, _, err := VerifyStoredOutcome(context.Background(), store, id); !errors.Is(err, ErrOutcomeEvidence) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("the outcome of another anchor fails", func(t *testing.T) {
		l5 := fixtureLayer5(ev)
		l5.Commitment.BundleID = "0x" + strings.Repeat("cd", 32)
		store, id := storedProof(t, l5, ev)
		if _, _, err := VerifyStoredOutcome(context.Background(), store, id); !errors.Is(err, ErrOutcomeEvidence) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("an outcome certified by another CERTEN set than the anchor's is a named state", func(t *testing.T) {
		l5 := fixtureLayer5(ev)
		l5.Commitment.CertenSetRoot = "0x" + strings.Repeat("ef", 32)
		store, id := storedProof(t, l5, ev)
		if _, _, err := VerifyStoredOutcome(context.Background(), store, id); !errors.Is(err, ErrOutcomeSetRotated) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a corrupt outcome row is a failure, not an absence", func(t *testing.T) {
		store, id := storedProof(t, fixtureLayer5(ev), nil)
		store[id] = append(store[id], certenproof.StoredLayerRow{LayerNumber: Layer6LayerNumber, LayerJSON: []byte(`{"version":`)})
		if _, _, err := VerifyStoredOutcome(context.Background(), store, id); !errors.Is(err, ErrOutcomeEvidence) {
			t.Fatalf("got %v", err)
		}
	})
}

// Evidence of one outcome from two validators: the recorder's, with the BLS aggregate only it holds, completes the
// other's; anything else that differs is a contradiction.
func TestOutcomeEvidenceFromTwoValidatorsConverges(t *testing.T) {
	ev := loadOutcomeFixture(t, 11155111)
	plain, _ := json.Marshal(ev)
	withAgg := *ev
	withAgg.Quorum.AggregateSignature, withAgg.Quorum.AggregatePublicKey = "0xaa", "0xbb"
	full, _ := json.Marshal(&withAgg)

	if d, _, err := decideOutcomeLayer(plain, ev); err != nil || d != database.OutcomeLayerKeep {
		t.Fatalf("the same evidence: %v %v", d, err)
	}
	if d, reason, err := decideOutcomeLayer(plain, &withAgg); err != nil || d != database.OutcomeLayerSupersede || reason == "" {
		t.Fatalf("evidence completed with the aggregate: %v %q %v", d, reason, err)
	}
	if d, _, err := decideOutcomeLayer(full, ev); err != nil || d != database.OutcomeLayerKeep {
		t.Fatalf("evidence without the aggregate against the complete one: %v %v", d, err)
	}
	other := *ev
	other.Member.Leaf.BlockNumber++
	if _, _, err := decideOutcomeLayer(plain, &other); err == nil {
		t.Fatal("evidence of another outcome was not a contradiction")
	}
	otherAgg := withAgg
	otherAgg.Quorum.AggregateSignature = "0xcc"
	if _, _, err := decideOutcomeLayer(full, &otherAgg); err == nil {
		t.Fatal("another aggregate was not a contradiction")
	}
}
