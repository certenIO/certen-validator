package consensus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// V-J J1 (RB9-F5 invariant 2): the one consensus-reachable change of F5-3, driven through the application. A checkpoint records the number of writes to
// the globals account the walk applied (globals_updates) and the root chain index of the anchor it closed at (root_chain_index) only from the rules
// v15 activation in force at the block that carries the extension - the activation accepted BELOW that block's height - and is v14's, byte for byte,
// before it. The synthetic major block applies two globals writes, so a gate forced the wrong way changes the bytes in either direction.
func TestAppSpineCheckpointCarriesGlobalsAndRootChainOnlyAfterTheActivation(t *testing.T) {
	w, err := xworld.Build(xworld.Options{MajorUpdates: []string{xworld.UpdateGlobalsB, xworld.UpdateGenesisGlobals}})
	if err != nil {
		t.Fatal(err)
	}
	const wantGlobals = 2
	const extHeight = 3 // the block that carries the extension; the genesis is accepted at 2
	rci := majorRootChainIndex(t, w)

	// What the proof package says the checkpoint is, with and without the count (the oracle the application is compared with).
	walk := func(count bool) ledger.AccumulateSpineCheckpoint {
		g, set, err := proofv2.AcceptSpineGenesis(w.Inputs, w.Pin, 2)
		if err != nil {
			t.Fatal(err)
		}
		l := &ledger.AccumulateSpineLog{Genesis: g, Sets: []ledger.AccumulateSpineSet{set}}
		cps, _, err := proofv2.ExtendSpineCounting(l, w.Archive.Majors, extHeight, count)
		if err != nil || len(cps) != 1 {
			t.Fatalf("the proof package's walk of the synthetic major: %v (%d checkpoints)", err, len(cps))
		}
		return cps[0]
	}
	plain, counted := walk(false), walk(true)
	if plain.GlobalsUpdates != 0 || plain.RootChainIndex != 0 || counted.GlobalsUpdates != wantGlobals || counted.RootChainIndex != rci {
		t.Fatalf("the oracle: plain %+v, counted %+v; want %d globals writes and root chain index %d", plain, counted, wantGlobals, rci)
	}
	plainJSON, _ := json.Marshal(plain)

	for _, c := range []struct {
		name       string
		activation *ledger.G1ActivationRecord // nil: no activation recorded
		want       ledger.AccumulateSpineCheckpoint
		fields     bool // the two fields are encoded
	}{
		{"no activation", nil, plain, false},
		{"activation below the block", &ledger.G1ActivationRecord{Version: 1, Height: extHeight - 1, ID: "g1-activation:test"}, counted, true},
		{"activation at the block itself (judged below the activation)", &ledger.G1ActivationRecord{Version: 1, Height: extHeight, ID: "g1-activation:test"}, plain, false},
		{"activation above the block (not yet accepted)", &ledger.G1ActivationRecord{Version: 1, Height: extHeight + 1, ID: "g1-activation:test"}, plain, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			fx := newSpineFixture(t)
			recs, err := proofv2.MarshalArchive(w.Archive)
			if err != nil {
				t.Fatal(err)
			}
			fx.records = nil
			if err := json.Unmarshal(recs, &fx.records); err != nil {
				t.Fatal(err)
			}
			fx.inputs = w.Inputs
			app, store := rotationApp(t, fx.rotationFixture)
			if r := finalize(t, app, 1, abcitypes.CommitInfo{}, fx.registryUnder(t, 1, hex.EncodeToString(w.Pin[:]))); r.TxResults[0].Code != 0 {
				t.Fatalf("registry: %s", r.TxResults[0].Log)
			}
			commit(t, app)
			if r := finalize(t, app, 2, abcitypes.CommitInfo{}, fx.genesis(t)); r.TxResults[0].Code != 0 {
				t.Fatalf("genesis: %s", r.TxResults[0].Log)
			}
			commit(t, app)
			if c.activation != nil {
				if err := store.SaveG1Activation(&ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{*c.activation}}); err != nil {
					t.Fatal(err)
				}
			}
			ext := fx.extend(t, 1, 1)
			first := finalize(t, app, extHeight, abcitypes.CommitInfo{}, ext)
			if first.TxResults[0].Code != 0 {
				t.Fatalf("the extension: %d %s", first.TxResults[0].Code, first.TxResults[0].Log)
			}
			// A re-executed block (the same block, executed again before it commits) recomputes the checkpoint it already wrote and compares: a
			// difference stops the node, so the executions must return the same code, the same app hash and leave one checkpoint.
			for run := 0; run < 2; run++ {
				again := finalize(t, app, extHeight, abcitypes.CommitInfo{}, ext)
				if again.TxResults[0].Code != 0 || !bytes.Equal(again.AppHash, first.AppHash) {
					t.Fatalf("re-execution %d: code %d, app hash unchanged %v", run, again.TxResults[0].Code, bytes.Equal(again.AppHash, first.AppHash))
				}
			}
			commit(t, app)
			l := spineLog(t, store)
			if len(l.Checkpoints) != 1 {
				t.Fatalf("%d checkpoints recorded", len(l.Checkpoints))
			}
			got := l.Checkpoints[0]
			if got != c.want {
				t.Fatalf("the application recorded %+v, want %+v", got, c.want)
			}
			raw, _ := json.Marshal(got)
			hasG, hasR := strings.Contains(string(raw), `"globals_updates"`), strings.Contains(string(raw), `"root_chain_index"`)
			if hasG != c.fields || hasR != c.fields {
				t.Fatalf("the encoded checkpoint %s: globals_updates present %v, root_chain_index present %v, want both %v", raw, hasG, hasR, c.fields)
			}
			if !c.fields && !bytes.Equal(raw, plainJSON) {
				t.Fatalf("a checkpoint below the activation is not ExtendSpine's, byte for byte:\n%s\n%s", raw, plainJSON)
			}
			if c.fields {
				// Everything but the two fields is ExtendSpine's.
				stripped := got
				stripped.GlobalsUpdates, stripped.RootChainIndex = 0, 0
				if s, _ := json.Marshal(stripped); !bytes.Equal(s, plainJSON) {
					t.Fatalf("beyond the two fields the checkpoint differs from ExtendSpine's:\n%s\n%s", s, plainJSON)
				}
			}
		})
	}
}

// majorRootChainIndex is the RootChainIndex the synthetic major's anchor carries.
func majorRootChainIndex(t *testing.T, w *xworld.Built) uint64 {
	t.Helper()
	body := w.Archive.Majors[0].Anchor.Message.(*messaging.TransactionMessage).Transaction.Body.(*protocol.DirectoryAnchor)
	if body.RootChainIndex == 0 {
		t.Fatal("the synthetic major's anchor holds no root chain index")
	}
	return body.RootChainIndex
}
