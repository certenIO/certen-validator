package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// liveG1Activation is the activation the runbook commits (docs/runbooks/rules-v15-g1-cross-partition-activation.md),
// signed by the named admins of f.
func liveG1Activation(f *rotationFixture, admins ...string) *G1ActivationTx {
	tx := &G1ActivationTx{Kind: G1ActivationKind, ChainID: rotChain, Version: 1}
	return tx.signedBy(f.admins, admins...)
}

func (t *G1ActivationTx) signedBy(keys map[string]ed25519.PrivateKey, ids ...string) *G1ActivationTx {
	t.Signatures = nil
	for _, id := range ids {
		t.Signatures = append(t.Signatures, PolicySignature{KeyID: id, Signature: hex.EncodeToString(ed25519.Sign(keys[id], t.SigningBytes()))})
	}
	return t
}

// The encoding admins sign, pinned against an independent computation of the same length-prefixed fields (Python
// hashlib over struct.pack('>I', len) || bytes of kind, chain, version, 2026-10-18): another chain or version signs
// differently, so an approval cannot be moved.
func TestTheG1ActivationEncodingIsPinned(t *testing.T) {
	const pinned = "39245269cb0c073ce6ad1a6a7cc8e62a9639839a45f9de308e200dd89ce9d260"
	f := newRotationFixture()
	tx := liveG1Activation(f)
	if got := hex.EncodeToString(tx.SigningBytes()); got != pinned {
		t.Fatalf("signing bytes %s, pinned %s", got, pinned)
	}
	if tx.ActivationID() != "g1-activation:"+pinned {
		t.Fatalf("id %s", tx.ActivationID())
	}
	other := &G1ActivationTx{Kind: G1ActivationKind, ChainID: rotChain, Version: 2}
	if bytes.Equal(other.SigningBytes(), tx.SigningBytes()) {
		t.Fatal("the version is not signed")
	}
	if got := hex.EncodeToString(other.SigningBytes()); got != "e4ce8bba05a8c4530955cc17bd4ebbcda150c8ffc87518871cd45bbafdcdc937" {
		t.Fatalf("version 2 signing bytes %s", got)
	}
	elsewhere := &G1ActivationTx{Kind: G1ActivationKind, ChainID: "certen-other", Version: 1}
	if bytes.Equal(elsewhere.SigningBytes(), tx.SigningBytes()) {
		t.Fatal("the chain is not signed")
	}
}

func TestAG1ActivationNeedsEverythingItClaims(t *testing.T) {
	f := newRotationFixture()
	rec, err := VerifyG1Activation(liveG1Activation(f, "ops-1", "ops-2"), rotChain, f.policy, nil, 5)
	if err != nil {
		t.Fatalf("the activation signed by two admins: %v", err)
	}
	if rec.Height != 5 || rec.Version != 1 || rec.ID != liveG1Activation(f).ActivationID() {
		t.Fatalf("record %+v", rec)
	}
	for name, tc := range map[string]struct {
		tx   func() *G1ActivationTx
		log  *ledger.G1ActivationLog
		want string
	}{
		"no chain": {tx: func() *G1ActivationTx {
			tx := liveG1Activation(f)
			tx.ChainID = " "
			return tx.signedBy(f.admins, "ops-1", "ops-2")
		}, want: "names its chain"},
		"another chain": {tx: func() *G1ActivationTx {
			tx := liveG1Activation(f)
			tx.ChainID = "certen-other"
			return tx.signedBy(f.admins, "ops-1", "ops-2")
		}, want: "is for chain"},
		"version zero": {tx: func() *G1ActivationTx {
			tx := liveG1Activation(f)
			tx.Version = 0
			return tx.signedBy(f.admins, "ops-1", "ops-2")
		}, want: "version 1"},
		"version two": {tx: func() *G1ActivationTx {
			tx := liveG1Activation(f)
			tx.Version = 2
			return tx.signedBy(f.admins, "ops-1", "ops-2")
		}, want: "version 1"},
		"a wrong kind": {tx: func() *G1ActivationTx {
			tx := liveG1Activation(f)
			tx.Kind = AnchorSetKind
			return tx.signedBy(f.admins, "ops-1", "ops-2")
		}, want: "is not"},
		"already activated": {tx: func() *G1ActivationTx { return liveG1Activation(f, "ops-1", "ops-2") },
			log:  &ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{{Version: 1, Height: 2}}},
			want: "an activation cannot be replayed, moved or undone"},
		"one admin": {tx: func() *G1ActivationTx { return liveG1Activation(f, "ops-1") }, want: "cross-partition activation"},
		"one admin twice": {tx: func() *G1ActivationTx {
			tx := liveG1Activation(f, "ops-1")
			tx.Signatures = append(tx.Signatures, tx.Signatures[0])
			return tx
		}, want: "cross-partition activation"},
		"a stranger": {tx: func() *G1ActivationTx {
			return liveG1Activation(f).signedBy(map[string]ed25519.PrivateKey{"ops-1": f.admins["ops-1"], "ops-9": seededKey(0x99)}, "ops-1", "ops-9")
		}, want: "cross-partition activation"},
		"signed for another chain": {tx: func() *G1ActivationTx {
			other := &G1ActivationTx{Kind: G1ActivationKind, ChainID: "certen-other", Version: 1}
			other.signedBy(f.admins, "ops-1", "ops-2")
			moved := liveG1Activation(f)
			moved.Signatures = other.Signatures
			return moved
		}, want: "cross-partition activation"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyG1Activation(tc.tx(), rotChain, f.policy, tc.log, 5)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
	// The admin set in force at the block authorises: rotated-out admins do not, the new ones do, but not in the block
	// that installed them.
	b := setB(f)
	rotated := *f.policy
	rotated.AdminReseals = []ledger.AdminReseal{{Height: 3, Keys: b.public(), Threshold: 2, Kind: AdminRotateKind, Sequence: 1}}
	if _, err := VerifyG1Activation(liveG1Activation(f, "ops-1", "ops-2"), rotChain, &rotated, nil, 4); err == nil {
		t.Fatal("the rotated-out admins authorised an activation")
	}
	if _, err := VerifyG1Activation(liveG1Activation(f).signedBy(b, "new-a", "new-b"), rotChain, &rotated, nil, 4); err != nil {
		t.Fatalf("the admin set in force: %v", err)
	}
	if _, err := VerifyG1Activation(liveG1Activation(f).signedBy(b, "new-a", "new-b"), rotChain, &rotated, nil, 3); err == nil {
		t.Fatal("the new admins authorised in the block that installed them")
	}
}

// The activation is in force for the heights above the block that accepted it, never at or below it: the 2.1 requirement
// starts at H+1, and every earlier block is decided as v14 decided it.
func TestG1ActivationIsInForceOnlyAboveItsBlock(t *testing.T) {
	log := &ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{{Version: 1, Height: 10, ID: "x"}}}
	for h, want := range map[int64]bool{1: false, 9: false, 10: false, 11: true, 12: true, 1000: true} {
		if got := G1CrossPartitionRequired(G1ActivationAt(log, h)); got != want {
			t.Errorf("height %d: required %v, want %v", h, got, want)
		}
	}
	if G1CrossPartitionRequired(G1ActivationAt(nil, 50)) || G1CrossPartitionRequired(G1ActivationAt(&ledger.G1ActivationLog{}, 50)) {
		t.Error("an empty log requires 2.1")
	}
}

// Before the activation the v15 binary decides every block as v14 did; the activation is recorded at its height, in the
// app hash, served by the query, stamps the state v15, and cannot be repeated.
func TestTheG1ActivationIsRecordedAndStampsRulesV15(t *testing.T) {
	f := newRotationFixture()
	app, store := rotationApp(t, f)
	good := rotJSON(t, liveG1Activation(f, "ops-1", "ops-2"))

	v14Step(t, app, 1, []uint32{0}, anchoredBlockJSON(t, "op-1", "validator-1", []ChainTarget{target(84532, liveAnchorBaseAndSepolia)}, nil))
	if app.committedRulesVersion() >= executionRulesV15 {
		t.Fatal("the state is v15's before any activation")
	}

	// One admin is refused (a refusal is a v15 verdict: v14 judged these bytes as a ValidatorBlock), two are accepted, and
	// the same activation again in the block - by the same or other admins: the id is the signed bytes' - is the accepted
	// no-op.
	resp := v14Step(t, app, 2, []uint32{codeG1ActivationRefused, 0, 0, 0},
		rotJSON(t, liveG1Activation(f, "ops-1")), good, good, rotJSON(t, liveG1Activation(f, "ops-2", "ops-3")))
	if !strings.Contains(resp.TxResults[0].Log, "cross-partition activation refused") {
		t.Fatalf("refusal log %q", resp.TxResults[0].Log)
	}
	l, err := store.LoadG1Activation()
	if err != nil || len(l.Activations) != 1 || l.Activations[0].Height != 2 || l.Activations[0].ID != liveG1Activation(f).ActivationID() {
		t.Fatalf("activation log (%+v, %v)", l, err)
	}
	if app.committedRulesVersion() != executionRulesV15 {
		t.Fatalf("after an activation the state is stamped v%d", app.committedRulesVersion())
	}
	if got, err := store.RulesFirstVerdict(executionRulesV15); err != nil || got != 2 {
		t.Fatalf("the first v15 verdict (%d, %v), want height 2", got, err)
	}
	without := finalize(t, newRotationAppFor(t, f), 2, abcitypes.CommitInfo{}, rotJSON(t, liveG1Activation(f, "ops-1")))
	if bytes.Equal(without.AppHash, resp.AppHash) {
		t.Fatal("the activation is not in the app hash")
	}

	// Later, the same activation is refused: the chain activates once.
	v14Step(t, app, 3, []uint32{codeG1ActivationRefused}, good)

	q, err := app.Query(context.Background(), &abcitypes.RequestQuery{Path: "/certen/g1_activation"})
	if err != nil || q.Code != 0 {
		t.Fatalf("query (%+v, %v)", q, err)
	}
	var got ledger.G1ActivationLog
	if err := json.Unmarshal(q.Value, &got); err != nil || len(got.Activations) != 1 || got.Activations[0].Height != 2 {
		t.Fatalf("query answered %s (%v)", q.Value, err)
	}
	if act, err := app.G1ActivationContext(); err != nil || act == nil || act.Height != 2 {
		t.Fatalf("the proposer's context (%+v, %v)", act, err)
	}
	if act := app.g1ActivationInForce(2); act != nil {
		t.Fatalf("the activation is in force in its own block: %+v", act)
	}
	if act := app.g1ActivationInForce(3); act == nil {
		t.Fatal("the activation is not in force the block after")
	}
}

// A committed activation-kind transaction must have been decided as one: v14 judged the same bytes as a ValidatorBlock,
// so any other code, or an acceptance with no record, is divergent state this binary refuses to continue.
func TestCommittedG1ActivationHistoryIsChecked(t *testing.T) {
	f := newRotationFixture()
	raw := rotJSON(t, liveG1Activation(f, "ops-1", "ops-2"))
	hist := func(code uint32) *fakeHistory {
		return &fakeHistory{base: 1, blocks: map[int64][][]byte{1: {raw}}, times: map[int64]time.Time{1: beforeV9},
			codes: map[int64][]uint32{1: {code}}}
	}
	for _, code := range []uint32{1, 2, 4, 0} {
		err := historyApp(t, 1).IndexCommittedHistory(hist(code))
		if !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) || !strings.Contains(err.Error(), "cross-partition activation") {
			t.Fatalf("an activation decided with code %d (and none recorded): %v", code, err)
		}
	}
	// Already indexed by a v14 binary: the kinds check still reads it.
	indexed := historyApp(t, 1)
	if err := indexed.ledgerStore.RecordCommittedBlock(1, nil); err != nil {
		t.Fatal(err)
	}
	if err := indexed.IndexCommittedHistory(hist(2)); !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) {
		t.Fatalf("an already-indexed chain with an activation decided as a ValidatorBlock: %v", err)
	}
	refused := historyApp(t, 1)
	if err := refused.IndexCommittedHistory(hist(codeG1ActivationRefused)); err != nil {
		t.Fatalf("an activation refused by v15: %v", err)
	}
	if refused.committedRulesVersion() != executionRulesV15 {
		t.Fatalf("a committed activation verdict left the state stamped v%d", refused.committedRulesVersion())
	}
	accepted := historyApp(t, 1)
	tx, _ := DecodeG1Activation(raw)
	if err := accepted.ledgerStore.SaveG1Activation(&ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{
		{Version: 1, Height: 1, ID: tx.ActivationID()}}}); err != nil {
		t.Fatal(err)
	}
	if err := accepted.IndexCommittedHistory(hist(0)); err != nil {
		t.Fatalf("an activation accepted and recorded by v15: %v", err)
	}
	// The tool's check: a node that cannot serve the activation log (before v15) can have recorded none.
	v, u, err := CommittedBlockViolations(1, [][]byte{raw}, []uint32{0}, &CommittedRecords{})
	if err != nil || len(v) != 1 || len(u) != 0 {
		t.Fatalf("an accepted activation against records without the log: %v %v %v", v, u, err)
	}
}

func TestCheckTxFiltersTheG1ActivationShape(t *testing.T) {
	f := newRotationFixture()
	app, _ := rotationApp(t, f)
	check := func(tx []byte) uint32 {
		t.Helper()
		r, err := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: tx})
		if err != nil {
			t.Fatal(err)
		}
		return r.Code
	}
	if c := check(rotJSON(t, liveG1Activation(f, "ops-1", "ops-2"))); c != 0 {
		t.Fatalf("a well-formed activation: code %d", c)
	}
	bad := liveG1Activation(f, "ops-1", "ops-2")
	bad.Version = 2
	if c := check(rotJSON(t, bad)); c != codeG1ActivationRefused {
		t.Fatalf("version 2: code %d", c)
	}
	// Bytes of the kind that do not decode are still the kind, refused by name - never judged as a ValidatorBlock.
	if c := check([]byte(`{"kind":"` + G1ActivationKind + `","version":"one"}`)); c != codeG1ActivationRefused {
		t.Fatalf("an undecodable activation: code %d", c)
	}
}
