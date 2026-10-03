package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// A block is executed again whenever FinalizeBlock runs without the Commit that follows it - a handshake replay after a
// crash between the two, or CometBFT re-executing the block. FinalizeBlock writes an accepted policy update, validator
// rotation or BLS registry to the ledger at once, so the second execution finds this block's own record. It must
// decide every transaction exactly as the first did: the result codes are hashed into the next block header
// (LastResultsHash), and a validator rotation's updates are applied by CometBFT.
//
// The case that breaks a judgement keyed on the record alone: a REFUSED transaction with the same content id as an
// accepted one in the same block (the id covers the content, not the signatures) - the refused one carrying too few
// admin signatures, followed by the same content properly signed.

// replayCheck executes the block twice on app and once on a fresh process over the same ledger (a restart between
// FinalizeBlock and Commit), and requires the same codes, logs, app hash and validator updates every time.
func replayCheck(t *testing.T, app *ValidatorApp, restart func() *ValidatorApp, h int64, want []uint32, txs ...[]byte) {
	t.Helper()
	first := finalize(t, app, h, abcitypes.CommitInfo{}, txs...)
	for i, c := range want {
		if first.TxResults[i].Code != c {
			t.Fatalf("first execution tx %d: code %d (%s), want %d", i, first.TxResults[i].Code, first.TxResults[i].Log, c)
		}
	}
	for name, again := range map[string]*abcitypes.ResponseFinalizeBlock{
		"executed again":         finalize(t, app, h, abcitypes.CommitInfo{}, txs...),
		"executed after restart": finalize(t, restart(), h, abcitypes.CommitInfo{}, txs...),
	} {
		for i := range txs {
			if again.TxResults[i].Code != first.TxResults[i].Code || again.TxResults[i].Log != first.TxResults[i].Log {
				t.Errorf("%s: tx %d decided %d %q, first %d %q", name, i, again.TxResults[i].Code, again.TxResults[i].Log,
					first.TxResults[i].Code, first.TxResults[i].Log)
			}
		}
		if !bytes.Equal(again.AppHash, first.AppHash) {
			t.Errorf("%s: app hash %x, first %x", name, again.AppHash, first.AppHash)
		}
		if len(again.ValidatorUpdates) != len(first.ValidatorUpdates) {
			t.Errorf("%s: %d validator updates, first %d", name, len(again.ValidatorUpdates), len(first.ValidatorUpdates))
			continue
		}
		for i := range first.ValidatorUpdates {
			if !sameUpdate(again.ValidatorUpdates[i], first.ValidatorUpdates[i]) {
				t.Errorf("%s: validator update %d differs", name, i)
			}
		}
	}
}

// replayFixture is a rotation app over a KV a restarted process can reopen.
func replayFixture(t *testing.T, f *rotationFixture) (*ValidatorApp, *memKV, func() *ValidatorApp) {
	t.Helper()
	kv := newMemKV()
	store := ledger.NewLedgerStore(kv)
	if err := store.SaveEntitlementPolicy(f.policy); err != nil {
		t.Fatal(err)
	}
	open := func() *ValidatorApp {
		app := newTestApp(t, ledger.NewLedgerStore(kv))
		app.validatorBlocks = map[string]*ValidatorBlock{}
		app.entitlement = EntitlementConfig{Mode: EntitlementOff}
		doc := &cmttypes.GenesisDoc{ChainID: rotChain}
		for i, k := range f.validators {
			doc.Validators = append(doc.Validators, cmttypes.GenesisValidator{
				PubKey: cmted25519.PubKey(k.Public().(ed25519.PublicKey)), Power: 10, Name: string(rune('a' + i))})
		}
		if err := app.SetGenesis(doc); err != nil {
			t.Fatal(err)
		}
		return app
	}
	return open(), kv, open
}

func TestARefusedRegistryIsRefusedOnReplay(t *testing.T) {
	f := newRegistryFixture(t)
	app, _, restart := replayFixture(t, f.rotationFixture)
	replayCheck(t, app, restart, 1, []uint32{codeBLSRegistryRefused, 0},
		rotJSON(t, f.registry(1, "ops-1")), rotJSON(t, f.registry(1, "ops-1", "ops-2")))
	// Two versions in one block replay as they were decided.
	replayCheck(t, app, restart, 2, []uint32{0, 0, codeBLSRegistryRefused},
		rotJSON(t, f.registry(2, "ops-2", "ops-3")), rotJSON(t, f.registry(3, "ops-1", "ops-3")), rotJSON(t, f.registry(5, "ops-1", "ops-3")))
}

func TestARefusedValidatorRotationIsRefusedOnReplay(t *testing.T) {
	f := newRotationFixture()
	app, _, restart := replayFixture(t, f)
	fresh := seededKey(0x77)
	replayCheck(t, app, restart, 1, []uint32{6, 0},
		rotJSON(t, f.rotation(1, f.validators[2], fresh, "ops-1")), rotJSON(t, f.rotation(1, f.validators[2], fresh, "ops-1", "ops-2")))
}

func TestARefusedPolicyUpdateIsRefusedOnReplay(t *testing.T) {
	f := newRotationFixture()
	app, kv, restart := replayFixture(t, f)
	update := func(admins ...string) []byte {
		u := &PolicyUpdateTx{Kind: PolicyUpdateKind, ChainID: rotChain, Mode: string(EntitlementOff),
			ActivationUnix: 1_800_000_001 + MinActivationDelay + 60, Version: 1}
		for _, id := range admins {
			u.Signatures = append(u.Signatures, PolicySignature{KeyID: id,
				Signature: hex.EncodeToString(ed25519.Sign(f.admins[id], u.SigningBytes()))})
		}
		return rotJSON(t, u)
	}
	replayCheck(t, app, restart, 1, []uint32{5, 0}, update("ops-1"), update("ops-1", "ops-2"))
	st, err := ledger.NewLedgerStore(kv).LoadEntitlementPolicy()
	if err != nil || len(st.Schedule) != 1 || st.Schedule[0].ProposedAtHeight != 1 {
		t.Fatalf("schedule after replays: (%+v, %v)", st, err)
	}
	if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err != nil {
		t.Fatal(err)
	}
}

// The same rotation twice in one block - the admins' transaction and a byte-different copy of it (a trailing space,
// which anyone who sees the first in a mempool can submit) - used to be accepted twice, returning the old key's
// removal and the new key's power twice. CometBFT refuses a validator update list naming a key twice ("duplicate
// entry"), so every node would fail to apply the block and the chain would halt. Rules v12 accepts the first and
// refuses the copy, and the state is v12's from then on (v11 decided the copy differently).
func TestTheSameRotationTwiceInABlockIsAcceptedOnce(t *testing.T) {
	f := newRotationFixture()
	app, _, restart := replayFixture(t, f)
	tx := rotJSON(t, f.rotation(1, f.validators[3], seededKey(0x79), "ops-1", "ops-2"))
	copyOfIt := append(append([]byte(nil), tx...), ' ')
	replayCheck(t, app, restart, 1, []uint32{0, 6}, tx, copyOfIt)
	resp := finalize(t, app, 1, abcitypes.CommitInfo{}, tx, copyOfIt)
	if len(resp.ValidatorUpdates) != 2 {
		t.Fatalf("%d validator updates for one rotation", len(resp.ValidatorUpdates))
	}
	if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err != nil {
		t.Fatal(err)
	}
	if v := app.committedRulesVersion(); v != executionRulesV12 {
		t.Fatalf("a block only v12 decides this way left the state stamped v%d", v)
	}
}

// "An update cannot be replayed" (VerifyPolicyUpdate): yet an update whose version was scheduled in an EARLIER block was
// accepted again - code 0, its id folded into the app hash - whatever it carried, signatures or not. Rules v12 refuses
// it by name; the same update again within its own block is still the accepted no-op it was.
func TestAPolicyUpdateIsNotAcceptedAgainInALaterBlock(t *testing.T) {
	f := newRotationFixture()
	app, _, restart := replayFixture(t, f)
	update := func(mode string, admins ...string) []byte {
		u := &PolicyUpdateTx{Kind: PolicyUpdateKind, ChainID: rotChain, Mode: mode,
			ActivationUnix: 1_800_000_001 + MinActivationDelay + 60, Version: 1}
		for _, id := range admins {
			u.Signatures = append(u.Signatures, PolicySignature{KeyID: id,
				Signature: hex.EncodeToString(ed25519.Sign(f.admins[id], u.SigningBytes()))})
		}
		return rotJSON(t, u)
	}
	good := update(string(EntitlementOff), "ops-1", "ops-2")
	replayCheck(t, app, restart, 1, []uint32{0, 0}, good, append(append([]byte(nil), good...), ' '))
	if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err != nil {
		t.Fatal(err)
	}
	if v := app.committedRulesVersion(); v >= executionRulesV12 {
		t.Fatalf("a block v11 decides the same way stamped v%d", v)
	}
	// Later: the same update, and an unsigned one under its version.
	resp := finalize(t, app, 2, abcitypes.CommitInfo{}, append(append([]byte(nil), good...), ' ', ' '), update(string(EntitlementObserve)))
	for i, r := range resp.TxResults {
		if r.Code != 5 || !strings.Contains(r.Log, "version 1 was scheduled at height 1") {
			t.Fatalf("tx %d in a later block: %d %s", i, r.Code, r.Log)
		}
	}
	if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err != nil {
		t.Fatal(err)
	}
	if v := app.committedRulesVersion(); v != executionRulesV12 {
		t.Fatalf("a refusal only v12 makes left the state stamped v%d", v)
	}
}
