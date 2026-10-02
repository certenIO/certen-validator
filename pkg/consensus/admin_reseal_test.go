package consensus

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// The re-seal rules v11 accepts on certen-testnet, pinned: the three new admin keys (threshold 2), and the lost set it
// replaces. The id is pinned against an independent computation (Python sha256 over the canonical text).
func TestTheProductionReSealIsPinned(t *testing.T) {
	tx := NewAdminResealTx("certen-testnet")
	if err := tx.CheckShape(); err != nil {
		t.Fatal(err)
	}
	if !sameAdminSet(tx.AdminKeys, tx.AdminThreshold, resealedAdminSet) || len(tx.AdminKeys) != 3 || tx.AdminThreshold != 2 {
		t.Fatalf("the re-seal names %v threshold %d", tx.AdminKeys, tx.AdminThreshold)
	}
	if got := tx.ResealID(); got != "4455af81676ff371d0f5871861f53e3ebd160cc6138373d8131629c3d3de2612" {
		t.Fatalf("re-seal id %s", got)
	}
	if lostAdminSet.Threshold != 2 || lostAdminSet.Keys["ops-1"] != "2074b00450f5dbfd9d084423b5232e3732ef5db108f8b6fb5d4c96b73d5effd6" ||
		lostAdminSet.Keys["ops-2"] != "4572d81eeb0b2f72347f987a1a2ba75f4d5b475da14bbda9e0b585d1d50bc2f8" || len(lostAdminSet.Keys) != 2 {
		t.Fatalf("the lost set is %+v", lostAdminSet)
	}
	// Round trip on the wire.
	b, _ := json.Marshal(tx)
	back, ok := DecodeAdminReseal(b)
	if !ok || back.ResealID() != tx.ResealID() {
		t.Fatal("the re-seal does not survive the wire")
	}
	if _, ok := DecodeAdminReseal([]byte(`{"kind":"certen.blsregistry.set/v1"}`)); ok {
		t.Fatal("another kind decoded as a re-seal")
	}
}

// resealSets are a test's lost set (the fixture's sealed admins) and the set its re-seal installs.
func resealSets(f *rotationFixture) (adminSet, adminSet, map[string]ed25519.PrivateKey) {
	from := adminSet{Keys: map[string]string{}, Threshold: f.policy.AdminThreshold}
	for id, k := range f.policy.AdminKeys {
		from.Keys[id] = k
	}
	newAdmins := map[string]ed25519.PrivateKey{"admin-a": seededKey(0xC1), "admin-b": seededKey(0xC2), "admin-c": seededKey(0xC3)}
	to := adminSet{Keys: map[string]string{}, Threshold: 2}
	for id, k := range newAdmins {
		to.Keys[id] = pubHex(k)
	}
	return from, to, newAdmins
}

func resealFor(to adminSet, chain string) *AdminResealTx {
	tx := &AdminResealTx{Kind: AdminResealKind, ChainID: chain, AdminKeys: map[string]string{}, AdminThreshold: to.Threshold}
	for id, k := range to.Keys {
		tx.AdminKeys[id] = k
	}
	return tx
}

// The rule accepts the one re-seal it defines - from the lost set, to its set, on certen-testnet, once - and nothing
// else.
func TestTheReSealIsTheOneTheRuleDefines(t *testing.T) {
	f := newRotationFixture()
	from, to, _ := resealSets(f)
	if err := verifyAdminReseal(resealFor(to, rotChain), rotChain, f.policy, 10, from, to); err != nil {
		t.Fatalf("the defined re-seal was refused: %v", err)
	}
	other := to
	other.Keys = map[string]string{"evil": pubHex(seededKey(0xEE))}
	other.Threshold = 1
	already := *f.policy
	already.AdminReseals = []ledger.AdminReseal{{Height: 5, ID: "x", Keys: to.Keys, Threshold: 2}}
	notLost := *f.policy
	notLost.AdminKeys = map[string]string{"ops-1": f.policy.AdminKeys["ops-1"]}
	notLost.AdminThreshold = 1
	for name, c := range map[string]struct {
		tx    *AdminResealTx
		chain string
		state *ledger.EntitlementPolicyState
	}{
		"another chain":                        {resealFor(to, "another-chain"), "another-chain", f.policy},
		"a transaction naming another chain":   {resealFor(to, "another-chain"), rotChain, f.policy},
		"another admin set":                    {resealFor(other, rotChain), rotChain, f.policy},
		"the lost set is not the one in force": {resealFor(to, rotChain), rotChain, &notLost},
		"a chain that already re-sealed":       {resealFor(to, rotChain), rotChain, &already},
		"no sealed policy":                     {resealFor(to, rotChain), rotChain, nil},
		"a malformed transaction":              {&AdminResealTx{Kind: AdminResealKind, ChainID: rotChain}, rotChain, f.policy},
	} {
		if err := verifyAdminReseal(c.tx, c.chain, c.state, 10, from, to); err == nil {
			t.Errorf("%s: re-sealed", name)
		}
	}
}

// Through FinalizeBlock: accepted at height H, the new admins authorise from H+1 - not in block H, even after the
// re-seal in it - and the lost admins no longer do; replaying block H decides it identically; a second re-seal is
// refused by name; the re-seal's id is in the app hash.
func TestAReSealTakesEffectFromTheNextHeight(t *testing.T) {
	f := newRegistryFixture(t)
	from, to, newAdmins := resealSets(f.rotationFixture)
	lost, installed := lostAdminSet, resealedAdminSet
	lostAdminSet, resealedAdminSet = from, to
	defer func() { lostAdminSet, resealedAdminSet = lost, installed }()

	app, store := rotationApp(t, f.rotationFixture)
	signedByNew := func(version uint64) []byte {
		tx := f.registry(version)
		tx.Signatures = nil
		for _, id := range []string{"admin-a", "admin-b"} {
			tx.Signatures = append(tx.Signatures, PolicySignature{KeyID: id,
				Signature: hex.EncodeToString(ed25519.Sign(newAdmins[id], tx.SigningBytes()))})
		}
		return rotJSON(t, tx)
	}
	reseal := rotJSON(t, resealFor(to, rotChain))

	// Block 1: the re-seal, then a registry signed by the NEW admins - still judged by the lost set in force for 1.
	resp := finalize(t, app, 1, abcitypes.CommitInfo{}, reseal, signedByNew(1))
	if c := resp.TxResults[0].Code; c != 0 {
		t.Fatalf("the re-seal: code %d %s", c, resp.TxResults[0].Log)
	}
	if c := resp.TxResults[1].Code; c != codeBLSRegistryRefused {
		t.Fatalf("the new admins authorised in the re-seal's own block: code %d", c)
	}
	st, _ := store.LoadEntitlementPolicy()
	if len(st.AdminReseals) != 1 || st.AdminReseals[0].Height != 1 || !sameAdminSet(st.AdminKeys, st.AdminThreshold, from) {
		t.Fatalf("recorded %+v; the genesis seal must stay as it was", st)
	}
	if keys, th := AdminSetAt(st, 1); !sameAdminSet(keys, th, from) {
		t.Fatal("the set in force at the re-seal's own height is not the lost one")
	}
	if keys, th := AdminSetAt(st, 2); !sameAdminSet(keys, th, to) {
		t.Fatal("the set in force from the next height is not the installed one")
	}
	first := fmt.Sprintf("%x", resp.AppHash)

	// Replay of block 1: the same verdicts and the same app hash.
	again := finalize(t, app, 1, abcitypes.CommitInfo{}, reseal, signedByNew(1))
	if again.TxResults[0].Code != 0 || again.TxResults[1].Code != codeBLSRegistryRefused || fmt.Sprintf("%x", again.AppHash) != first {
		t.Fatalf("replay decided block 1 differently: %d %d %x", again.TxResults[0].Code, again.TxResults[1].Code, again.AppHash)
	}
	if _, err := app.Commit(nil, nil); err != nil {
		t.Fatal(err)
	}

	// Block 2: the lost admins no longer authorise; the new ones do.
	resp = finalize(t, app, 2, abcitypes.CommitInfo{}, rotJSON(t, f.registry(1, "ops-1", "ops-2")), signedByNew(1))
	if resp.TxResults[0].Code != codeBLSRegistryRefused {
		t.Fatalf("the lost admins still authorise after the re-seal: code %d", resp.TxResults[0].Code)
	}
	if resp.TxResults[1].Code != 0 {
		t.Fatalf("the new admins do not authorise after the re-seal: code %d %s", resp.TxResults[1].Code, resp.TxResults[1].Log)
	}
	if _, err := app.Commit(nil, nil); err != nil {
		t.Fatal(err)
	}

	// Block 3: no second re-seal.
	resp = finalize(t, app, 3, abcitypes.CommitInfo{}, reseal)
	if resp.TxResults[0].Code != codeAdminResealRefused {
		t.Fatalf("a second re-seal: code %d", resp.TxResults[0].Code)
	}
	// And the committed state says v11 decided it.
	if v := app.committedRulesVersion(); v != executionRulesV11 {
		t.Fatalf("committed rules v%d", v)
	}
}

// A chain whose sealed admins are not the lost set cannot be re-sealed at all.
func TestAChainWithItsAdminsIsNotReSealed(t *testing.T) {
	f := newRotationFixture()
	app, _ := rotationApp(t, f) // sealed with the fixture's admins; the production rule names others
	resp := finalize(t, app, 10, abcitypes.CommitInfo{}, rotJSON(t, NewAdminResealTx(rotChain)))
	if resp.TxResults[0].Code != codeAdminResealRefused {
		t.Fatalf("re-sealed a chain whose admins are not the lost set: code %d", resp.TxResults[0].Code)
	}
}

// History: a committed re-seal-kind transaction v10 judged as a ValidatorBlock (code 2) is history v11 does not
// reproduce, and the node refuses to start on it; one decided as a re-seal makes the state v11's.
func TestCommittedReSealHistoryIsChecked(t *testing.T) {
	reseal := []byte(fmt.Sprintf(`{"kind":%q,"chain_id":"certen-testnet"}`, AdminResealKind))
	bad := &fakeHistory{base: 1, blocks: map[int64][][]byte{1: {reseal}}, times: map[int64]time.Time{1: beforeV9},
		codes: map[int64][]uint32{1: {2}}}
	if err := historyApp(t, 1).IndexCommittedHistory(bad); !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) {
		t.Fatalf("history with a re-seal decided as a ValidatorBlock: %v", err)
	}
	good := &fakeHistory{base: 1, blocks: map[int64][][]byte{1: {reseal}}, times: map[int64]time.Time{1: beforeV9},
		codes: map[int64][]uint32{1: {codeAdminResealRefused}}}
	app := historyApp(t, 1)
	if err := app.IndexCommittedHistory(good); err != nil {
		t.Fatalf("history with a re-seal decided as one: %v", err)
	}
	if app.committedRulesVersion() != executionRulesV11 {
		t.Fatalf("a committed re-seal verdict left the state stamped v%d", app.committedRulesVersion())
	}
	if isValidatorBlockTx(reseal) {
		t.Fatal("a re-seal is read back as a ValidatorBlock")
	}
}
