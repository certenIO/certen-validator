package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// RB3-F95 phase 2: a validator's consensus key is rotated by a transaction the chain agrees to.

const rotChain = "certen-testnet"

func seededKey(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }

func pubHex(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }

type rotationFixture struct {
	admins     map[string]ed25519.PrivateKey
	validators []ed25519.PrivateKey
	genesis    []GenesisValidator
	policy     *ledger.EntitlementPolicyState
}

func newRotationFixture() *rotationFixture {
	f := &rotationFixture{admins: map[string]ed25519.PrivateKey{"ops-1": seededKey(0xA1), "ops-2": seededKey(0xA2), "ops-3": seededKey(0xA3)}}
	f.policy = &ledger.EntitlementPolicyState{Mode: string(EntitlementOff), AdminKeys: map[string]string{}, AdminThreshold: 2}
	for id, k := range f.admins {
		f.policy.AdminKeys[id] = pubHex(k)
	}
	for i := 0; i < 7; i++ {
		k := seededKey(byte(0x10 + i))
		f.validators = append(f.validators, k)
		f.genesis = append(f.genesis, GenesisValidator{PubKey: k.Public().(ed25519.PublicKey), Power: 10})
	}
	return f
}

// rotation builds a rotation old -> new at version, with the new key's possession proof and the named admins'
// signatures.
func (f *rotationFixture) rotation(version uint64, oldKey, newKey ed25519.PrivateKey, admins ...string) *ValidatorRotationTx {
	t := &ValidatorRotationTx{Kind: ValidatorRotationKind, ChainID: rotChain, Version: version,
		OldPubKey: pubHex(oldKey), NewPubKey: pubHex(newKey)}
	t.Possession = hex.EncodeToString(ed25519.Sign(newKey, t.PossessionBytes()))
	for _, id := range admins {
		t.Signatures = append(t.Signatures, PolicySignature{KeyID: id, Signature: hex.EncodeToString(ed25519.Sign(f.admins[id], t.SigningBytes()))})
	}
	return t
}

func TestARotationNeedsEverythingItClaims(t *testing.T) {
	f := newRotationFixture()
	fresh := seededKey(0x77)
	empty := &ledger.ValidatorRotationLog{}

	good := f.rotation(1, f.validators[2], fresh, "ops-1", "ops-2")
	if power, err := VerifyValidatorRotation(good, rotChain, f.policy, f.genesis, empty, 50); err != nil || power != 10 {
		t.Fatalf("a well-formed rotation: (%d, %v)", power, err)
	}

	refused := map[string]*ValidatorRotationTx{
		"one admin of two": f.rotation(1, f.validators[2], fresh, "ops-1"),
		"the same admin twice": func() *ValidatorRotationTx {
			r := f.rotation(1, f.validators[2], fresh, "ops-1")
			r.Signatures = append(r.Signatures, r.Signatures[0])
			return r
		}(),
		"another chain": func() *ValidatorRotationTx {
			r := f.rotation(1, f.validators[2], fresh, "ops-1", "ops-2")
			r.ChainID = "another-chain"
			return r
		}(),
		"a skipped version":    f.rotation(2, f.validators[2], fresh, "ops-1", "ops-2"),
		"an unknown old key":   f.rotation(1, seededKey(0x55), fresh, "ops-1", "ops-2"),
		"a new key in the set": f.rotation(1, f.validators[2], f.validators[3], "ops-1", "ops-2"),
		"no proof of possession": func() *ValidatorRotationTx {
			r := f.rotation(1, f.validators[2], fresh, "ops-1", "ops-2")
			r.Possession = hex.EncodeToString(ed25519.Sign(seededKey(0x66), r.PossessionBytes()))
			return r
		}(),
		"admin signature used as possession": func() *ValidatorRotationTx {
			r := f.rotation(1, f.validators[2], fresh, "ops-1", "ops-2")
			r.Possession = hex.EncodeToString(ed25519.Sign(fresh, r.SigningBytes()))
			return r
		}(),
		"a signature over other keys": func() *ValidatorRotationTx {
			r := f.rotation(1, f.validators[2], fresh, "ops-1", "ops-2")
			r.NewPubKey = pubHex(seededKey(0x78))
			return r
		}(),
	}
	for name, r := range refused {
		if _, err := VerifyValidatorRotation(r, rotChain, f.policy, f.genesis, empty, 50); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := VerifyValidatorRotation(good, rotChain, nil, f.genesis, empty, 50); err == nil {
		t.Error("accepted on a chain with no sealed policy")
	}
	if _, err := VerifyValidatorRotation(good, rotChain, &ledger.EntitlementPolicyState{Mode: "off"}, f.genesis, empty, 50); err == nil {
		t.Error("accepted on a chain that sealed no admin quorum")
	}
	if _, err := VerifyValidatorRotation(good, rotChain, f.policy, nil, empty, 50); err == nil {
		t.Error("accepted with no genesis set to judge against")
	}
}

// One rotation at a time: until the rotated validator signs with its new key, only that same slot can be
// rotated again. A key that left the set never comes back.
func TestOnlyOneValidatorIsEverMidRotation(t *testing.T) {
	f := newRotationFixture()
	first, second, replacement := seededKey(0x71), seededKey(0x72), seededKey(0x73)
	log := &ledger.ValidatorRotationLog{Rotations: []ledger.ValidatorRotationRecord{{
		Version: 1, Height: 10, OldPubKey: pubHex(f.validators[0]), NewPubKey: pubHex(first), Power: 10, ID: "r1"}}}

	other := f.rotation(2, f.validators[1], second, "ops-1", "ops-2")
	if _, err := VerifyValidatorRotation(other, rotChain, f.policy, f.genesis, log, 20); err == nil ||
		!strings.Contains(err.Error(), "has not been adopted") {
		t.Fatalf("a second validator was rotated while the first is not signing: %v", err)
	}
	same := f.rotation(2, first, replacement, "ops-1", "ops-2")
	if _, err := VerifyValidatorRotation(same, rotChain, f.policy, f.genesis, log, 20); err != nil {
		t.Fatalf("re-rotating the pending slot: %v", err)
	}
	back := f.rotation(2, first, f.validators[0], "ops-1", "ops-2")
	if _, err := VerifyValidatorRotation(back, rotChain, f.policy, f.genesis, log, 20); err == nil {
		t.Fatal("a key rotated out came back")
	}

	// Adopted at 15: the next validator may rotate from 16 on - and not before.
	log.Rotations[0].AdoptedHeight = 15
	if _, err := VerifyValidatorRotation(other, rotChain, f.policy, f.genesis, log, 20); err != nil {
		t.Fatalf("after adoption: %v", err)
	}
	if _, err := VerifyValidatorRotation(other, rotChain, f.policy, f.genesis, log, 14); err == nil {
		t.Fatal("judged at a height before the adoption, the second rotation was accepted")
	}
}

// ---- the app -----------------------------------------------------------------------------------------

func rotationApp(t *testing.T, f *rotationFixture) (*ValidatorApp, *ledger.LedgerStore) {
	t.Helper()
	store := ledger.NewLedgerStore(newMemKV())
	if err := store.SaveEntitlementPolicy(f.policy); err != nil {
		t.Fatal(err)
	}
	app := newTestApp(t, store)
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
	return app, store
}

func finalize(t *testing.T, app *ValidatorApp, height int64, commit abcitypes.CommitInfo, txs ...[]byte) *abcitypes.ResponseFinalizeBlock {
	t.Helper()
	resp, err := app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
		Height: height, Time: time.Unix(1_800_000_000+height, 0), Hash: bytes.Repeat([]byte{byte(height)}, 32),
		Txs: txs, DecidedLastCommit: commit,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func rotJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sameUpdate(a, b abcitypes.ValidatorUpdate) bool {
	return a.Power == b.Power && a.PubKey.Equal(b.PubKey)
}

func signedBy(keys ...ed25519.PrivateKey) abcitypes.CommitInfo {
	var c abcitypes.CommitInfo
	for _, k := range keys {
		c.Votes = append(c.Votes, abcitypes.VoteInfo{
			Validator:   abcitypes.Validator{Address: cmted25519.PubKey(k.Public().(ed25519.PublicKey)).Address(), Power: 10},
			BlockIdFlag: cmtproto.BlockIDFlagCommit,
		})
	}
	return c
}

func TestTheAppRotatesAKeyAndReplaysItExactly(t *testing.T) {
	f := newRotationFixture()
	app, store := rotationApp(t, f)
	fresh := seededKey(0x77)
	tx := rotJSON(t, f.rotation(1, f.validators[4], fresh, "ops-2", "ops-3"))

	resp := finalize(t, app, 40, abcitypes.CommitInfo{}, tx)
	if resp.TxResults[0].Code != 0 {
		t.Fatalf("rotation refused: %s", resp.TxResults[0].Log)
	}
	want := []abcitypes.ValidatorUpdate{
		abcitypes.Ed25519ValidatorUpdate(f.validators[4].Public().(ed25519.PublicKey), 0),
		abcitypes.Ed25519ValidatorUpdate(fresh.Public().(ed25519.PublicKey), 10),
	}
	if len(resp.ValidatorUpdates) != 2 || !sameUpdate(resp.ValidatorUpdates[0], want[0]) || !sameUpdate(resp.ValidatorUpdates[1], want[1]) {
		t.Fatalf("updates %v, want %v", resp.ValidatorUpdates, want)
	}
	empty := finalize(t, app, 40, abcitypes.CommitInfo{})
	if bytes.Equal(empty.AppHash, resp.AppHash) {
		t.Fatal("the rotation is not in the app hash")
	}

	// Replay: the same block again (a handshake replay, or FinalizeBlock without Commit) gives the same
	// updates and the same app hash, and the log still holds one rotation.
	again := finalize(t, app, 40, abcitypes.CommitInfo{}, tx)
	if again.TxResults[0].Code != 0 || !bytes.Equal(again.AppHash, resp.AppHash) || len(again.ValidatorUpdates) != 2 ||
		!sameUpdate(again.ValidatorUpdates[1], want[1]) {
		t.Fatalf("replay differs: %+v", again)
	}
	log, err := store.LoadValidatorRotations()
	if err != nil || len(log.Rotations) != 1 || log.Rotations[0].Height != 40 {
		t.Fatalf("log after replay: (%+v, %v)", log, err)
	}

	// The same rotation in a later block is not a replay: refused.
	if later := finalize(t, app, 41, abcitypes.CommitInfo{}, tx); later.TxResults[0].Code == 0 || len(later.ValidatorUpdates) != 0 {
		t.Fatal("a rotation was accepted twice")
	}
}

func TestOneRotationPerBlockAndTheNextOnlyAfterAdoption(t *testing.T) {
	f := newRotationFixture()
	app, store := rotationApp(t, f)
	a, b := seededKey(0x81), seededKey(0x82)
	first := rotJSON(t, f.rotation(1, f.validators[0], a, "ops-1", "ops-2"))
	second := rotJSON(t, f.rotation(2, f.validators[1], b, "ops-1", "ops-2"))

	resp := finalize(t, app, 10, abcitypes.CommitInfo{}, first, second)
	if resp.TxResults[0].Code != 0 || resp.TxResults[1].Code == 0 || len(resp.ValidatorUpdates) != 2 {
		t.Fatalf("two rotations in one block: %+v", resp.TxResults)
	}
	if r := finalize(t, app, 13, signedBy(f.validators[2:]...), second); r.TxResults[0].Code == 0 {
		t.Fatal("the next rotation was accepted before the first new key signed anything")
	}
	// Block 14 carries a commit the new key signed: adopted, and from here the next rotation is accepted.
	finalize(t, app, 14, signedBy(append([]ed25519.PrivateKey{a}, f.validators[1:]...)...))
	log, _ := store.LoadValidatorRotations()
	if log.Rotations[0].AdoptedHeight != 14 {
		t.Fatalf("adoption not recorded: %+v", log.Rotations[0])
	}
	if r := finalize(t, app, 15, abcitypes.CommitInfo{}, second); r.TxResults[0].Code != 0 {
		t.Fatalf("after adoption: %s", r.TxResults[0].Log)
	}
}

// The state is stamped v7 until the chain accepts a rotation - so the v7 binary can still start on it - and
// v8 from then on.
func TestTheStampIsTheLowestRulesThatReproduceTheChain(t *testing.T) {
	f := newRotationFixture()
	app, store := rotationApp(t, f)
	commit := func(h int64, txs ...[]byte) uint64 {
		finalize(t, app, h, abcitypes.CommitInfo{}, txs...)
		if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err != nil {
			t.Fatal(err)
		}
		st, err := store.LoadABCIState()
		if err != nil {
			t.Fatal(err)
		}
		return st.ExecutionRulesVersion
	}
	if v := commit(1); v != executionRulesV7 {
		t.Fatalf("no rotation yet, stamped v%d", v)
	}
	if v := commit(2, rotJSON(t, f.rotation(1, f.validators[6], seededKey(0x90), "ops-1", "ops-3"))); v != executionRulesV8 {
		t.Fatalf("after a rotation, stamped v%d", v)
	}
}

// The possession proof and the admin digest are different messages over the same fields.
func TestPossessionAndAdminDigestsDiffer(t *testing.T) {
	r := newRotationFixture().rotation(1, seededKey(1), seededKey(2))
	if bytes.Equal(r.PossessionBytes(), r.SigningBytes()) {
		t.Fatal("the possession proof signs the admin digest")
	}
	if h := sha256.Sum256(nil); bytes.Equal(r.SigningBytes(), h[:]) {
		t.Fatal("empty digest")
	}
}

// A tick makes a block and nothing else: accepted, no app-hash contribution, no validator update. A
// malformed one is refused, identically on every node.
func TestATickChangesNothing(t *testing.T) {
	app, _ := rotationApp(t, newRotationFixture())
	empty := finalize(t, app, 5, abcitypes.CommitInfo{})
	tick := rotJSON(t, ChainTickTx{Kind: ChainTickKind, Nonce: "00112233445566778899aabbccddeeff"})
	resp := finalize(t, app, 5, abcitypes.CommitInfo{}, tick)
	if resp.TxResults[0].Code != 0 || !bytes.Equal(resp.AppHash, empty.AppHash) || len(resp.ValidatorUpdates) != 0 {
		t.Fatalf("tick: %+v", resp)
	}
	for _, bad := range []ChainTickTx{{Kind: ChainTickKind, Nonce: "00"}, {Kind: ChainTickKind, Nonce: "zz112233445566778899"}} {
		if r := finalize(t, app, 5, abcitypes.CommitInfo{}, rotJSON(t, bad)); r.TxResults[0].Code == 0 {
			t.Fatalf("malformed tick %q accepted", bad.Nonce)
		}
		if c, _ := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: rotJSON(t, bad)}); c.Code == 0 {
			t.Fatalf("malformed tick %q admitted to the mempool", bad.Nonce)
		}
	}
}

// The golden rotation (testdata/rotation_v1_golden.json) - the vector the pre-rotation binary was shown
// to refuse - is accepted and moves the set. It pins the wire format and both signing digests.
func TestTheGoldenRotationMovesTheSet(t *testing.T) {
	f := newRotationFixture()
	app, _ := rotationApp(t, f)
	tx, err := os.ReadFile("testdata/rotation_v1_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	resp := finalize(t, app, 40, abcitypes.CommitInfo{}, tx)
	if resp.TxResults[0].Code != 0 || len(resp.ValidatorUpdates) != 2 {
		t.Fatalf("golden rotation: %d %s, %d updates", resp.TxResults[0].Code, resp.TxResults[0].Log, len(resp.ValidatorUpdates))
	}
	if !bytes.Equal(tx, rotJSON(t, f.rotation(1, f.validators[4], seededKey(0x77), "ops-1", "ops-2"))) {
		t.Fatal("the wire format or a signing digest changed: the golden rotation no longer reproduces")
	}
}
