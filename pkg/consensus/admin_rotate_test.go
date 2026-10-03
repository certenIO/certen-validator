package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// RB5-F37, rules v12: the admin quorum in force rotates the admin set.

// adminKeys is a test admin set's private keys by id.
type adminKeys map[string]ed25519.PrivateKey

func (k adminKeys) public() map[string]string {
	out := make(map[string]string, len(k))
	for id, priv := range k {
		out[id] = pubHex(priv)
	}
	return out
}

// adminRotation builds the rotation at seq, against the set whose id is current, installing to at threshold, with
// every new key's proof of possession and no admin signature.
func adminRotation(seq uint64, current string, to adminKeys, threshold int) *AdminRotateTx {
	tx := &AdminRotateTx{Kind: AdminRotateKind, ChainID: rotChain, Sequence: seq, CurrentSetID: current,
		NewAdminKeys: to.public(), NewThreshold: threshold}
	tx.prove(to)
	return tx
}

// prove (re)signs every new key's proof of possession.
func (t *AdminRotateTx) prove(to adminKeys) {
	t.Possession = nil
	for _, id := range sortedAdminIDs(t.NewAdminKeys) {
		t.Possession = append(t.Possession, PolicySignature{KeyID: id,
			Signature: hex.EncodeToString(ed25519.Sign(to[id], t.PossessionBytes()))})
	}
}

// signedBy adds the named admins' signatures and returns the transaction.
func (t *AdminRotateTx) signedBy(keys adminKeys, ids ...string) *AdminRotateTx {
	for _, id := range ids {
		t.Signatures = append(t.Signatures, PolicySignature{KeyID: id,
			Signature: hex.EncodeToString(ed25519.Sign(keys[id], t.SigningBytes()))})
	}
	return t
}

// setB is the set the tests rotate the fixture's admins to: two new keys and ops-3 kept, threshold 2.
func setB(f *rotationFixture) adminKeys {
	return adminKeys{"new-a": seededKey(0xD1), "new-b": seededKey(0xD2), "ops-3": f.admins["ops-3"]}
}

func genesisSetID(f *rotationFixture) string {
	return AdminSetID(f.policy.AdminKeys, f.policy.AdminThreshold)
}

// The canonical encodings are pinned against an independent computation (a shell script: printf of each field's
// 4-byte big-endian length and bytes, piped to sha256sum).
func TestTheAdminRotationEncodingIsPinned(t *testing.T) {
	a, b, c := strings.Repeat("11", 32), strings.Repeat("22", 32), strings.Repeat("33", 32)
	cur := AdminSetID(map[string]string{"a": a, "b": b}, 2)
	if cur != "ac323b69aa364d7a46aa43871716a7a7a244c7ee78c8866092d79cb177b09cea" {
		t.Fatalf("admin set id %s", cur)
	}
	tx := &AdminRotateTx{Kind: AdminRotateKind, ChainID: "certen-testnet", Sequence: 1, CurrentSetID: cur,
		NewAdminKeys: map[string]string{"c": c, "a": a, "b": b}, NewThreshold: 2}
	if got := tx.NewSetID(); got != "3af00e71a0836a0c2024c6a28f393466d56042b8302019d15c9814c5ed94bd0b" {
		t.Fatalf("new set id %s", got)
	}
	if got := hex.EncodeToString(tx.SigningBytes()); got != "a26e10c46f2ca5dbd279288b87d1e4dc537e5698ab5f9367da38dd0b157d846d" {
		t.Fatalf("signing bytes %s", got)
	}
	if got := hex.EncodeToString(tx.PossessionBytes()); got != "ddc1ed00da25b7fb3808d929d9d790a4b70fd20ac16a3927cb57940c26cf2c92" {
		t.Fatalf("possession bytes %s", got)
	}
	if tx.RotationID() != "admin-rotation:a26e10c46f2ca5dbd279288b87d1e4dc537e5698ab5f9367da38dd0b157d846d" {
		t.Fatalf("rotation id %s", tx.RotationID())
	}
	// Threshold and membership are both bound: changing either changes the set id.
	if AdminSetID(map[string]string{"a": a, "b": b}, 1) == cur || AdminSetID(map[string]string{"a": a, "c": b}, 2) == cur {
		t.Fatal("the set id does not bind the threshold and the key ids")
	}
	// The wire round trip keeps every field, and another kind is not this one.
	back, ok := DecodeAdminRotate(rotJSON(t, tx))
	if !ok || back.RotationID() != tx.RotationID() {
		t.Fatal("the rotation does not survive the wire")
	}
	if _, ok := DecodeAdminRotate([]byte(fmt.Sprintf(`{"kind":%q}`, AdminResealKind))); ok {
		t.Fatal("a re-seal decoded as an admin rotation")
	}
	if r, ok := DecodeAdminRotate([]byte(fmt.Sprintf(`{"kind":%q,"sequence":"one"}`, AdminRotateKind))); !ok || r.CheckShape() == nil {
		t.Fatal("malformed bytes of the kind are not the kind, refused")
	}
}

// A rotation needs everything it claims: the threshold of distinct current admins, the chain, the next sequence, the
// set in force, every new key's possession, and a shape that never makes one key of several sufficient.
func TestAnAdminRotationNeedsEverythingItClaims(t *testing.T) {
	f := newRotationFixture()
	b := setB(f)
	cur := genesisSetID(f)
	good := func() *AdminRotateTx { return adminRotation(1, cur, b, 2).signedBy(f.admins, "ops-1", "ops-2") }
	if err := VerifyAdminRotate(good(), rotChain, f.policy, 10); err != nil {
		t.Fatalf("a well-formed rotation: %v", err)
	}
	// Signed by ops-3 too, which stays: still one signer each.
	if err := VerifyAdminRotate(adminRotation(1, cur, b, 2).signedBy(f.admins, "ops-3", "ops-1"), rotChain, f.policy, 10); err != nil {
		t.Fatalf("signed by a kept admin: %v", err)
	}
	// Explicitly a single key: allowed.
	solo := adminKeys{"solo": seededKey(0xD9)}
	if err := VerifyAdminRotate(adminRotation(1, cur, solo, 1).signedBy(f.admins, "ops-1", "ops-2"), rotChain, f.policy, 10); err != nil {
		t.Fatalf("a single-key set: %v", err)
	}

	otherSet := AdminSetID(map[string]string{"x": pubHex(seededKey(0xEE))}, 1)
	refused := map[string]*AdminRotateTx{
		"one admin of two":     adminRotation(1, cur, b, 2).signedBy(f.admins, "ops-1"),
		"the same admin twice": adminRotation(1, cur, b, 2).signedBy(f.admins, "ops-1", "ops-1"),
		"a new key signing as an admin": adminRotation(1, cur, b, 2).signedBy(f.admins, "ops-1").
			signedBy(adminKeys{"new-a": b["new-a"]}, "new-a"),
		"a foreign key under an admin's id": adminRotation(1, cur, b, 2).signedBy(f.admins, "ops-1").
			signedBy(adminKeys{"ops-2": seededKey(0xEE)}, "ops-2"),
		"another chain": func() *AdminRotateTx {
			r := adminRotation(1, cur, b, 2)
			r.ChainID = "another-chain"
			r.prove(b)
			return r.signedBy(f.admins, "ops-1", "ops-2")
		}(),
		"a sequence ahead":            adminRotation(2, cur, b, 2).signedBy(f.admins, "ops-1", "ops-2"),
		"a sequence already used (0)": adminRotation(0, cur, b, 2).signedBy(f.admins, "ops-1", "ops-2"),
		"made against another set":    adminRotation(1, otherSet, b, 2).signedBy(f.admins, "ops-1", "ops-2"),
		"a missing proof of possession": func() *AdminRotateTx {
			r := good()
			r.Possession = r.Possession[1:]
			return r
		}(),
		"a proof of possession by another key": func() *AdminRotateTx {
			r := good()
			r.Possession[0].Signature = hex.EncodeToString(ed25519.Sign(seededKey(0xEE), r.PossessionBytes()))
			return r
		}(),
		"an approval used as a proof of possession": func() *AdminRotateTx {
			r := good()
			id := r.Possession[0].KeyID
			r.Possession[0].Signature = hex.EncodeToString(ed25519.Sign(b[id], r.SigningBytes()))
			return r
		}(),
		"a proof for a key not in the set": func() *AdminRotateTx {
			r := good()
			r.Possession = append(r.Possession, PolicySignature{KeyID: "stranger",
				Signature: hex.EncodeToString(ed25519.Sign(seededKey(0xEE), r.PossessionBytes()))})
			return r
		}(),
		"an unreachable threshold":  adminRotation(1, cur, b, 4).signedBy(f.admins, "ops-1", "ops-2"),
		"one of several keys alone": adminRotation(1, cur, b, 1).signedBy(f.admins, "ops-1", "ops-2"),
		"threshold zero":            adminRotation(1, cur, solo, 0).signedBy(f.admins, "ops-1", "ops-2"),
		"one key under two ids": adminRotation(1, cur, adminKeys{"k1": seededKey(0xD5), "k2": seededKey(0xD5)}, 2).
			signedBy(f.admins, "ops-1", "ops-2"),
		"a key in uppercase hex": func() *AdminRotateTx {
			r := adminRotation(1, cur, b, 2)
			r.NewAdminKeys["new-a"] = strings.ToUpper(r.NewAdminKeys["new-a"])
			r.prove(adminKeys{"new-a": b["new-a"], "new-b": b["new-b"], "ops-3": b["ops-3"]})
			return r.signedBy(f.admins, "ops-1", "ops-2")
		}(),
		"a key id that is not a plain name": adminRotation(1, cur, adminKeys{"new a": seededKey(0xD6), "new-b": seededKey(0xD7)}, 2).
			signedBy(f.admins, "ops-1", "ops-2"),
		"no keys": adminRotation(1, cur, adminKeys{}, 1).signedBy(f.admins, "ops-1", "ops-2"),
		"the set in force again": adminRotation(1, cur, adminKeys{"ops-1": f.admins["ops-1"], "ops-2": f.admins["ops-2"],
			"ops-3": f.admins["ops-3"]}, 2).signedBy(f.admins, "ops-1", "ops-2"),
		"signatures over another new set": func() *AdminRotateTx {
			r := good()
			swapped := adminKeys{"new-a": seededKey(0xD8), "new-b": b["new-b"], "ops-3": b["ops-3"]}
			r.NewAdminKeys = swapped.public()
			r.prove(swapped)
			return r
		}(),
	}
	for name, r := range refused {
		if err := VerifyAdminRotate(r, rotChain, f.policy, 10); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := VerifyAdminRotate(good(), rotChain, nil, 10); err == nil {
		t.Error("accepted on a chain with no sealed policy")
	}
	if err := VerifyAdminRotate(good(), rotChain, &ledger.EntitlementPolicyState{Mode: "off"}, 10); err == nil {
		t.Error("accepted on a chain that sealed no admin quorum")
	}
	if err := VerifyAdminRotate(good(), "another-chain", f.policy, 10); err == nil {
		t.Error("accepted on another chain")
	}
}

// From a recorded change on, the set in force is the new one, the next sequence is 2, and a key that left can never
// come back.
func TestAfterARotationTheNewSetGovernsAndRetiredKeysStayOut(t *testing.T) {
	f := newRotationFixture()
	b := setB(f)
	state := *f.policy
	state.AdminReseals = []ledger.AdminReseal{{Height: 5, ID: "admin-rotation:x", Keys: b.public(), Threshold: 2,
		Kind: AdminRotateKind, Sequence: 1}}
	setBID := AdminSetID(b.public(), 2)
	if NextAdminSequence(&state, 5) != 1 || NextAdminSequence(&state, 6) != 2 {
		t.Fatal("the sequence does not count the changes below the height")
	}
	c := adminKeys{"c-1": seededKey(0xE1), "c-2": seededKey(0xE2), "new-b": b["new-b"]}
	if err := VerifyAdminRotate(adminRotation(2, setBID, c, 2).signedBy(b, "new-a", "ops-3"), rotChain, &state, 6); err != nil {
		t.Fatalf("the next rotation by the set in force: %v", err)
	}
	for name, r := range map[string]*AdminRotateTx{
		"signed by the old set":       adminRotation(2, setBID, c, 2).signedBy(f.admins, "ops-1", "ops-2"),
		"made against the old set":    adminRotation(2, genesisSetID(f), c, 2).signedBy(b, "new-a", "ops-3"),
		"the first sequence replayed": adminRotation(1, setBID, c, 2).signedBy(b, "new-a", "ops-3"),
		"a retired key coming back": adminRotation(2, setBID, adminKeys{"c-1": seededKey(0xE1), "back": f.admins["ops-1"]}, 2).
			signedBy(b, "new-a", "ops-3"),
	} {
		if err := VerifyAdminRotate(r, rotChain, &state, 6); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// At the change's own height the old set is still in force.
	if err := VerifyAdminRotate(adminRotation(1, genesisSetID(f), b, 2).signedBy(f.admins, "ops-1", "ops-2"), rotChain, &state, 5); err != nil {
		t.Fatalf("at the change's own height: %v", err)
	}
}

// Through FinalizeBlock: accepted at height H, the new set authorises from H+1 - not in block H - and the old one no
// longer does, for every admin-signed kind: the BLS registry, a validator rotation, a policy update and the next admin
// rotation. Replay of each block decides it identically.
func TestAnAdminRotationTakesEffectFromTheNextHeight(t *testing.T) {
	f := newRegistryFixture(t)
	app, store := rotationApp(t, f.rotationFixture)
	b := setB(f.rotationFixture)
	registryBy := func(version uint64, keys adminKeys, ids ...string) []byte {
		tx := f.registry(version)
		for _, id := range ids {
			tx.Signatures = append(tx.Signatures, PolicySignature{KeyID: id, Signature: hex.EncodeToString(ed25519.Sign(keys[id], tx.SigningBytes()))})
		}
		return rotJSON(t, tx)
	}
	step := func(h int64, want []uint32, txs ...[]byte) *abcitypes.ResponseFinalizeBlock {
		t.Helper()
		resp := finalize(t, app, h, abcitypes.CommitInfo{}, txs...)
		again := finalize(t, app, h, abcitypes.CommitInfo{}, txs...)
		if !bytes.Equal(resp.AppHash, again.AppHash) {
			t.Fatalf("block %d: replay changed the app hash", h)
		}
		for i := range want {
			if resp.TxResults[i].Code != want[i] {
				t.Fatalf("block %d tx %d: code %d (%s), want %d", h, i, resp.TxResults[i].Code, resp.TxResults[i].Log, want[i])
			}
			if again.TxResults[i].Code != resp.TxResults[i].Code || again.TxResults[i].Log != resp.TxResults[i].Log {
				t.Fatalf("block %d tx %d: replay decided it differently: %d %q vs %d %q", h, i,
					again.TxResults[i].Code, again.TxResults[i].Log, resp.TxResults[i].Code, resp.TxResults[i].Log)
			}
		}
		if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// refusedAt executes a block at h carrying only tx, twice, and requires code each time; nothing is committed.
	refusedAt := func(h int64, code uint32, tx []byte) {
		t.Helper()
		for run := 0; run < 2; run++ {
			if r := finalize(t, app, h, abcitypes.CommitInfo{}, tx); r.TxResults[0].Code != code {
				t.Fatalf("block %d run %d: code %d (%s), want %d", h, run, r.TxResults[0].Code, r.TxResults[0].Log, code)
			}
		}
	}

	if app.committedRulesVersion() >= executionRulesV12 {
		t.Fatal("the state is v12's before any admin rotation")
	}
	rot := adminRotation(1, genesisSetID(f.rotationFixture), b, 2).signedBy(f.admins, "ops-1", "ops-2")
	// Block 1: the rotation; a registry signed by the NEW set is still judged by the old set in force for block 1.
	resp := step(1, []uint32{0, codeBLSRegistryRefused}, rotJSON(t, rot), registryBy(1, b, "new-a", "new-b"))
	without := finalize(t, newRotationAppFor(t, f.rotationFixture), 1, abcitypes.CommitInfo{}, registryBy(1, b, "new-a", "new-b"))
	if bytes.Equal(without.AppHash, resp.AppHash) {
		t.Fatal("the rotation is not in the app hash")
	}
	st, _ := store.LoadEntitlementPolicy()
	if len(st.AdminReseals) != 1 || st.AdminReseals[0].Height != 1 || st.AdminReseals[0].Kind != AdminRotateKind ||
		st.AdminReseals[0].Sequence != 1 || st.AdminReseals[0].ID != rot.RotationID() {
		t.Fatalf("recorded %+v", st.AdminReseals)
	}
	if !sameKeysAndThreshold(st.AdminKeys, st.AdminThreshold, f.policy.AdminKeys, f.policy.AdminThreshold) {
		t.Fatal("the genesis seal changed")
	}
	if app.committedRulesVersion() != executionRulesV12 {
		t.Fatalf("after an admin rotation the state is stamped v%d", app.committedRulesVersion())
	}

	// Block 2: the registry - the old set refused, the new set accepted.
	refusedAt(2, codeBLSRegistryRefused, registryBy(1, f.admins, "ops-1", "ops-2"))
	step(2, []uint32{0}, registryBy(1, b, "new-a", "ops-3"))
	// Block 3: a validator rotation.
	vr := func(keys adminKeys, ids ...string) []byte {
		r := f.rotation(1, f.validators[6], seededKey(0x92))
		for _, id := range ids {
			r.Signatures = append(r.Signatures, PolicySignature{KeyID: id, Signature: hex.EncodeToString(ed25519.Sign(keys[id], r.SigningBytes()))})
		}
		return rotJSON(t, r)
	}
	refusedAt(3, 6, vr(f.admins, "ops-1", "ops-2"))
	step(3, []uint32{0}, vr(b, "new-b", "ops-3"))
	// Block 4: a policy update.
	pu := func(keys adminKeys, ids ...string) []byte {
		u := &PolicyUpdateTx{Kind: PolicyUpdateKind, ChainID: rotChain, Mode: string(EntitlementOff),
			ActivationUnix: 1_800_000_004 + MinActivationDelay + 60, Version: 1}
		for _, id := range ids {
			u.Signatures = append(u.Signatures, PolicySignature{KeyID: id, Signature: hex.EncodeToString(ed25519.Sign(keys[id], u.SigningBytes()))})
		}
		return rotJSON(t, u)
	}
	refusedAt(4, 5, pu(f.admins, "ops-2", "ops-3"))
	step(4, []uint32{0}, pu(b, "new-a", "new-b"))

	// Block 5: the next admin rotation - by the old set refused, by the new set accepted (chained).
	c := adminKeys{"c-1": seededKey(0xE1), "c-2": seededKey(0xE2), "c-3": seededKey(0xE3)}
	setBID := AdminSetID(b.public(), 2)
	step(5, []uint32{codeAdminRotateRefused, 0}, rotJSON(t, adminRotation(2, setBID, c, 2).signedBy(f.admins, "ops-1", "ops-2")),
		rotJSON(t, adminRotation(2, setBID, c, 2).signedBy(b, "new-a", "new-b")))
	// Block 6: the old rotation again (a replay in a later block), and two changes in one block - the second refused.
	setCID := AdminSetID(c.public(), 2)
	d := adminKeys{"d-1": seededKey(0xF1), "d-2": seededKey(0xF2)}
	e := adminKeys{"e-1": seededKey(0xF3), "e-2": seededKey(0xF4)}
	resp = step(6, []uint32{codeAdminRotateRefused, 0, codeAdminRotateRefused}, rotJSON(t, rot),
		rotJSON(t, adminRotation(3, setCID, d, 2).signedBy(c, "c-1", "c-3")),
		rotJSON(t, adminRotation(4, AdminSetID(d.public(), 2), e, 2).signedBy(d, "d-1", "d-2")))
	if !strings.Contains(resp.TxResults[0].Log, "sequence 1 is not the next") || !strings.Contains(resp.TxResults[2].Log, "one admin-set change per block") {
		t.Fatalf("refusals: %q / %q", resp.TxResults[0].Log, resp.TxResults[2].Log)
	}
	st, _ = store.LoadEntitlementPolicy()
	if len(st.AdminReseals) != 3 {
		t.Fatalf("%d changes recorded, want 3", len(st.AdminReseals))
	}
	if keys, th := AdminSetAt(st, 7); !sameKeysAndThreshold(keys, th, d.public(), 2) {
		t.Fatal("the set in force after three rotations is not the last one")
	}
	if keys, th := AdminSetAt(st, 6); !sameKeysAndThreshold(keys, th, c.public(), 2) {
		t.Fatal("the set in force in block 6 is not the one block 5 installed")
	}
}

// newRotationAppFor is a second app on the same fixture, for comparing app hashes.
func newRotationAppFor(t *testing.T, f *rotationFixture) *ValidatorApp {
	app, _ := rotationApp(t, f)
	return app
}

// A block whose first rotation is refused and second accepted - and the reverse - is decided identically however
// often it is executed: the same codes, the same logs, the same app hash.
func TestABlockOfAdminRotationsIsDeterministic(t *testing.T) {
	f := newRotationFixture()
	b := setB(f)
	cur := genesisSetID(f)
	bad := rotJSON(t, adminRotation(1, cur, b, 2).signedBy(f.admins, "ops-1"))
	good := rotJSON(t, adminRotation(1, cur, b, 2).signedBy(f.admins, "ops-1", "ops-2"))
	for name, txs := range map[string][][]byte{"refused then accepted": {bad, good}, "accepted then refused": {good, bad}} {
		app, _ := rotationApp(t, f)
		first := finalize(t, app, 1, abcitypes.CommitInfo{}, txs...)
		for run := 0; run < 3; run++ {
			again := finalize(t, app, 1, abcitypes.CommitInfo{}, txs...)
			if !bytes.Equal(again.AppHash, first.AppHash) {
				t.Fatalf("%s: run %d changed the app hash", name, run)
			}
			for i := range txs {
				if again.TxResults[i].Code != first.TxResults[i].Code || again.TxResults[i].Log != first.TxResults[i].Log {
					t.Fatalf("%s: run %d tx %d: %d %q, first %d %q", name, run, i, again.TxResults[i].Code,
						again.TxResults[i].Log, first.TxResults[i].Code, first.TxResults[i].Log)
				}
			}
		}
		codes := []uint32{first.TxResults[0].Code, first.TxResults[1].Code}
		if (name == "refused then accepted" && (codes[0] != codeAdminRotateRefused || codes[1] != 0)) ||
			(name == "accepted then refused" && (codes[0] != 0 || codes[1] != codeAdminRotateRefused)) {
			t.Fatalf("%s: codes %v", name, codes)
		}
		// A second, independent node executing the block reaches the same app hash.
		other, _ := rotationApp(t, f)
		if h := finalize(t, other, 1, abcitypes.CommitInfo{}, txs...).AppHash; !bytes.Equal(h, first.AppHash) {
			t.Fatalf("%s: two nodes disagree", name)
		}
	}
}

// The re-seal and an admin rotation are both admin-set changes: one per block, the sequence counts the re-seal, and
// the re-seal is refused - by name - once any change is recorded.
func TestTheReSealAndAdminRotationsShareOneRecord(t *testing.T) {
	f := newRegistryFixture(t)
	from, to, newAdmins := resealSets(f.rotationFixture)
	lost, installed := lostAdminSet, resealedAdminSet
	lostAdminSet, resealedAdminSet = from, to
	defer func() { lostAdminSet, resealedAdminSet = lost, installed }()

	app, store := rotationApp(t, f.rotationFixture)
	b := setB(f.rotationFixture)
	reseal := rotJSON(t, resealFor(to, rotChain))
	resp := finalize(t, app, 1, abcitypes.CommitInfo{}, reseal,
		rotJSON(t, adminRotation(1, genesisSetID(f.rotationFixture), b, 2).signedBy(f.admins, "ops-1", "ops-2")))
	if resp.TxResults[0].Code != 0 || resp.TxResults[1].Code != codeAdminRotateRefused ||
		!strings.Contains(resp.TxResults[1].Log, "one admin-set change per block") {
		t.Fatalf("a re-seal and a rotation in one block: %d / %d %s", resp.TxResults[0].Code, resp.TxResults[1].Code, resp.TxResults[1].Log)
	}
	if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err != nil {
		t.Fatal(err)
	}
	// The re-sealed set rotates, at sequence 2: the re-seal was change 1.
	resealedID := AdminSetID(to.Keys, to.Threshold)
	fresh := adminKeys{"new-a": seededKey(0xD1), "new-b": seededKey(0xD2), "new-c": seededKey(0xD3)}
	if r := finalize(t, app, 2, abcitypes.CommitInfo{}, rotJSON(t, adminRotation(1, resealedID, fresh, 2).signedBy(newAdmins, "admin-a", "admin-b"))); r.TxResults[0].Code != codeAdminRotateRefused {
		t.Fatal("sequence 1 accepted after the re-seal")
	}
	if r := finalize(t, app, 2, abcitypes.CommitInfo{}, rotJSON(t, adminRotation(2, resealedID, fresh, 2).signedBy(newAdmins, "admin-a", "admin-c"))); r.TxResults[0].Code != 0 {
		t.Fatalf("the re-sealed set's rotation: %s", r.TxResults[0].Log)
	}
	st, _ := store.LoadEntitlementPolicy()
	if len(st.AdminReseals) != 2 || st.AdminReseals[0].Kind != "" || st.AdminReseals[1].Sequence != 2 {
		t.Fatalf("records %+v", st.AdminReseals)
	}

	// A chain that rotated first: the re-seal is refused, and the refusal says a rotation changed the set.
	f2 := newRegistryFixture(t)
	app2, _ := rotationApp(t, f2.rotationFixture)
	finalize(t, app2, 1, abcitypes.CommitInfo{}, rotJSON(t, adminRotation(1, genesisSetID(f2.rotationFixture), setB(f2.rotationFixture), 2).
		signedBy(f2.admins, "ops-1", "ops-2")))
	r := finalize(t, app2, 2, abcitypes.CommitInfo{}, reseal)
	if r.TxResults[0].Code != codeAdminResealRefused || !strings.Contains(r.TxResults[0].Log, "changed by an admin rotation at height 1") {
		t.Fatalf("a re-seal after a rotation: %d %s", r.TxResults[0].Code, r.TxResults[0].Log)
	}
}

// The mempool filters on shape and possession; an admin rotation is never read back as a ValidatorBlock, and a block
// carrying one is not refused as a proposal.
func TestCheckTxFiltersAdminRotations(t *testing.T) {
	f := newRotationFixture()
	app, _ := rotationApp(t, f)
	b := setB(f)
	good := adminRotation(1, genesisSetID(f), b, 2).signedBy(f.admins, "ops-1", "ops-2")
	noPossession := adminRotation(1, genesisSetID(f), b, 2).signedBy(f.admins, "ops-1", "ops-2")
	noPossession.Possession = nil
	for name, c := range map[string]struct {
		tx   []byte
		code uint32
	}{
		"well formed":         {rotJSON(t, good), 0},
		"without possession":  {rotJSON(t, noPossession), codeAdminRotateRefused},
		"malformed, the kind": {[]byte(fmt.Sprintf(`{"kind":%q,"new_threshold":"two"}`, AdminRotateKind)), codeAdminRotateRefused},
	} {
		res, err := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: c.tx})
		if err != nil || res.Code != c.code {
			t.Errorf("%s: (%+v, %v), want code %d", name, res, err, c.code)
		}
	}
	if isValidatorBlockTx(rotJSON(t, good)) {
		t.Fatal("an admin rotation is read back as a ValidatorBlock")
	}
	pp, err := app.ProcessProposal(context.Background(), &abcitypes.RequestProcessProposal{Txs: [][]byte{rotJSON(t, good)}})
	if err != nil || pp.Status != abcitypes.ResponseProcessProposal_ACCEPT {
		t.Fatalf("a proposal carrying an admin rotation: (%v, %v)", pp, err)
	}
}

// History: a committed admin-rotation-kind transaction v11 decided as a ValidatorBlock is history v12 does not reproduce,
// and the node refuses to start on it - also when an older binary already indexed the block, which the committed-
// operation index alone never re-reads. One decided as an admin rotation makes the state v12's.
func TestCommittedAdminRotationHistoryIsChecked(t *testing.T) {
	f := newRotationFixture()
	rotation := rotJSON(t, adminRotation(1, genesisSetID(f), setB(f), 2).signedBy(f.admins, "ops-1", "ops-2"))
	hist := func(code uint32) *fakeHistory {
		return &fakeHistory{base: 1, blocks: map[int64][][]byte{1: {rotation}}, times: map[int64]time.Time{1: beforeV9},
			codes: map[int64][]uint32{1: {code}}}
	}
	for _, code := range []uint32{1, 2, 3, 4, 0} {
		err := historyApp(t, 1).IndexCommittedHistory(hist(code))
		if !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) {
			t.Fatalf("an admin rotation decided with code %d (and none recorded): %v", code, err)
		}
	}
	// The same history, already indexed by the v11 binary that committed it.
	indexed := historyApp(t, 1)
	if err := indexed.ledgerStore.RecordCommittedBlock(1, nil); err != nil {
		t.Fatal(err)
	}
	if err := indexed.IndexCommittedHistory(hist(2)); !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) {
		t.Fatalf("an already-indexed chain with an admin rotation decided as a ValidatorBlock: %v", err)
	}
	// Decided as an admin rotation: refused (code 12), or accepted and recorded.
	app := historyApp(t, 1)
	if err := app.IndexCommittedHistory(hist(codeAdminRotateRefused)); err != nil {
		t.Fatalf("an admin rotation refused by v12: %v", err)
	}
	if app.committedRulesVersion() != executionRulesV12 {
		t.Fatalf("a committed admin-rotation verdict left the state stamped v%d", app.committedRulesVersion())
	}
	accepted := historyApp(t, 1)
	tx, _ := DecodeAdminRotate(rotation)
	policy := *f.policy
	policy.AdminReseals = []ledger.AdminReseal{{Height: 1, ID: tx.RotationID(), Keys: tx.NewAdminKeys, Threshold: 2,
		Kind: AdminRotateKind, Sequence: 1}}
	if err := accepted.ledgerStore.SaveEntitlementPolicy(&policy); err != nil {
		t.Fatal(err)
	}
	if err := accepted.IndexCommittedHistory(hist(0)); err != nil {
		t.Fatalf("an admin rotation accepted and recorded by v12: %v", err)
	}
	// Checked once: the watermark covers the chain, and a second start reads nothing.
	if through, err := accepted.ledgerStore.KindsCheckedThrough(CurrentExecutionRulesVersion); err != nil || through != 1 {
		t.Fatalf("kinds checked through %d, %v", through, err)
	}
	if err := accepted.IndexCommittedHistory(&fakeHistory{base: 1}); err != nil {
		t.Fatalf("a checked chain was read again: %v", err)
	}
}

// Every block this binary commits advances the kinds watermark: it decided them.
func TestCommitAdvancesTheKindsWatermark(t *testing.T) {
	app := newPersistTestApp(t)
	for h := int64(1); h <= 3; h++ {
		commitBlock(t, app, nil, h, beforeV9)
	}
	if through, err := app.ledgerStore.KindsCheckedThrough(CurrentExecutionRulesVersion); err != nil || through != 3 {
		t.Fatalf("kinds checked through %d, %v", through, err)
	}
}

// /certen/admin_set answers what a tool needs to make and judge the next rotation: the set in force for the next block,
// its id, the next sequence and every change - and a rotation the view's Policy accepts is one the chain accepts.
func TestTheAdminSetQuery(t *testing.T) {
	f := newRotationFixture()
	app, _ := rotationApp(t, f)
	b := setB(f)
	view := func() *AdminSetView {
		t.Helper()
		res, err := app.Query(context.Background(), &abcitypes.RequestQuery{Path: "/certen/admin_set"})
		if err != nil || res.Code != 0 {
			t.Fatalf("query: (%+v, %v)", res, err)
		}
		var v AdminSetView
		if err := json.Unmarshal(res.Value, &v); err != nil {
			t.Fatal(err)
		}
		return &v
	}
	v := view()
	if v.InForceSetID != genesisSetID(f) || v.NextSequence != 1 || len(v.Changes) != 0 {
		t.Fatalf("before any rotation: %+v", v)
	}
	rot := adminRotation(v.NextSequence, v.InForceSetID, b, 2).signedBy(f.admins, "ops-2", "ops-3")
	if err := VerifyAdminRotate(rot, rotChain, v.Policy(), v.Height+1); err != nil {
		t.Fatalf("the view's policy refuses what the chain accepts: %v", err)
	}
	finalize(t, app, 1, abcitypes.CommitInfo{}, rotJSON(t, rot))
	// Mid-block (finalized, not committed) the view still answers for the committed height.
	if mid := view(); mid.InForceSetID != genesisSetID(f) || mid.NextSequence != 1 {
		t.Fatalf("before Commit: %+v", mid)
	}
	if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err != nil {
		t.Fatal(err)
	}
	if v = view(); v.InForceSetID != AdminSetID(b.public(), 2) || v.NextSequence != 2 || len(v.Changes) != 1 || v.Height != 1 {
		t.Fatalf("after the rotation: %+v", v)
	}
}

// certen-testnet's admin sets - the lost genesis pair and the re-seal's three - name distinct keys, so counting
// distinct keys from v12 on changes no verdict its history holds (checkAdminKeyCountingContinuity).
func TestCertenTestnetAdminSetsNameDistinctKeys(t *testing.T) {
	state := &ledger.EntitlementPolicyState{AdminKeys: lostAdminSet.Keys, AdminThreshold: lostAdminSet.Threshold,
		AdminReseals: []ledger.AdminReseal{{Height: 2788, Keys: resealedAdminSet.Keys, Threshold: resealedAdminSet.Threshold}}}
	if found := adminSetsRepeatingAKey(state); len(found) != 0 {
		t.Fatalf("certen-testnet's admin sets repeat a key: %v", found)
	}
	if err := checkAdminKeyCountingContinuity(executionRulesV11, state); err != nil {
		t.Fatal(err)
	}
}
