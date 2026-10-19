package consensus

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/entitlement"
	"github.com/certen/independant-validator/pkg/ledger"
)

// The entitlement store and consensus verify epochs against ONE key set: the one consensus applies (entitlement_keys.go).
// The store used to verify against CERTEN_ENTITLEMENT_KEYS, read once from the environment - the genesis seed a sealed
// chain ignores - while consensus judges by the sealed policy and every key rotation since.

// epochServer serves one epoch for gatePayer signed by key under keyID, and returns its URL.
func epochServer(t *testing.T, keyID string, key ed25519.PrivateKey) string {
	t.Helper()
	set := entitlement.Set{Leaves: []entitlement.Leaf{activeLeaf(gatePayer)}}
	setHash, err := set.SetHash()
	if err != nil {
		t.Fatal(err)
	}
	h := entitlement.Header{Epoch: uint64(time.Now().Unix() / 30), Root: set.Root(), SetHash: setHash,
		NativeUSDMicro: 3000 * 1_000_000, IssuedAtUnix: gateNow - 60, NotAfterUnix: gateNow + 3600, KeyID: keyID}
	h.Signature = hex.EncodeToString(ed25519.Sign(key, h.SigningBytes()))
	body, err := json.Marshal(entitlement.Document{Header: h, Set: set})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)
	return srv.URL
}

func storeConfig(url string) entitlement.StoreConfig {
	return entitlement.StoreConfig{URL: url, RefreshInterval: time.Hour, MaxAge: time.Hour, Timeout: 5 * time.Second}
}

func TestTheEntitlementStoreVerifiesEpochsWithTheConsensusKeySet(t *testing.T) {
	oldKey, newKey := seededKey(0x51), seededKey(0x52)
	f := newRotationFixture()
	policy := *f.policy
	policy.Mode = string(EntitlementEnforce)
	policy.Keys = map[string]string{"k-old": pubHex(oldKey)}
	pf := *f
	pf.policy = &policy
	app, store := rotationApp(t, &pf)
	quiet := log.New(io.Discard, "", 0)
	targets := func() []ChainTarget { return []ChainTarget{target(84532, liveAnchorBaseAndSepolia)} }

	// Before the rotation the store holds the old key's epoch and builds evidence consensus accepts.
	cached := app.NewEntitlementStore(storeConfig(epochServer(t, "k-old", oldKey)), quiet)
	if err := cached.Refresh(context.Background()); err != nil {
		t.Fatalf("the key in force: %v", err)
	}
	oldEv := cached.BuildEvidence(gatePayer)
	if oldEv == nil {
		t.Fatal("no evidence from an epoch signed by the key in force")
	}

	// The admin quorum rotates the entitlement key in policy state: k-new from an activation an hour ago. CERTEN's
	// environment still names k-old, as it did at genesis.
	policy.Schedule = []ledger.ScheduledPolicyChange{{Mode: string(EntitlementEnforce),
		Keys: map[string]string{"k-new": pubHex(newKey)}, ActivationUnix: time.Now().Unix() - 3600, Version: 2, ProposedAtHeight: 1}}
	if err := store.SaveEntitlementPolicy(&policy); err != nil {
		t.Fatal(err)
	}
	envKeys := entitlement.KeySet{"k-old": oldKey.Public().(ed25519.PublicKey)}

	// Consensus, at a block after the activation: the new key's evidence is accepted, the old key's refused.
	newURL := epochServer(t, "k-new", newKey)
	consensusEvidence := entitlement.NewStore(storeConfig(newURL), entitlement.KeySet{"k-new": newKey.Public().(ed25519.PublicKey)}, quiet)
	if err := consensusEvidence.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	newEv := consensusEvidence.BuildEvidence(gatePayer)
	resp := v14Step(t, app, 1, []uint32{0, 4},
		anchoredBlockJSON(t, "op-new", "validator-1", targets(), newEv),
		anchoredBlockJSON(t, "op-old", "validator-1", targets(), oldEv))
	if !strings.Contains(resp.TxResults[1].Log, entitlement.ReasonUnknownKey) {
		t.Fatalf("consensus refused the retired key's evidence for another reason: %q", resp.TxResults[1].Log)
	}

	// The defect, as main.go built the store: from the environment's keys. It refuses the epoch consensus accepts.
	fromEnv := entitlement.NewStore(storeConfig(newURL), envKeys, quiet)
	if err := fromEnv.Refresh(context.Background()); err == nil {
		t.Fatal("expected the environment-keyed store to refuse the new key's epoch")
	}

	// The store a validator builds now (main.go: ValidatorApp.NewEntitlementStore) agrees with consensus both ways.
	agrees := app.NewEntitlementStore(storeConfig(newURL), quiet)
	if err := agrees.Refresh(context.Background()); err != nil {
		t.Fatalf("the store refused the epoch consensus accepts: %v", err)
	}
	ev := agrees.BuildEvidence(gatePayer)
	if ev == nil {
		t.Fatal("the store built no evidence from the epoch consensus accepts")
	}
	v14Step(t, app, 2, []uint32{0}, anchoredBlockJSON(t, "op-store", "validator-1", targets(), ev))
	retired := app.NewEntitlementStore(storeConfig(epochServer(t, "k-old", oldKey)), quiet)
	if err := retired.Refresh(context.Background()); err == nil {
		t.Fatal("the store accepted an epoch signed by the retired key, which consensus refuses")
	}
	// And a store that cached the retired key's epoch before the rotation builds no evidence on it after.
	if cached.BuildEvidence(gatePayer) != nil {
		t.Fatal("evidence was built on an epoch whose key a rotation retired")
	}
	if _, ok := cached.Lookup(gatePayer); ok {
		t.Fatal("the pre-screen read an epoch whose key a rotation retired")
	}
}
