package consensus

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/entitlement"
	"github.com/certen/independant-validator/pkg/ledger"
)

// THE TEST THAT WOULD HAVE CAUGHT THE 2026-07-27 OUTAGE.
//
// Changing the entitlement rule alters which ValidatorBlocks are accepted, and
// the app hash is a chain over accepted bundle-ids. So a rule change moves the
// app hash — and if the rule can differ between a node and its own committed
// past, replay diverges and CometBFT panics at handshake with no recovery.
//
// A test that never restarts cannot see this. These tests run a chain ACROSS a
// policy activation boundary, then replay the identical blocks against fresh
// application instances sharing the same committed state, and require the app
// hashes to match at every height.

// blockRunner drives the same sequence FinalizeBlock does: activate any pending
// policy for this height, process the block's transactions, stage the app hash,
// then promote it as Commit would.
func runBlockFull(app *ValidatorApp, height int64, blockTime time.Time, txs ...[]byte) []byte {
	app.currentBlockTime = blockTime
	app.activatePolicyForBlock(height, blockTime.UTC().Unix())
	app.currentBlockHeight = uint64(height)
	app.blockBundles = app.blockBundles[:0]
	for _, tx := range txs {
		if pu, ok := DecodePolicyUpdate(tx); ok {
			app.processPolicyUpdate(pu, height)
			continue
		}
		app.processValidatorTransaction(tx)
	}
	staged := app.stageAppHash(app.blockBundles)
	app.committedAppHash = staged // what Commit does
	return staged
}

// appOn builds an application over an existing KV, which is how a "restart" is
// simulated: the process is new, the committed state is not.
func appOn(t *testing.T, kv *memKV, blockTime time.Time) *ValidatorApp {
	t.Helper()
	store := ledger.NewLedgerStore(kv)
	sealed, err := store.LoadEntitlementPolicy()
	if err != nil {
		t.Fatal(err)
	}
	cfg := EntitlementConfig{Mode: EntitlementOff, Keys: entitlement.KeySet{}}
	if sealed != nil {
		if cfg, err = policyStateTo(sealed); err != nil {
			t.Fatal(err)
		}
	}
	return &ValidatorApp{
		logger:           log.New(io.Discard, "", 0),
		validatorBlocks:  make(map[string]*ValidatorBlock),
		ledgerStore:      store,
		chainID:          "certen-test",
		entitlement:      cfg,
		currentBlockTime: blockTime,
	}
}

// sealPolicyWithAdmin seals a genesis policy that CAN be updated.
func sealPolicyWithAdmin(t *testing.T, kv *memKV, mode EntitlementMode, epochKeys entitlement.KeySet) ed25519.PrivateKey {
	t.Helper()
	adminPub, adminPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for id, pub := range epochKeys {
		keys[id] = hex.EncodeToString(pub)
	}
	store := ledger.NewLedgerStore(kv)
	if err := store.SaveEntitlementPolicy(&ledger.EntitlementPolicyState{
		Mode:           string(mode),
		Keys:           keys,
		Version:        1,
		AdminKeys:      map[string]string{"admin-1": hex.EncodeToString(adminPub)},
		AdminThreshold: 1,
	}); err != nil {
		t.Fatal(err)
	}
	return adminPriv
}

func signedUpdate(t *testing.T, priv ed25519.PrivateKey, mode string, keys entitlement.KeySet, activationUnix int64, version uint64) []byte {
	t.Helper()
	hexKeys := map[string]string{}
	for id, pub := range keys {
		hexKeys[id] = hex.EncodeToString(pub)
	}
	tx := &PolicyUpdateTx{
		Kind:           PolicyUpdateKind,
		Mode:           mode,
		Keys:           hexKeys,
		ActivationUnix: activationUnix,
		Version:        version,
	}
	tx.Signatures = []PolicySignature{{
		KeyID:     "admin-1",
		Signature: hex.EncodeToString(ed25519.Sign(priv, tx.SigningBytes())),
	}}
	b, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// MIGRATION STEP 4. Switch the policy at a height, restart across the boundary,
// and require identical app hashes on both sides.
func TestPolicyActivationReplaysIdenticallyAcrossARestart(t *testing.T) {
	kv := newMemKV()
	blockTime := time.Unix(gateNow, 0).UTC()
	epochKeys := testKeySet(t, 1)
	adminPriv := sealPolicyWithAdmin(t, kv, EntitlementObserve, epochKeys)

	const proposeAt = int64(10)
	// Activation is a TIME. The chain produces blocks only for real work, so a
	// height-based schedule would mean something different at every throughput;
	// block time comes from the header and is just as deterministic.
	proposeTime := blockTime
	activateTime := proposeTime.Add(time.Duration(MinActivationDelay) * time.Second)

	// An unentitled block: accepted under observe, refused under enforce. It is
	// the transaction whose treatment changes at the boundary, and therefore the
	// one that moves the app hash.
	unentitled := invariantValidBlockJSON(t, "bundle-A", "acc://stranger.acme/data")
	update := signedUpdate(t, adminPriv, string(EntitlementEnforce), epochKeys, activateTime.Unix(), 2)

	// Blocks spanning the boundary. Heights advance one at a time; the TIMES are
	// what decide when the rule changes.
	type blk struct {
		h int64
		t time.Time
	}
	blocks := []blk{
		{proposeAt, proposeTime},
		{proposeAt + 1, proposeTime.Add(time.Second)},
		{proposeAt + 2, activateTime.Add(-time.Second)},
		{proposeAt + 3, activateTime},
		{proposeAt + 4, activateTime.Add(time.Second)},
	}

	// ---- first run ----
	first := map[int64]string{}
	app := appOn(t, kv, blockTime)
	for _, b := range blocks {
		var hash []byte
		if b.h == proposeAt {
			hash = runBlockFull(app, b.h, b.t, update, unentitled)
		} else {
			hash = runBlockFull(app, b.h, b.t, unentitled)
		}
		first[b.h] = hex.EncodeToString(hash)
	}

	// The boundary must actually have done something, or this test proves
	// nothing about activation.
	//
	// A rejected block contributes no bundle-id, and stageAppHash deliberately
	// returns the UNCHANGED committed hash for an empty block (advancing it
	// would make CometBFT emit endless proof blocks). So enforcement does not
	// move the hash at the boundary — it stops it advancing. That is the
	// signature to assert.
	if first[proposeAt+2] == first[proposeAt+1] {
		t.Fatal("hash did not advance while the block was still being ACCEPTED under observe")
	}
	if first[proposeAt+3] != first[proposeAt+2] {
		t.Fatal("hash advanced at the activation time; the block was not rejected, so enforcement did not take effect")
	}
	if first[proposeAt+4] != first[proposeAt+3] {
		t.Fatal("hash advanced after activation; blocks are still being accepted under enforce")
	}
	if app.entitlement.Mode != EntitlementEnforce {
		t.Fatalf("policy did not activate: mode = %s, want enforce", app.entitlement.Mode)
	}

	// ---- replay: new application instances, same committed state ----
	// Reset the hash chain to genesis and re-execute the identical blocks, as
	// CometBFT does at handshake. Committed policy state is deliberately kept.
	replayApp := appOn(t, kv, blockTime)
	replayApp.committedAppHash = nil
	for _, b := range blocks {
		var hash []byte
		if b.h == proposeAt {
			hash = runBlockFull(replayApp, b.h, b.t, update, unentitled)
		} else {
			hash = runBlockFull(replayApp, b.h, b.t, unentitled)
		}
		if got := hex.EncodeToString(hash); got != first[b.h] {
			t.Fatalf("REPLAY DIVERGED at height %d: first=%s replay=%s\n"+
				"This is the failure that bricked the fleet: the rule applied on replay "+
				"differs from the one that committed the block.", b.h, first[b.h], got)
		}
	}
}

// The activation height is what makes the switch simultaneous. If the rule
// applied depended on when a node restarted rather than on the height, the
// whole mechanism would be theatre.
func TestRuleInForceDependsOnBlockTimeNotOnRestartTime(t *testing.T) {
	kv := newMemKV()
	blockTime := time.Unix(gateNow, 0).UTC()
	epochKeys := testKeySet(t, 1)
	adminPriv := sealPolicyWithAdmin(t, kv, EntitlementObserve, epochKeys)

	activateTime := blockTime.Add(time.Duration(MinActivationDelay) * time.Second)
	update := signedUpdate(t, adminPriv, string(EntitlementEnforce), epochKeys, activateTime.Unix(), 2)

	app := appOn(t, kv, blockTime)
	runBlockFull(app, 1, blockTime, update)

	// A node restarting BEFORE the activation height must still be on observe,
	// no matter that the change is already committed.
	early := appOn(t, kv, blockTime)
	runBlockFull(early, 2, activateTime.Add(-time.Second))
	if early.entitlement.Mode != EntitlementObserve {
		t.Fatalf("rule changed before its activation time: mode = %s", early.entitlement.Mode)
	}

	// A node restarting AT or after it must be on enforce.
	late := appOn(t, kv, blockTime)
	runBlockFull(late, 2, activateTime)
	if late.entitlement.Mode != EntitlementEnforce {
		t.Fatalf("rule did not activate at its time: mode = %s", late.entitlement.Mode)
	}
}
