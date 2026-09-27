package consensus

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// RB3-F117: a policy update's admin signatures cover the chain it is for.

// unboundUpdate is an update signed the pre-v8 way (no chain id).
func unboundUpdate(t *testing.T, priv ed25519.PrivateKey, version uint64) *PolicyUpdateTx {
	t.Helper()
	tx := &PolicyUpdateTx{Kind: PolicyUpdateKind, Mode: string(EntitlementObserve), ActivationUnix: gateNow + 3600, Version: version}
	tx.Signatures = []PolicySignature{{KeyID: "admin-1", Signature: hex.EncodeToString(ed25519.Sign(priv, tx.SigningBytes()))}}
	return tx
}

// An update signed for no chain in particular is refused - it would verify on any chain with the same admins.
func TestAnUnboundPolicyUpdateIsRefused(t *testing.T) {
	kv := newMemKV()
	priv := sealPolicyWithAdmin(t, kv, EntitlementObserve, testKeySet(t, 1))
	app := appOn(t, kv, time.Unix(gateNow, 0).UTC())
	if res := app.processPolicyUpdate(unboundUpdate(t, priv, 2), 10); res.Code == 0 {
		t.Fatal("an update bound to no chain was accepted")
	}
}

func TestAPolicyUpdateIsBoundToItsChain(t *testing.T) {
	kv := newMemKV()
	priv := sealPolicyWithAdmin(t, kv, EntitlementObserve, testKeySet(t, 1))
	st, err := appOn(t, kv, time.Unix(gateNow, 0).UTC()).ledgerStore.LoadEntitlementPolicy()
	if err != nil {
		t.Fatal(err)
	}
	bound := unboundUpdate(t, priv, 2)
	bound.ChainID = "certen-test"
	bound.Signatures = []PolicySignature{{KeyID: "admin-1", Signature: hex.EncodeToString(ed25519.Sign(priv, bound.SigningBytes()))}}
	if err := VerifyPolicyUpdateOnChain(bound, st, gateNow, "certen-test"); err != nil {
		t.Fatalf("a bound update on its chain: %v", err)
	}
	if err := VerifyPolicyUpdateOnChain(bound, st, gateNow, "another-chain"); err == nil {
		t.Fatal("a bound update was accepted on another chain")
	}
	// The binding is in the signed digest: moving the update to another chain breaks its signatures.
	moved := *bound
	moved.ChainID = "another-chain"
	if err := VerifyPolicyUpdateOnChain(&moved, st, gateNow, "another-chain"); err == nil {
		t.Fatal("an update re-labelled for another chain kept valid signatures")
	}
	if err := VerifyPolicyUpdateOnChain(unboundUpdate(t, priv, 2), st, gateNow, "certen-test"); err == nil {
		t.Fatal("an unbound update was accepted")
	}
}

// The two updates committed on the production chain before v8 are exactly the allowlist: their replay is
// unchanged there, and they are refused on any other chain.
func TestTheCommittedLegacyUpdatesAreExactlyTheAllowlist(t *testing.T) {
	f, err := os.Open("testdata/committed_policy_updates_certen-testnet.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	seen := map[string]bool{}
	for sc.Scan() {
		pu, ok := DecodePolicyUpdate(sc.Bytes())
		if !ok {
			t.Fatal("undecodable committed update")
		}
		if !IsCommittedLegacyPolicyUpdate("certen-testnet", pu) || IsCommittedLegacyPolicyUpdate("another-chain", pu) {
			t.Fatalf("committed update v%d is not allowlisted for exactly its chain", pu.Version)
		}
		seen[hex.EncodeToString(pu.SigningBytes())] = true
	}
	if len(seen) != len(committedLegacyPolicyUpdates["certen-testnet"]) || len(committedLegacyPolicyUpdates) != 1 {
		t.Fatalf("the allowlist holds more than the committed updates: %v", committedLegacyPolicyUpdates)
	}
}
