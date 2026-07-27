package consensus

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
)

// A policy update changes a consensus rule, so the bar for accepting one is the
// bar for changing what the whole fleet enforces. These tests pin that bar.

func adminState(t *testing.T, threshold int, n int) (*ledger.EntitlementPolicyState, []ed25519.PrivateKey) {
	t.Helper()
	keys := map[string]string{}
	privs := make([]ed25519.PrivateKey, 0, n)
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[string(rune('A'+i))] = hex.EncodeToString(pub)
		privs = append(privs, priv)
	}
	epochPub, _, _ := ed25519.GenerateKey(rand.Reader)
	return &ledger.EntitlementPolicyState{
		Mode:           string(EntitlementObserve),
		Keys:           map[string]string{"entitlement-v1": hex.EncodeToString(epochPub)},
		Version:        1,
		AdminKeys:      keys,
		AdminThreshold: threshold,
	}, privs
}

func updateSignedBy(t *testing.T, st *ledger.EntitlementPolicyState, privs []ed25519.PrivateKey, signers []int, activation int64, version uint64) *PolicyUpdateTx {
	t.Helper()
	tx := &PolicyUpdateTx{
		Kind:             PolicyUpdateKind,
		Mode:             string(EntitlementEnforce),
		Keys:             st.Keys,
		ActivationHeight: activation,
		Version:          version,
	}
	for _, i := range signers {
		tx.Signatures = append(tx.Signatures, PolicySignature{
			KeyID:     string(rune('A' + i)),
			Signature: hex.EncodeToString(ed25519.Sign(privs[i], tx.SigningBytes())),
		})
	}
	return tx
}

func TestQuorumIsRequired(t *testing.T) {
	st, privs := adminState(t, 2, 3)

	one := updateSignedBy(t, st, privs, []int{0}, 1000, 2)
	if err := VerifyPolicyUpdate(one, st, 100); err == nil {
		t.Fatal("one signature met a threshold of two")
	}

	two := updateSignedBy(t, st, privs, []int{0, 1}, 1000, 2)
	if err := VerifyPolicyUpdate(two, st, 100); err != nil {
		t.Fatalf("two valid signatures should meet a threshold of two: %v", err)
	}
}

// The same admin signing twice must not reach a threshold of two. Otherwise a
// single compromised key changes what the whole fleet enforces.
func TestDuplicateSignerDoesNotReachQuorum(t *testing.T) {
	st, privs := adminState(t, 2, 3)
	tx := updateSignedBy(t, st, privs, []int{0}, 1000, 2)
	tx.Signatures = append(tx.Signatures, tx.Signatures[0]) // same key again

	if err := VerifyPolicyUpdate(tx, st, 100); err == nil {
		t.Fatal("one key signing twice reached a threshold of two")
	}
}

func TestNonAdminSignatureIsIgnored(t *testing.T) {
	st, privs := adminState(t, 1, 1)
	_, outsider, _ := ed25519.GenerateKey(rand.Reader)

	tx := updateSignedBy(t, st, privs, nil, 1000, 2)
	tx.Signatures = []PolicySignature{{
		KeyID:     "A",                                                           // a real admin id...
		Signature: hex.EncodeToString(ed25519.Sign(outsider, tx.SigningBytes())), // ...but not their key
	}}
	if err := VerifyPolicyUpdate(tx, st, 100); err == nil {
		t.Fatal("a signature from a non-admin key was accepted under an admin's id")
	}
}

// Tampering after signing must invalidate the signature, or the activation
// height and mode could be rewritten in flight.
func TestTamperedFieldsInvalidateSignatures(t *testing.T) {
	st, privs := adminState(t, 1, 1)

	for _, tc := range []struct {
		name   string
		mutate func(*PolicyUpdateTx)
	}{
		{"mode", func(tx *PolicyUpdateTx) { tx.Mode = string(EntitlementOff) }},
		{"activation height", func(tx *PolicyUpdateTx) { tx.ActivationHeight = 500 }},
		{"version", func(tx *PolicyUpdateTx) { tx.Version = 99 }},
		{"keys", func(tx *PolicyUpdateTx) { tx.Keys = map[string]string{"x": "00"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := updateSignedBy(t, st, privs, []int{0}, 1000, 2)
			tc.mutate(tx)
			if err := VerifyPolicyUpdate(tx, st, 100); err == nil {
				t.Fatalf("tampering with %s did not invalidate the update", tc.name)
			}
		})
	}
}

// The delay is what makes activation simultaneous. Without it an update could
// apply to the very block carrying it, and a node that had not yet seen that
// block would disagree.
func TestActivationTooSoonIsRefused(t *testing.T) {
	st, privs := adminState(t, 1, 1)
	current := int64(100)

	tooSoon := updateSignedBy(t, st, privs, []int{0}, current+MinActivationDelay-1, 2)
	err := VerifyPolicyUpdate(tooSoon, st, current)
	if err == nil {
		t.Fatal("an update activating inside the delay window was accepted")
	}
	if !strings.Contains(err.Error(), "too soon") {
		t.Errorf("message should explain the delay; got: %v", err)
	}

	justRight := updateSignedBy(t, st, privs, []int{0}, current+MinActivationDelay, 2)
	if err := VerifyPolicyUpdate(justRight, st, current); err != nil {
		t.Fatalf("an update exactly at the minimum delay should be accepted: %v", err)
	}
}

// Versions must advance, so a captured update cannot be replayed later to
// silently revert the rule.
func TestStaleVersionIsRefused(t *testing.T) {
	st, privs := adminState(t, 1, 1)
	if err := VerifyPolicyUpdate(updateSignedBy(t, st, privs, []int{0}, 1000, 1), st, 100); err == nil {
		t.Fatal("an update at the committed version was accepted")
	}
	if err := VerifyPolicyUpdate(updateSignedBy(t, st, privs, []int{0}, 1000, 2), st, 100); err != nil {
		t.Fatalf("a newer version should be accepted: %v", err)
	}
}

// Scheduling enforce-with-no-keys would halt the fleet at the activation
// height. A delayed outage is worse than an immediate refusal, because nothing
// connects it back to this action.
func TestUnusableProposedPolicyIsRefusedAtAcceptance(t *testing.T) {
	st, privs := adminState(t, 1, 1)
	tx := &PolicyUpdateTx{
		Kind: PolicyUpdateKind, Mode: string(EntitlementEnforce),
		Keys: map[string]string{}, ActivationHeight: 1000, Version: 2,
	}
	tx.Signatures = []PolicySignature{{
		KeyID: "A", Signature: hex.EncodeToString(ed25519.Sign(privs[0], tx.SigningBytes())),
	}}
	if err := VerifyPolicyUpdate(tx, st, 100); err == nil {
		t.Fatal("enforce with no keys was scheduled; the fleet would halt at activation")
	}
}

// A chain sealed with no admin keys is immutable, which is the safe default and
// must not be silently bypassable.
func TestChainWithoutAdminKeysCannotBeUpdated(t *testing.T) {
	// Epoch keys ARE present, so the update is otherwise valid and the refusal
	// can only come from the absent admin set.
	withAdmin, privs := adminState(t, 1, 1)
	st := &ledger.EntitlementPolicyState{Mode: "observe", Keys: withAdmin.Keys, Version: 1}
	tx := updateSignedBy(t, st, privs, []int{0}, 1000, 2)

	err := VerifyPolicyUpdate(tx, st, 100)
	if err == nil {
		t.Fatal("a chain with no admin keys accepted a policy update")
	}
	if !strings.Contains(err.Error(), "immutable") {
		t.Errorf("message should say the chain is immutable; got: %v", err)
	}
}

// Applying the same update twice must be a no-op. Replay depends on it.
func TestApplyIsIdempotentByVersion(t *testing.T) {
	st, privs := adminState(t, 1, 1)
	tx := updateSignedBy(t, st, privs, []int{0}, 1000, 2)

	once := ApplyPolicyUpdate(tx, st, 100)
	twice := ApplyPolicyUpdate(tx, once, 100)

	if len(once.Schedule) != 1 {
		t.Fatalf("schedule length after one apply = %d, want 1", len(once.Schedule))
	}
	if len(twice.Schedule) != 1 {
		t.Fatalf("re-applying appended a duplicate: length = %d, want 1", len(twice.Schedule))
	}
}

// The rule in force must be a pure function of (schedule, height).
func TestActivePolicyAtIsDerivedFromHeight(t *testing.T) {
	st, _ := adminState(t, 1, 1)
	st.Schedule = []ledger.ScheduledPolicyChange{
		{Mode: "enforce", Keys: st.Keys, ActivationHeight: 300, Version: 2},
		{Mode: "off", Keys: st.Keys, ActivationHeight: 600, Version: 3},
	}

	for _, tc := range []struct {
		height int64
		want   string
	}{
		{1, "observe"},   // before any change: genesis
		{299, "observe"}, // one block before the first activation
		{300, "enforce"}, // exactly at it
		{599, "enforce"},
		{600, "off"}, // the later change wins
		{9999, "off"},
	} {
		if got := ActivePolicyAt(st, tc.height).Mode; got != tc.want {
			t.Errorf("height %d: mode = %s, want %s", tc.height, got, tc.want)
		}
	}
}

// Out-of-order entries must not change the answer — the schedule is a set, and
// "latest activation at or below H" is what defines the rule.
func TestActivePolicyIgnoresScheduleOrder(t *testing.T) {
	st, _ := adminState(t, 1, 1)
	forward := []ledger.ScheduledPolicyChange{
		{Mode: "enforce", Keys: st.Keys, ActivationHeight: 300, Version: 2},
		{Mode: "off", Keys: st.Keys, ActivationHeight: 600, Version: 3},
	}
	reversed := []ledger.ScheduledPolicyChange{forward[1], forward[0]}

	for _, h := range []int64{1, 300, 599, 600, 1000} {
		a := *st
		a.Schedule = forward
		b := *st
		b.Schedule = reversed
		if ActivePolicyAt(&a, h).Mode != ActivePolicyAt(&b, h).Mode {
			t.Fatalf("height %d: schedule order changed the active rule", h)
		}
	}
}
