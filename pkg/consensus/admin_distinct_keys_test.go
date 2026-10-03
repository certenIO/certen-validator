package consensus

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
)

// An admin threshold counts distinct KEYS. A set naming one key under two ids at threshold 2 let that one key sign
// twice - once per id - and authorise alone: a policy update, a validator rotation, a BLS registry or an admin rotation.
func TestOneKeyUnderTwoIdsIsOneSigner(t *testing.T) {
	k := seededKey(0xC7)
	state := &ledger.EntitlementPolicyState{Mode: "off", AdminThreshold: 2,
		AdminKeys: map[string]string{"alias-1": pubHex(k), "alias-2": strings.ToUpper(pubHex(k))}}
	digest := []byte("anything an admin signs")
	sig := hex.EncodeToString(ed25519.Sign(k, digest))
	err := verifyAdminQuorum(digest, []PolicySignature{{KeyID: "alias-1", Signature: sig}, {KeyID: "alias-2", Signature: sig}},
		state, "test", "nothing")
	if err == nil {
		t.Fatal("one key signing under two ids reached a threshold of 2")
	}
	// Two distinct keys still do.
	k2 := seededKey(0xC8)
	state.AdminKeys["other"] = pubHex(k2)
	if err := verifyAdminQuorum(digest, []PolicySignature{{KeyID: "alias-1", Signature: sig},
		{KeyID: "other", Signature: hex.EncodeToString(ed25519.Sign(k2, digest))}}, state, "test", "nothing"); err != nil {
		t.Fatalf("two distinct keys: %v", err)
	}
}

// Genesis never seals a set that names one key twice.
func TestTheGenesisSeedRefusesOneKeyUnderTwoIds(t *testing.T) {
	k := pubHex(seededKey(0xC7))
	t.Setenv("CERTEN_ENTITLEMENT_ADMIN_KEYS", "a:"+k+",b:"+strings.ToUpper(k))
	t.Setenv("CERTEN_ENTITLEMENT_ADMIN_THRESHOLD", "2")
	if _, err := AdminSeedFromEnv(); err == nil {
		t.Fatal("sealed one key under two ids")
	}
	t.Setenv("CERTEN_ENTITLEMENT_ADMIN_KEYS", "a:"+k+",b:"+pubHex(seededKey(0xC8)))
	if _, err := AdminSeedFromEnv(); err != nil {
		t.Fatalf("two keys: %v", err)
	}
}

// Counting keys instead of ids changes no verdict on a chain whose admin sets never named a key twice - certen-testnet's
// lost set, its re-seal and every set an admin rotation installs. A node continuing older state therefore refuses to
// start if any admin set its chain ever had names a key twice: there, history may hold a verdict v12 does not reach.
func TestOlderStateWithARepeatedAdminKeyIsNotContinued(t *testing.T) {
	f := newRotationFixture()
	if err := checkAdminKeyCountingContinuity(executionRulesV11, f.policy); err != nil {
		t.Fatalf("distinct keys: %v", err)
	}
	dup := *f.policy
	dup.AdminReseals = []ledger.AdminReseal{{Height: 4, ID: "x", Threshold: 2,
		Keys: map[string]string{"a": f.policy.AdminKeys["ops-1"], "b": f.policy.AdminKeys["ops-1"]}}}
	for _, v := range []uint64{0, executionRulesV7, executionRulesV11} {
		if err := checkAdminKeyCountingContinuity(v, &dup); err == nil {
			t.Fatalf("v%d state whose re-seal named one key twice was continued", v)
		}
	}
	if err := checkAdminKeyCountingContinuity(executionRulesV12, &dup); err != nil {
		t.Fatalf("v12 state is v12's own: %v", err)
	}
	if err := checkAdminKeyCountingContinuity(executionRulesV11, nil); err != nil {
		t.Fatalf("no sealed policy: %v", err)
	}
}
