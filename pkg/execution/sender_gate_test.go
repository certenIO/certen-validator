// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"testing"
)

// RB3-F64: until this process has verified that its sending key is its registered identity, it sends
// nothing and decides no settlement - it used to run with batching live while the check waited in the
// background, so another validator's key could send and claim first.
func TestNothingIsSentOrClaimedBeforeTheSendersAreVerified(t *testing.T) {
	sendersVerified.Store(false)
	t.Cleanup(func() { sendersVerified.Store(true) })

	var unavailable *SenderUnavailableError
	if _, err := (&EthereumContractManager{}).batchSender(); !errors.As(err, &unavailable) {
		t.Fatalf("batchSender before verification: %v", err)
	}

	f := &fakeODChain{attested: true, attester: odOwnAddr, settleTx: odReplacementTx}
	m := odMember(1, odChain, 100)
	out := settle(t, f, m)
	if !out.Deferred || f.settleCalls != 0 || out.Settled || out.Released {
		t.Fatalf("outcome %+v settle calls %d; want deferred and nothing sent", out, f.settleCalls)
	}
	if _, err := odOrchestrator(f).OnDemandMemberNeedsThisValidator(context.Background(), m); err == nil {
		t.Fatal("'needs this validator' answered before this validator's address was proven")
	}
}

// VerifySendersAreIdentity lets the process send only when every chain's key is the identity.
func TestSendersAreVerifiedOnlyWhenTheyAreTheIdentity(t *testing.T) {
	sendersVerified.Store(false)
	t.Cleanup(func() { sendersVerified.Store(true) })
	if err := VerifySendersAreIdentity(nil, "0x1111111111111111111111111111111111111111"); err == nil || SendersVerified() {
		t.Fatal("verified without a resolver")
	}
}
