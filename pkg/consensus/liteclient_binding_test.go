package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// The lite-client proof is the only thing in a ValidatorBlock that originates
// outside the proposer. These tests pin what checking it does and does not buy.

// receiptFor builds a real, self-consistent one-step receipt: Start hashed with
// a sibling reaches Anchor. Built with the library's own combining rule so the
// test cannot pass against a validator that disagrees with production.
func receiptFor(start []byte) *merkle.Receipt {
	sib := sha256.Sum256([]byte("sibling"))
	r := &merkle.Receipt{Start: start}
	r.Entries = []*merkle.ReceiptEntry{{Right: true, Hash: sib[:]}}
	both := append(append([]byte{}, start...), sib[:]...)
	sum := sha256.Sum256(both)
	r.Anchor = sum[:]
	return r
}

func txHashHex(seed string) (string, []byte) {
	h := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(h[:]), h[:]
}

// An absent proof is not an error here — presence is the caller's policy.
// Requiring it inside the invariant would refuse every block not yet producing
// one, which is an outage rather than a security control.
func TestAbsentProofIsNotRejectedHere(t *testing.T) {
	if err := verifyLiteClientBinding("", "", nil, nil, nil, "acc://payer.acme/data"); err != nil {
		t.Fatalf("an absent proof was rejected: %v", err)
	}
}

// A proof about a different account proves nothing about this one.
func TestProofForAnotherAccountIsRejected(t *testing.T) {
	txHex, txBytes := txHashHex("tx-1")
	err := verifyLiteClientBinding(
		"acc://stranger.acme/data", txHex, receiptFor(txBytes), nil, nil,
		"acc://payer.acme/data")
	if err == nil {
		t.Fatal("a proof for a different account was accepted")
	}
	if !strings.Contains(err.Error(), "cannot authorise this one") {
		t.Errorf("message should say why; got: %v", err)
	}
}

// The bare identity and its data account are the same IDENTITY, which is the
// real production shape — the proof names one, the anchor reference the other.
func TestProofBindsAcrossIdentityAndDataAccount(t *testing.T) {
	txHex, txBytes := txHashHex("tx-1")
	if err := verifyLiteClientBinding(
		"acc://carp-seller-91503.acme", txHex, receiptFor(txBytes), nil, nil,
		"acc://carp-seller-91503.acme/data"); err != nil {
		t.Fatalf("the production shape was rejected: %v", err)
	}
}

// A receipt that does not hash from its start to its anchor is fabricated or
// corrupt. This is the check a forged proof most easily fails.
func TestReceiptThatDoesNotReachItsAnchorIsRejected(t *testing.T) {
	txHex, txBytes := txHashHex("tx-1")
	bad := receiptFor(txBytes)
	bad.Anchor = make([]byte, 32) // claim an anchor the entries do not produce

	err := verifyLiteClientBinding("acc://payer.acme/data", txHex, bad, nil, nil, "acc://payer.acme/data")
	if err == nil {
		t.Fatal("a receipt that does not reach its anchor was accepted")
	}
	if !strings.Contains(err.Error(), "not internally consistent") {
		t.Errorf("message should name the defect; got: %v", err)
	}
}

// Tampering with the proven element must break the receipt, or the proof could
// be retargeted at another transaction.
func TestTamperedStartBreaksTheReceipt(t *testing.T) {
	txHex, txBytes := txHashHex("tx-1")
	r := receiptFor(txBytes)
	r.Start = make([]byte, 32)

	if err := verifyLiteClientBinding("acc://payer.acme/data", txHex, r, nil, nil, "acc://payer.acme/data"); err == nil {
		t.Fatal("a receipt with a swapped start was accepted")
	}
}

// A perfectly valid proof for a DIFFERENT transaction by the same account must
// not satisfy this block: real evidence, wrong subject.
func TestValidProofForAnotherTransactionIsRejected(t *testing.T) {
	_, otherTx := txHashHex("tx-OTHER")
	thisTxHex, _ := txHashHex("tx-THIS")

	err := verifyLiteClientBinding(
		"acc://payer.acme/data", thisTxHex, receiptFor(otherTx), nil, nil,
		"acc://payer.acme/data")
	if err == nil {
		t.Fatal("a proof for a different transaction was accepted")
	}
	if !strings.Contains(err.Error(), "different transaction") {
		t.Errorf("message should name the mismatch; got: %v", err)
	}
}

// The matching case must pass, or the check is just an outage.
func TestMatchingProofIsAccepted(t *testing.T) {
	txHex, txBytes := txHashHex("tx-1")
	if err := verifyLiteClientBinding(
		"acc://payer.acme/data", txHex, receiptFor(txBytes), nil, nil,
		"acc://payer.acme/data"); err != nil {
		t.Fatalf("a matching, valid proof was rejected: %v", err)
	}
}

// A proof naming an account but carrying no receipts binds nothing, and must
// not be accepted as though it did.
func TestAccountWithoutReceiptsStillRequiresAMatch(t *testing.T) {
	if err := verifyLiteClientBinding(
		"acc://stranger.acme/data", "", nil, nil, nil, "acc://payer.acme/data"); err == nil {
		t.Fatal("a proof naming a different account with no receipts was accepted")
	}
}
