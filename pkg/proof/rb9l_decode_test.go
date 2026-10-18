package proof

import (
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB9-L: Accumulate's union decoder answers neither an account nor an error for bytes that hold no type (a run of zeros). The set check
// decodes the network and globals accounts a proposer supplies BEFORE it binds them to a root, so such bytes reached
// (protocol.Account).Type() on a nil account. They are refused, naming the account, like any bytes that are not an account.
func TestDataEntryOfRefusesBytesThatHoldNoAccount(t *testing.T) {
	zeros := make([]byte, 100)
	// The premise: the decoder answers nothing for zeros. If a later Accumulate answers an error, dataEntryOf refuses with that error and
	// the second assertion below, which pins the nothing-case, is the one to revisit - this test must then fail loudly, not pass vacuously.
	if acct, err := protocol.UnmarshalAccount(zeros); acct != nil || err != nil {
		t.Fatalf("the premise changed: Accumulate's decoder answers %v, %v for zeros", acct, err)
	}
	_, err := dataEntryOf(zeros, "network account")
	const want = "network account: does not decode as an account: it holds no account"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
}
