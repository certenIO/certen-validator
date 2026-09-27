// Copyright 2026 Certen Protocol

package consensus

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// RB3-F116: a ledger this node cannot read is never taken for an empty one.

var errUnreadable = errors.New("leveldb: corrupted block")

// brokenKV holds state it cannot read back, as a damaged database does.
type brokenKV struct{ sets int }

func (k *brokenKV) Get([]byte) ([]byte, error) { return nil, errUnreadable }
func (k *brokenKV) Set([]byte, []byte) error   { k.sets++; return nil }

// Before: the sealed policy read as "none", and the environment's policy was sealed over it.
func TestAnUnreadablePolicyIsNeverResealedFromTheEnvironment(t *testing.T) {
	kv := &brokenKV{}
	_, err := ResolveEntitlementPolicy(ledger.NewLedgerStore(kv),
		EntitlementConfig{Mode: EntitlementObserve, Keys: testKeySet(t, 1)}, quietLogger())
	if !errors.Is(err, errUnreadable) {
		t.Fatalf("resolve on an unreadable ledger: %v", err)
	}
	if kv.sets != 0 {
		t.Fatalf("the policy was written %d time(s) over one that could not be read", kv.sets)
	}
}

// Before: Info answered height 0, forcing a replay from genesis (unrecoverable on a pruned store).
func TestInfoRefusesToAnswerFromAnUnreadableLedger(t *testing.T) {
	app := newTestApp(t, ledger.NewLedgerStore(&brokenKV{}))
	resp, err := app.Info(context.Background(), &abcitypes.RequestInfo{})
	if !errors.Is(err, errUnreadable) || resp != nil {
		t.Fatalf("Info on an unreadable ledger: (%+v, %v)", resp, err)
	}
}

// The constructor stops rather than "starting fresh" (it exits the process, so this holds the source).
func TestTheConstructorDoesNotStartFreshOnAnUnreadableLedger(t *testing.T) {
	src, err := os.ReadFile("abci_validator.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "(starting fresh)") {
		t.Fatal("abci_validator.go still starts fresh when the ABCI state cannot be read")
	}
}

// FinalizeBlock does not judge a block by a rule it could not read: keeping the previous rule, or
// refusing a policy update (withholding its id from the app hash), forks this node from the fleet.
// Both paths stop the node (they exit the process, so this holds the source).
func TestFinalizeBlockDoesNotRunPastAnUnreadablePolicy(t *testing.T) {
	src, err := os.ReadFile("policy_update_apply.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"if err != nil || state == nil {", "could not load the committed policy"} {
		if strings.Contains(string(src), bad) {
			t.Errorf("policy_update_apply.go still runs past an unreadable policy (%s)", bad)
		}
	}
	if n := strings.Count(string(src), "the committed policy could not be read"); n != 2 {
		t.Errorf("%d of the 2 policy reads stop the node when the policy cannot be read", n)
	}
}
