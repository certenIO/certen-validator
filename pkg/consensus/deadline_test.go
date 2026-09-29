package consensus

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ledger"
)

// RB4-F60. An intent's deadline (replay expires_at) stops CERTEN starting work on it late. It was judged against
// the node's current clock on every validator, every time the intent was processed - including when an intent
// consensus had already committed was processed again: after a restart, or to re-drive a member (RB4-F55 repair).
// Production 2026-09-29: intent 000ac79a was admitted at 08:47:54 and settled at 08:48:38, before its deadline
// (09:00:29); re-deriving its round at 11:15 refused it "permanently invalid: intent expired", so its base member
// could never be proven. A committed operation's deadline was decided at its commit: it is judged at the commit's
// block time, the same on every node. New work is judged now.

const (
	f60Created  = int64(1790676329) // 08:45:29Z
	f60Deadline = int64(1790677229) // 09:00:29Z
	f60Commit   = int64(1790678874) - 1000
	f60Now      = int64(1790680548) // 11:15:48Z
)

func deadlineIntent(t *testing.T) *CertenIntent {
	t.Helper()
	ci := batchableIntent(t, "000ac79a-deadline", 84532)
	ci.TransactionHash = "db0236d87fa3c0fd8e6f1c21cba1ce7527bf592c5f727632ad7f329cacbe0e48"
	blob, err := json.Marshal(map[string]interface{}{"nonce": "n-000ac79a", "created_at": f60Created, "expires_at": f60Deadline})
	if err != nil {
		t.Fatal(err)
	}
	ci.ReplayData = blob
	return ci
}

func TestAnIntentsDeadlineIsJudgedAtTheInstantGiven(t *testing.T) {
	ci := deadlineIntent(t)
	if err := ci.CheckDeadline(time.Unix(f60Deadline-60, 0)); err != nil {
		t.Fatalf("before its deadline: %v", err)
	}
	err := ci.CheckDeadline(time.Unix(f60Now, 0))
	if err == nil || !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), "judged at") {
		t.Fatalf("after its deadline: %v", err)
	}
}

type committedOps struct {
	rec *ledger.CommittedOperation
	err error
	got []string
}

func (c *committedOps) CommittedOperation(validatorID, operationID string) (*ledger.CommittedOperation, int64, error) {
	c.got = append(c.got, validatorID+"|"+operationID)
	return c.rec, 42, c.err
}

func TestACommittedOperationsDeadlineIsJudgedAtItsCommit(t *testing.T) {
	ci := deadlineIntent(t)
	opID, err := ci.OperationID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(f60Now, 0)
	commit := time.Date(2026, 9, 29, 8, 47, 54, 0, time.UTC)

	reader := &committedOps{rec: &ledger.CommittedOperation{Height: 3071, BundleID: "0xbundle", BlockTime: commit}}
	at, basis, err := deadlineInstant(reader, "validator-6", ci, now)
	if err != nil || !at.Equal(commit) || !strings.Contains(basis, "committed at height 3071") {
		t.Fatalf("THE regression: a committed operation's deadline is judged at %v (%s, %v); want its commit %v", at, basis, err, commit)
	}
	if len(reader.got) != 1 || reader.got[0] != "validator-6|"+opID {
		t.Fatalf("asked the index %v; want this validator's block for the intent's operation", reader.got)
	}
	if err := ci.CheckDeadline(at); err != nil {
		t.Fatalf("admitted before its deadline, re-derived after it: %v", err)
	}

	at, basis, err = deadlineInstant(&committedOps{}, "validator-6", ci, now)
	if err != nil || !at.Equal(now) || !strings.Contains(basis, "not committed") {
		t.Fatalf("new work is judged now: %v (%s, %v)", at, basis, err)
	}

	if _, _, err := deadlineInstant(&committedOps{err: errors.New("index behind")}, "validator-6", ci, now); err == nil {
		t.Fatal("an index that cannot answer was taken as an answer")
	}
	if _, _, err := deadlineInstant(nil, "validator-6", ci, now); err == nil {
		t.Fatal("with no committed-operation index the deadline was judged anyway")
	}
}
