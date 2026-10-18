package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/intent"
)

// RB8-G (verifier defect 3): `repair lifecycle-rows` promised exit status 2 for an intent that is not in its block, and
// never searched the block. It now searches the named block with the Accumulate client and owes an entry only when EVERY
// named intent is in it; one that is not makes the whole request a mistake (a wrong --block), so nothing is owed.

// blockOfIntents is a fake Accumulate client serving one Directory Network block.
type blockOfIntents struct {
	accumulate.Client
	height int64
	txs    []*accumulate.CertenTransaction
	err    error
}

func (c *blockOfIntents) SearchCertenTransactions(_ context.Context, h int64) ([]*accumulate.CertenTransaction, error) {
	if c.err != nil {
		return nil, c.err
	}
	if h != c.height {
		return nil, nil
	}
	return c.txs, nil
}

func intentTx(hash, intentID string, height int64) *accumulate.CertenTransaction {
	return &accumulate.CertenTransaction{
		Hash: hash, AccountURL: "acc://harbor.acme/data", BlockHeight: height,
		Partition: "acc://dn.acme", ProofPartition: "bvn1", ProofBlockIndex: 8270001,
		IntentData: map[string]interface{}{
			"intentData":     map[string]interface{}{"intent_id": intentID, "proof_class": "on_demand"},
			"crossChainData": map[string]interface{}{},
			"governanceData": map[string]interface{}{"organizationAdi": "acc://harbor.acme"},
			"replayData":     map[string]interface{}{"expires_at": 1790600000},
		},
	}
}

type fakeRows map[string]database.IntentLifecycleStatus

func (f fakeRows) GetByIntentID(_ context.Context, id string) (*database.IntentLifecycle, error) {
	st, ok := f[id]
	if !ok {
		return nil, database.ErrIntentLifecycleNotFound
	}
	return &database.IntentLifecycle{IntentID: id, Status: st}, nil
}

const rowsBlock = 11243840

func rowsBlockClient(t *testing.T, intents ...string) (*blockOfIntents, []string) {
	t.Helper()
	c := &blockOfIntents{height: rowsBlock}
	for i, name := range intents {
		c.txs = append(c.txs, intentTx(strings.Repeat(string(rune('a'+i)), 64), name, rowsBlock))
	}
	have, err := intent.IntentsInBlock(c, rowsBlock)
	if err != nil || len(have) != len(intents) {
		t.Fatalf("the fake block lists %v (err %v); want %d intents", have, err, len(intents))
	}
	var ids []string
	for id := range have {
		ids = append(ids, id)
	}
	return c, ids
}

func plan(t *testing.T, c accumulate.Client, rows fakeRows, ids []string, apply bool) ([]lifecycleRowsLine, []intent.PendingRetry, int, error) {
	t.Helper()
	return planLifecycleRows(context.Background(), rows,
		func(h uint64) (map[string]bool, error) { return intent.IntentsInBlock(c, h) }, rowsBlock, ids, apply)
}

func TestLifecycleRowsOwesEveryNamedIntentThatIsInItsBlock(t *testing.T) {
	c, ids := rowsBlockClient(t, "owed-a", "owed-b", "owed-has-row")
	rows := fakeRows{ids[2]: database.IntentLifecycleAuthorized}

	lines, owed, code, err := plan(t, c, rows, ids, true)
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v", code, err)
	}
	if len(owed) != 2 || owed[0].IntentID != ids[0] || owed[1].IntentID != ids[1] || owed[0].BlockHeight != rowsBlock {
		t.Fatalf("owed %+v; want the two without a row, in their block", owed)
	}
	for _, l := range lines {
		if !l.InBlock {
			t.Errorf("%s is reported not in its block", l.IntentID)
		}
	}
	if lines[2].HasRow != true || lines[0].HasRow {
		t.Errorf("has_row misreported: %+v", lines)
	}
}

func TestLifecycleRowsOwesNothingWhenAnIntentIsNotInItsBlock(t *testing.T) {
	c, ids := rowsBlockClient(t, "present-a", "present-b")
	ids = append(ids, "11111111-2222-3333-4444-555555555555") // in no block: a wrong id or a wrong --block

	for _, apply := range []bool{true, false} {
		lines, owed, code, err := plan(t, c, fakeRows{}, ids, apply)
		if err != nil {
			t.Fatal(err)
		}
		if code != 2 {
			t.Fatalf("apply=%v: exit status %d; want 2 for an intent that is not in its block", apply, code)
		}
		if len(owed) != 0 {
			t.Fatalf("apply=%v: %+v owed although an intent is not in its block", apply, owed)
		}
		if !lines[0].InBlock || !lines[1].InBlock || lines[2].InBlock {
			t.Fatalf("apply=%v: in_block is %v %v %v; want true true false", apply, lines[0].InBlock, lines[1].InBlock, lines[2].InBlock)
		}
		if !strings.Contains(lines[2].Action, "not in block") {
			t.Fatalf("the absent intent's line does not say so: %q", lines[2].Action)
		}
	}
}

// An intent that already has a row is still checked against its block: the report is the same for dry runs and applies.
func TestLifecycleRowsChecksTheBlockOfAnIntentThatHasARow(t *testing.T) {
	c, ids := rowsBlockClient(t, "has-row")
	other := "99999999-aaaa-bbbb-cccc-dddddddddddd"
	rows := fakeRows{other: database.IntentLifecycleAuthorized}
	_, owed, code, err := plan(t, c, rows, append(ids, other), true)
	if err != nil || code != 2 || len(owed) != 0 {
		t.Fatalf("code %d owed %+v err %v; want 2 and nothing owed", code, owed, err)
	}
}

// A block that cannot be searched is an error (exit 1), never an answer.
func TestLifecycleRowsReportsABlockItCannotSearch(t *testing.T) {
	c, ids := rowsBlockClient(t, "any")
	c.err = errors.New("accumulate: 503")
	_, owed, _, err := plan(t, c, fakeRows{}, ids, true)
	if err == nil || !strings.Contains(err.Error(), "503") || len(owed) != 0 {
		t.Fatalf("err %v owed %+v; an unsearchable block must be an error that owes nothing", err, owed)
	}
}
