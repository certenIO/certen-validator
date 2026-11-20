// Copyright 2026 Certen Protocol
//
// AGT-F81: the pending component of a key page whose KEY BOOK has a pending transaction, rebuilt from served data, binds the page's receipt. Offline,
// over the page recorded from Kermit on 2026-11-20 (acc://fict-agent-08015.acme/book/1, whose book still lists the delivered transaction
// 0cb15e58... as pending): the capture used to assume a zero pending component and named the page unbound (AGT-0 scene 4b, intent f2545191).

package proofv2

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

type fixtureSource struct {
	fx       pendingFixture
	dropBook bool
}

func (f fixtureSource) Pending(_ context.Context, account *url.URL) ([]*url.TxID, error) {
	ids, ok := f.fx.Pending[account.String()]
	if !ok {
		return nil, fmt.Errorf("the fixture holds no pending list for %v", account)
	}
	if f.dropBook && len(ids) > 0 && account.String() != "acc://fict-agent-08015.acme/book/1" {
		return nil, nil
	}
	var out []*url.TxID
	for _, s := range ids {
		id, err := url.ParseTxID(s)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func (f fixtureSource) Record(_ context.Context, txid *url.TxID) (*api.MessageRecord[messaging.Message], error) {
	raw, ok := f.fx.Records[txid.String()]
	if !ok {
		return nil, fmt.Errorf("the fixture holds no record of %v", txid)
	}
	rec := new(api.MessageRecord[messaging.Message])
	if err := json.Unmarshal(raw, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

func loadPendingFixture(t *testing.T, page string) (pendingFixture, protocol.Account, *merkle.Receipt) {
	t.Helper()
	b, err := os.ReadFile(fixturePath(page))
	if err != nil {
		t.Fatal(err)
	}
	var fx pendingFixture
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	sb, _ := hex.DecodeString(fx.Account)
	acct, err := protocol.UnmarshalAccount(sb)
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := hex.DecodeString(fx.Receipt)
	r := new(merkle.Receipt)
	if err := r.UnmarshalBinary(rb); err != nil {
		t.Fatal(err)
	}
	return fx, acct, r
}

func TestPendingComponentBindsAPageWhoseBookHasAPendingTransaction(t *testing.T) {
	fx, acct, r := loadPendingFixture(t, "acc://fict-agent-08015.acme/book/1")
	receipt := toChainedReceipt(r)
	zero := hex.EncodeToString(make([]byte, 32))
	if err := proof.VerifyChainBinding(receipt, fx.Chains, zero); err == nil {
		t.Fatal("the recorded page binds with a ZERO pending component: the fixture does not exercise the book's pending transaction")
	}
	cand, err := pendingComponent(context.Background(), fixtureSource{fx: fx}, acct)
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.VerifyChainBinding(receipt, fx.Chains, cand); err != nil {
		t.Fatalf("the rebuilt pending component does not bind the recorded receipt: %v", err)
	}
	// without the book's pending transaction (the rule a page's hash follows, observer_prod.go) the component is zero and does not bind
	without, err := pendingComponent(context.Background(), fixtureSource{fx: fx, dropBook: true}, acct)
	if err != nil {
		t.Fatal(err)
	}
	if without != zero {
		t.Fatalf("without the book's pending transaction the component is %s, want zero", without)
	}
}

func TestPendingComponentRefusesAnActiveMessageItCannotPlace(t *testing.T) {
	fx, acct, _ := loadPendingFixture(t, "acc://fict-agent-08015.acme/book/1")
	// a page that no longer holds the key of the active signature: the entry's key index cannot be established, so no component is claimed
	kp := *acct.(*protocol.KeyPage)
	kp.Keys = nil
	if _, err := pendingComponent(context.Background(), fixtureSource{fx: fx}, &kp); err == nil {
		t.Fatal("a component was rebuilt although the key of an active signature is not an entry of the page")
	}
}

// AGT-F81: an account's OWN pending transaction (a data account holding an agent payment that waits for its authorities: the txid, then its votes and
// credit payments as the account records them), recorded from Kermit during gate-candidate-3 A-03 (2026-11-20T13:09Z).
func TestPendingComponentBindsAnAccountWithItsOwnPendingTransaction(t *testing.T) {
	fx, acct, r := loadPendingFixture(t, "acc://agt5-agent-a-43152.acme/data")
	receipt := toChainedReceipt(r)
	zero := hex.EncodeToString(make([]byte, 32))
	if err := proof.VerifyChainBinding(receipt, fx.Chains, zero); err == nil {
		t.Fatal("the recorded account binds with a ZERO pending component: the fixture does not exercise its own pending transaction")
	}
	if n := len(fx.Pending[acct.GetUrl().String()]); n == 0 {
		t.Fatal("the fixture records no pending transaction on the account itself")
	}
	cand, err := pendingComponent(context.Background(), fixtureSource{fx: fx}, acct)
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.VerifyChainBinding(receipt, fx.Chains, cand); err != nil {
		t.Fatalf("the rebuilt pending component does not bind the recorded receipt: %v", err)
	}
}
