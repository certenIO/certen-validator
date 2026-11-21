// Copyright 2026 Certen Protocol
//
// AGT-F81 fixture RECORDER (live, Kermit): writes what the pending-component test reads offline. It is a tool, run by hand:
//
//	CERTEN_PENDING_RECORD=acc://fict-agent-08015.acme/book/1 go test ./pkg/proof/v2/ -run TestRecordPendingFixture -count=1
//
// It records the page (state and receipt as of now), its chain roots, the pending lists of the page and its book, and the record of each pending
// transaction, into testdata/pending/<host>-<path>.json. The offline test (pending_test.go) is the gate.

package proofv2

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

type pendingFixture struct {
	Source   string                     `json:"source"`
	Account  string                     `json:"account"` // hex of the account's binary state
	Receipt  string                     `json:"receipt"` // hex of the receipt's binary
	Chains   []proof.ChainRoot          `json:"chains"`
	Pending  map[string][]string        `json:"pending"` // account URL -> pending txids
	Records  map[string]json.RawMessage `json:"records"` // txid -> MessageRecord JSON
	Recorded string                     `json:"recorded"`
}

func fixturePath(page string) string {
	u := url.MustParse(page)
	return filepath.Join("testdata", "pending", strings.ReplaceAll(u.Authority+u.Path, "/", "-")+".json")
}

type recordingSource struct {
	inner   apiPending
	pending map[string][]string
	records map[string]json.RawMessage
}

func (r *recordingSource) Pending(ctx context.Context, account *url.URL) ([]*url.TxID, error) {
	ids, err := r.inner.Pending(ctx, account)
	if err == nil {
		for _, id := range ids {
			r.pending[account.String()] = append(r.pending[account.String()], id.String())
		}
		if _, ok := r.pending[account.String()]; !ok {
			r.pending[account.String()] = []string{}
		}
	}
	return ids, err
}

func (r *recordingSource) Record(ctx context.Context, txid *url.TxID) (*api.MessageRecord[messaging.Message], error) {
	rec, err := r.inner.Record(ctx, txid)
	if err == nil {
		b, merr := json.Marshal(rec)
		if merr != nil {
			return nil, merr
		}
		r.records[txid.String()] = b
	}
	return rec, err
}

func TestRecordPendingFixture(t *testing.T) {
	page := os.Getenv("CERTEN_PENDING_RECORD")
	if page == "" {
		t.Log("CERTEN_PENDING_RECORD not set: the recorder writes no fixture (a tool run by hand; the gate is pending_test.go)")
		return
	}
	const endpoint = "https://kermit.accumulatenetwork.io/v3"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := jsonrpc.NewClient(endpoint)
	q, err := c.Query(ctx, url.MustParse(page), &api.DefaultQuery{IncludeReceipt: &api.ReceiptOptions{ForAny: true}})
	if err != nil {
		t.Fatal(err)
	}
	ar := q.(*api.AccountRecord)
	state, err := ar.Account.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	rb, err := ar.Receipt.Receipt.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	chains, err := proof.FetchChainRoots(ctx, proof.NewHTTPQuerier(endpoint), page)
	if err != nil {
		t.Fatal(err)
	}
	src := &recordingSource{inner: apiPending{c}, pending: map[string][]string{}, records: map[string]json.RawMessage{}}
	cand, err := pendingComponent(ctx, src, ar.Account)
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.VerifyChainBinding(toChainedReceipt(&ar.Receipt.Receipt), chains, cand); err != nil {
		t.Fatalf("the rebuilt pending component does not bind the live receipt: %v", err)
	}
	fx := pendingFixture{Source: endpoint + " " + page, Account: hex.EncodeToString(state), Receipt: hex.EncodeToString(rb), Chains: chains,
		Pending: src.pending, Records: src.records, Recorded: time.Now().UTC().Format(time.RFC3339)}
	b, _ := json.MarshalIndent(fx, "", " ")
	if err := os.MkdirAll(filepath.Dir(fixturePath(page)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath(page), b, 0o644); err != nil {
		t.Fatal(err)
	}
	_ = protocol.KeyPage{}
	t.Logf("recorded %s (pending component %s)", fixturePath(page), cand[:16])
}
