// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/database"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// AGT-F104: a governing page whose admissible block (design D2) is below the node's retained BPT history is refused by the capture as
// g1_historical_unavailable{<partition>,<block>}. The capture runs in the background and stores that refusal as text (capture_error), so
// the certificate's proof (ProveG1) used to return it as text only: nothing downstream could tell, by type, that an intent failed because
// the node lacked history rather than for any other reason. These pin that the stored refusal is read back as the *proofv2.NamedState it
// was rendered from, with its partition and block, and that every other stored capture error reads exactly as before.

// rowDriver is a database/sql driver that answers the two reads buildOne makes of one proof_v2_shadow row: the captured pages
// (Captured) and the capture result (CaptureResult). Every write fails, as a store that is down does; the build's own record of its
// failure is then only logged.
type rowDriver struct {
	raw        []byte
	captureErr string
}

func (d *rowDriver) Connect(context.Context) (driver.Conn, error) { return &rowConn{d}, nil }
func (d *rowDriver) Driver() driver.Driver                        { return d }
func (d *rowDriver) Open(string) (driver.Conn, error)             { return &rowConn{d}, nil }

type rowConn struct{ d *rowDriver }

func (c *rowConn) Prepare(q string) (driver.Stmt, error) { return &rowStmt{d: c.d, q: q}, nil }
func (c *rowConn) Close() error                          { return nil }
func (c *rowConn) Begin() (driver.Tx, error)             { return nil, fmt.Errorf("no transactions") }

type rowStmt struct {
	d *rowDriver
	q string
}

func (s *rowStmt) Close() error                               { return nil }
func (s *rowStmt) NumInput() int                              { return -1 }
func (s *rowStmt) Exec([]driver.Value) (driver.Result, error) { return nil, fmt.Errorf("no writes") }
func (s *rowStmt) Query([]driver.Value) (driver.Rows, error) {
	if strings.Contains(s.q, "capture_error") {
		return &rowRows{cols: []string{"captured", "capture_error", "recorded"}, vals: []driver.Value{s.d.raw, s.d.captureErr, true}}, nil
	}
	if strings.HasPrefix(strings.TrimSpace(s.q), "SELECT captured FROM") {
		return &rowRows{cols: []string{"captured"}, vals: []driver.Value{s.d.raw}}, nil
	}
	return nil, fmt.Errorf("unexpected query %q", s.q)
}

type rowRows struct {
	cols []string
	vals []driver.Value
	sent bool
}

func (r *rowRows) Columns() []string { return r.cols }
func (r *rowRows) Close() error      { return nil }
func (r *rowRows) Next(dest []driver.Value) error {
	if r.sent {
		return io.EOF
	}
	r.sent = true
	copy(dest, r.vals)
	return nil
}

func shadowOnRow(t *testing.T, raw []byte, captureErr string) *Shadow {
	t.Helper()
	db := sql.OpenDB(&rowDriver{raw: raw, captureErr: captureErr})
	t.Cleanup(func() { db.Close() })
	return &Shadow{repo: database.NewProofV2ShadowRepository(database.NewClientFromDB(db)), logf: func(string, ...any) {}}
}

func proveStored(t *testing.T, raw []byte, captureErr string) error {
	t.Helper()
	_, err := shadowOnRow(t, raw, captureErr).ProveG1(context.Background(), "f104-intent", "acc://cust.acme/pay", strings.Repeat("ab", 32), "BVN1", 1, true)
	if err == nil {
		t.Fatal("a capture that fell short was proven")
	}
	return err
}

// The F104 path end to end on the fake network: the capture stops with g1_historical_unavailable because the partition's last
// admissible block has left retention (no later block is admissible under D2), the capture is stored as CaptureG1 stores it (the pages
// kept, the error's text), and the certificate's proof returns that refusal as its named state - partition and block included.
func TestAStoredHistoricalRefusalIsProvenAsItsNamedState(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	v := vote("acc://bank.acme/book", "acc://bank.acme/book/2")
	f.facts.Votes = []VoteFact{v}
	f.arrivals[v.Cause.String()] = fakeArrival{"BVN2", 2005} // smallest admissible: 2010, which is also the last one below
	f.anchors["BVN2"] = []fakeAnchor{{480, 2000}, {490, 2010}, {510, 2030}}
	col := f.collector()
	inner := col.Page
	col.Page = func(ctx context.Context, account, p string, block uint64) (*proofv2.PageState, error) {
		if p == "BVN2" && block == 2010 {
			return nil, &proofv2.NamedState{Code: proofv2.StateHistoricalUnavailable, Partition: p, Block: block, Detail: "below the retained range [2020, 2820]"}
		}
		return inner(ctx, account, p, block)
	}
	cp, captureErr := col.Collect(context.Background(), f.facts.Principal.String(), strings.Repeat("ab", 32))
	if captureErr == nil {
		t.Fatal("the capture did not stop as set up")
	}
	var raw []byte
	if cp != nil {
		var err error
		if raw, err = json.Marshal(cp); err != nil {
			t.Fatal(err)
		}
	}

	err := proveStored(t, raw, captureErr.Error())
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateHistoricalUnavailable || ns.Partition != "BVN2" || ns.Block != 2010 {
		t.Fatalf("the stored refusal is not its named state: %v (%+v)", err, ns)
	}
	if !strings.Contains(err.Error(), captureErr.Error()) {
		t.Fatalf("the stored text was not kept: %v", err)
	}
	if cp != nil && !errors.Is(err, ErrPartialCapture) {
		t.Fatalf("a partial capture's answer no longer says so: %v", err)
	}
}

// A capture that stored no pages answers with what it stored. It used to answer "g1_historical_unavailable: no pages were captured at
// discovery" for every such capture, whatever had stopped it and without the partition or block - so a routing failure read as a history
// refusal, and a history refusal lost where it was.
func TestACaptureWithoutPagesAnswersWithWhatItStored(t *testing.T) {
	stored := "route acc://officer-2.acme/book: g1_historical_unavailable{BVN3,17540539}: acc://officer-2.acme/book is below the retained range [17542319, 17543113]"
	err := proveStored(t, nil, stored)
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateHistoricalUnavailable || ns.Partition != "BVN3" || ns.Block != 17540539 {
		t.Fatalf("a stored refusal without pages is not its named state: %v", err)
	}
	if !strings.Contains(err.Error(), stored) || errors.Is(err, ErrPartialCapture) {
		t.Fatalf("answer %v", err)
	}

	other := "routing: dial tcp: connection refused"
	err = proveStored(t, nil, other)
	if errors.As(err, &ns) || !strings.Contains(err.Error(), other) {
		t.Fatalf("a capture that failed for another reason answered %v (named %+v)", err, ns)
	}

	// Nothing stored at all: the old answer stands, and it carries no partition, so it is not the typed refusal.
	err = proveStored(t, nil, "")
	if !strings.Contains(err.Error(), "no pages were captured at discovery") || errors.As(err, &ns) {
		t.Fatalf("a capture that stored nothing answered %v", err)
	}
}

// Only the exact rendering of a history refusal is read back, and only when it names one place: another named state, a rendering without
// a partition or block, or two different places, is text as before.
func TestOnlyAnUnambiguousHistoryRefusalIsReadBack(t *testing.T) {
	for _, tc := range []struct {
		text string
		want *proofv2.NamedState
	}{
		{(&proofv2.NamedState{Code: proofv2.StateHistoricalUnavailable, Partition: "BVN1", Block: 77, Detail: "x"}).Error(),
			&proofv2.NamedState{Code: proofv2.StateHistoricalUnavailable, Partition: "BVN1", Block: 77}},
		{"key book acc://a.acme/book: g1_historical_unavailable{Directory,13445001}: d; again g1_historical_unavailable{Directory,13445001}",
			&proofv2.NamedState{Code: proofv2.StateHistoricalUnavailable, Partition: "Directory", Block: 13445001}},
		{(&proofv2.NamedState{Code: proofv2.StateNotReady, Partition: "BVN1", Block: 77}).Error(), nil},
		{(&proofv2.NamedState{Code: proofv2.StateHistoricalUnavailable, Partition: "BVN1"}).Error(), nil},
		{(&proofv2.NamedState{Code: proofv2.StateHistoricalUnavailable, Block: 77}).Error(), nil},
		{"g1_historical_unavailable: no pages were captured at discovery", nil},
		{"g1_historical_unavailable{BVN1,7} and g1_historical_unavailable{BVN2,8}", nil},
		{"g1_historical_unavailable{BVN1,0}", nil},
		{"xg1_historical_unavailable{BVN1,7}", nil},
		{"g1_historical_unavailable{BVN1,99999999999999999999999}", nil},
	} {
		got := historicalUnavailableIn(tc.text)
		switch {
		case tc.want == nil && got != nil:
			t.Errorf("%q read back as %+v", tc.text, got)
		case tc.want != nil && (got == nil || got.Code != tc.want.Code || got.Partition != tc.want.Partition || got.Block != tc.want.Block):
			t.Errorf("%q read back as %+v, want %+v", tc.text, got, tc.want)
		}
	}
}
