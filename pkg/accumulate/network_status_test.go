// Copyright 2026 Certen Protocol

package accumulate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeV3 answers network-status as told and every block query with a BVN block at height 777.
func fakeV3(t *testing.T, status func() (interface{}, bool)) *LiteClientAdapter {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "network-status" {
			if res, ok := status(); ok {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": res})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1,
				"error": map[string]interface{}{"code": -32000, "message": "unavailable"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{
			"recordType": "minorBlock", "index": 777, "time": "2026-09-27T09:59:42Z"}})
	}))
	t.Cleanup(srv.Close)
	a, err := NewLiteClientAdapter(&LiteClientConfig{NetworkURL: srv.URL, RequestTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// RB3-F104: the latest height is the Directory Network's, from network-status, or an error. A failed
// network-status used to become "the latest block of whichever partition answers" - here a BVN block
// at 777 - which GetBlock then read as a DN height.
func TestTheLatestHeightIsTheDirectoryNetworksOrAnError(t *testing.T) {
	a := fakeV3(t, func() (interface{}, bool) { return nil, false })
	if st, err := a.getNetworkStatusV3(context.Background()); err == nil {
		t.Fatalf("network-status failed and a height was produced anyway: %d", st.Network.Status.LastBlockHeight)
	}

	a = fakeV3(t, func() (interface{}, bool) {
		return map[string]interface{}{"directoryHeight": 9912973, "network": map[string]interface{}{"networkName": "DevNet"}}, true
	})
	st, err := a.getNetworkStatusV3(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Network.Status.LastBlockHeight != 9912973 || st.Network.ID != "DevNet" {
		t.Fatalf("status %+v; want DN height 9912973 on DevNet, as network-status said", st.Network)
	}
	if st.Network.Status.LastBlockHash != "" || st.Network.Status.LastBlockTime != "" || st.Network.Type != "" {
		t.Fatalf("status states what network-status did not: %+v", st.Network)
	}
}

// A minor block record without a readable time is refused; it used to carry the zero time into the
// intent's BlockTime.
func TestAMinorBlockWithoutItsTimeIsRefused(t *testing.T) {
	a := &LiteClientAdapter{}
	if _, err := a.parseMinorBlockRecord(map[string]interface{}{"index": 5.0}, "acc://bvn-BVN1.acme", 5); err == nil {
		t.Fatal("a block with no time was accepted")
	}
	if _, err := a.parseMinorBlockRecord(map[string]interface{}{"index": 5.0, "time": "yesterday"}, "acc://bvn-BVN1.acme", 5); err == nil {
		t.Fatal("a block with an unreadable time was accepted")
	}
	b, err := a.parseMinorBlockRecord(map[string]interface{}{"index": 5.0, "time": "2026-09-27T09:59:42Z"}, "acc://bvn-BVN1.acme", 5)
	if err != nil || !b.Time.Equal(time.Date(2026, 9, 27, 9, 59, 42, 0, time.UTC)) {
		t.Fatalf("(%+v, %v)", b, err)
	}
}
