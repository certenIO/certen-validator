package accumulate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// RB3-F125: a DN block is searched completely - every BVN block it anchored, every entry of each - or the
// search is an error. It used to drop a partition whose query failed (about 2% of DN blocks on Kermit,
// whose endpoint cuts responses near 98 KB), query the BVNs at the DN's height, and read "up to 500"
// entries of a block.

const (
	dnH       = 100
	intentTx  = "cbe521460586cd0550118d29ad3ff0ebfbf196fa13db248c0acd54c647c2485c"
	bvn1Block = 500
	bvn2Block = 600
)

// dnFake is a v3 API with a DN block (anchoring BVN1 500 and BVN2 600), the anchor pool's index and main
// chains, and the two BVN blocks. BVN1 500 has 12 entries, the last a CERTEN intent.
type dnFake struct {
	mu              sync.Mutex
	routeToDN       bool
	dnNotFound      bool
	dnAnchorsIndexH int64 // the DN block the second index entry names
	truncate        func(scope string, query map[string]interface{}) bool
	shortPage       bool
	notAnAnchor     bool
	blockQueries    []string
}

func (f *dnFake) entry(account string, i int, intent bool) map[string]interface{} {
	memo := ""
	if intent {
		memo = "CERTEN_INTENT"
	}
	hash := fmt.Sprintf("%064x", i+1)
	if intent {
		hash = intentTx
	}
	return map[string]interface{}{
		"recordType": "chainEntry", "account": account, "name": "main", "type": "transaction", "index": float64(i), "entry": hash,
		"value": map[string]interface{}{"recordType": "message", "id": "acc://" + hash + "@" + strings.TrimPrefix(account, "acc://"),
			"message": map[string]interface{}{"type": "transaction", "transaction": map[string]interface{}{
				"header": map[string]interface{}{"principal": account, "memo": memo},
				"body":   map[string]interface{}{"type": "writeData", "entry": map[string]interface{}{"type": "doubleHash", "data": []interface{}{"00"}}},
			}}},
	}
}

func (f *dnFake) block(scope string, minor int64, start, count int) (map[string]interface{}, *V3APIError) {
	var total int
	var mk func(i int) map[string]interface{}
	switch {
	case scope == "acc://dn.acme/ledger" && minor == dnH:
		if f.dnNotFound {
			return nil, &V3APIError{Code: v3NotFound, Message: "cannot locate ledger for block"}
		}
		total, mk = 3, func(i int) map[string]interface{} { return f.entry("acc://dn.acme/anchors", i, false) }
	case scope == "acc://bvn-bvn1.acme/ledger" && minor == bvn1Block:
		total, mk = 12, func(i int) map[string]interface{} { return f.entry("acc://user.acme/data", i, i == 11) }
	case scope == "acc://bvn-bvn2.acme/ledger" && minor == bvn2Block:
		total, mk = 2, func(i int) map[string]interface{} { return f.entry("acc://other.acme/data", i, false) }
	default:
		return nil, &V3APIError{Code: v3NotFound, Message: "cannot locate ledger for block"}
	}
	src := map[string]string{"acc://dn.acme/ledger": "acc://dn.acme", "acc://bvn-bvn1.acme/ledger": "acc://bvn-BVN1.acme", "acc://bvn-bvn2.acme/ledger": "acc://bvn-BVN2.acme"}[scope]
	var recs []interface{}
	for i := start; i < total && i < start+count; i++ {
		recs = append(recs, mk(i))
	}
	if f.shortPage && scope == "acc://bvn-bvn1.acme/ledger" && start >= 10 {
		recs = nil // the server claims 12 entries but hands back none past 10
	}
	rng := map[string]interface{}{"recordType": "range", "start": float64(start), "total": float64(total)}
	if len(recs) > 0 {
		rng["records"] = recs
	}
	return map[string]interface{}{"recordType": "minorBlock", "index": float64(minor), "time": "2026-09-27T14:12:55Z", "source": src, "entries": rng}, nil
}

func (f *dnFake) chain(scope, name string, start, count int64) (map[string]interface{}, *V3APIError) {
	type idx struct{ source, block int64 }
	index := []idx{{4, dnH - 1}, {7, f.dnAnchorsIndexH}}
	anchors := map[int64][2]interface{}{
		5: {"acc://bvn-BVN1.acme", float64(bvn1Block)},
		6: {"acc://dn.acme", float64(dnH - 1)},
		7: {"acc://bvn-BVN2.acme", float64(bvn2Block)},
	}
	if scope != dnAnchorPool {
		return nil, &V3APIError{Code: v3NotFound, Message: "no such chain"}
	}
	if count < 0 { // count query
		n := map[string]int64{"main-index": int64(len(index)), "main": 8}[name]
		return map[string]interface{}{"recordType": "chain", "name": name, "count": float64(n)}, nil
	}
	var recs []interface{}
	for i := start; i < start+count; i++ {
		switch name {
		case "main-index":
			if i >= int64(len(index)) {
				continue
			}
			recs = append(recs, map[string]interface{}{"recordType": "chainEntry", "index": float64(i),
				"value": map[string]interface{}{"recordType": "indexEntry", "value": map[string]interface{}{"source": float64(index[i].source), "blockIndex": float64(index[i].block)}}})
		case "main":
			a, ok := anchors[i]
			typ := "blockValidatorAnchor"
			if a[0] == "acc://dn.acme" {
				typ = "directoryAnchor"
			}
			if f.notAnAnchor && i == 7 {
				typ = "writeData"
			}
			if !ok {
				continue
			}
			recs = append(recs, map[string]interface{}{"recordType": "chainEntry", "index": float64(i),
				"value": map[string]interface{}{"recordType": "message", "message": map[string]interface{}{"transaction": map[string]interface{}{
					"body": map[string]interface{}{"type": typ, "source": a[0], "minorBlockIndex": a[1]}}}}})
		}
	}
	return map[string]interface{}{"recordType": "range", "records": recs}, nil
}

func (f *dnFake) serve(t *testing.T) *LiteClientAdapter {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params struct {
				Scope string                 `json:"scope"`
				Query map[string]interface{} `json:"query"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		var result map[string]interface{}
		var apiErr *V3APIError
		scope := strings.ToLower(req.Params.Scope)
		q := req.Params.Query
		switch {
		case req.Method == "network-status":
			part := "BVN1"
			if f.routeToDN {
				part = "Directory"
			}
			result = map[string]interface{}{"routing": map[string]interface{}{
				"routes":    []interface{}{map[string]interface{}{"partition": part}, map[string]interface{}{"partition": "BVN2"}},
				"overrides": []interface{}{map[string]interface{}{"account": "acc://dn.acme", "partition": "Directory"}},
			}}
		case q["queryType"] == "block":
			er, _ := q["entryRange"].(map[string]interface{})
			start, _ := er["start"].(float64)
			count, _ := er["count"].(float64)
			f.blockQueries = append(f.blockQueries, fmt.Sprintf("%s|%v|%v", scope, q["minor"], start))
			if f.truncate != nil && f.truncate(scope, q) {
				w.Header().Set("Content-Length", "100000")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"recordType":"minorBlock","ind`))
				return
			}
			result, apiErr = f.block(scope, int64(q["minor"].(float64)), int(start), int(count))
		case q["queryType"] == "chain":
			if rg, ok := q["range"].(map[string]interface{}); ok {
				result, apiErr = f.chain(req.Params.Scope, q["name"].(string), int64(rg["start"].(float64)), int64(rg["count"].(float64)))
			} else {
				result, apiErr = f.chain(req.Params.Scope, q["name"].(string), 0, -1)
			}
		default:
			apiErr = &V3APIError{Code: -32601, Message: "unexpected query"}
		}
		out := map[string]interface{}{"jsonrpc": "2.0", "id": 1}
		if apiErr != nil {
			out["error"] = map[string]interface{}{"code": apiErr.Code, "message": apiErr.Message}
		} else {
			out["result"] = result
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return &LiteClientAdapter{config: &LiteClientConfig{NetworkURL: srv.URL}, httpClient: &http.Client{Timeout: 10 * time.Second}}
}

func newFake() *dnFake { return &dnFake{dnAnchorsIndexH: dnH} }

func TestADNBlockIsSearchedThroughEveryAnchoredBlock(t *testing.T) {
	f := newFake()
	txs, err := f.serve(t).SearchCertenTransactions(context.Background(), dnH)
	if err != nil {
		t.Fatal(err)
	}
	if len(txs) != 1 || !strings.EqualFold(txs[0].Hash, intentTx) || txs[0].BlockHeight != dnH || txs[0].AccountURL != "acc://user.acme/data" {
		t.Fatalf("found %+v; want the one intent, at DN height %d", txs, dnH)
	}
	// The BVNs were read at their own block, never at the DN's height.
	for _, q := range f.blockQueries {
		if strings.HasPrefix(q, "acc://bvn") && strings.Contains(q, fmt.Sprintf("|%d|", dnH)) {
			t.Fatalf("a BVN was queried at the DN's height: %s", q)
		}
	}
}

func TestAnUndeliverablePageIsAnErrorNotAPartialBlock(t *testing.T) {
	f := newFake()
	// The page holding the intent cannot be delivered at any size.
	f.truncate = func(scope string, q map[string]interface{}) bool {
		er := q["entryRange"].(map[string]interface{})
		return scope == "acc://bvn-bvn1.acme/ledger" && er["start"].(float64) >= 10
	}
	if txs, err := f.serve(t).SearchCertenTransactions(context.Background(), dnH); err == nil {
		t.Fatalf("a block whose last page could not be read was searched: %v", txs)
	}

	// A page too big as ten entries but deliverable as fewer is read in smaller pages.
	g := newFake()
	g.truncate = func(scope string, q map[string]interface{}) bool {
		er := q["entryRange"].(map[string]interface{})
		return scope == "acc://bvn-bvn1.acme/ledger" && er["count"].(float64) > 2
	}
	txs, err := g.serve(t).SearchCertenTransactions(context.Background(), dnH)
	if err != nil || len(txs) != 1 {
		t.Fatalf("a block readable in smaller pages: (%v, %v)", txs, err)
	}
}

func TestEntriesShortOfTheTotalAreAnError(t *testing.T) {
	f := newFake()
	f.shortPage = true
	if _, err := f.serve(t).SearchCertenTransactions(context.Background(), dnH); err == nil {
		t.Fatal("a block that delivered 10 of 12 entries was searched")
	}
}

func TestANotFoundDNBlockIsEmptyOnlyIfNothingWasAnchoredInIt(t *testing.T) {
	f := newFake()
	f.dnNotFound = true
	f.dnAnchorsIndexH = dnH + 1 // the index names no anchors for dnH
	txs, err := f.serve(t).SearchCertenTransactions(context.Background(), dnH)
	if err != nil || len(txs) != 0 {
		t.Fatalf("a DN block with no ledger and no anchors: (%v, %v)", txs, err)
	}
	g := newFake()
	g.dnNotFound = true // but the index says it anchored blocks
	if _, err := g.serve(t).SearchCertenTransactions(context.Background(), dnH); err == nil {
		t.Fatal("a not-found DN block the index says anchored blocks was taken as empty")
	}
}

func TestDiscoveryRefusesIfUserAccountsCanLiveOnTheDN(t *testing.T) {
	f := newFake()
	f.routeToDN = true
	if _, err := f.serve(t).SearchCertenTransactions(context.Background(), dnH); err == nil || !strings.Contains(err.Error(), "Directory") {
		t.Fatalf("routing to the Directory Network: %v", err)
	}
}

func TestAnAnchorEntryThatIsNotAnAnchorIsAnError(t *testing.T) {
	f := newFake()
	f.notAnAnchor = true
	if _, err := f.serve(t).SearchCertenTransactions(context.Background(), dnH); err == nil {
		t.Fatal("an anchor-pool entry that is not an anchor was skipped")
	}
}
