package accumulate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// blockServer answers v3 block queries from a table keyed by "scope|height", using the record shape
// Kermit returns (captured 2026-09-21): index, time and source at the top level of the result.
func blockServer(t *testing.T, records map[string]map[string]interface{}) (*LiteClientAdapter, *[]string) {
	t.Helper()
	var scopes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Scope string `json:"scope"`
				Query struct {
					Minor int64 `json:"minor"`
				} `json:"query"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		scopes = append(scopes, req.Params.Scope)
		key := strings.ToLower(req.Params.Scope) + "|" + jsonInt(req.Params.Query.Minor)
		out := map[string]interface{}{"jsonrpc": "2.0", "id": 1}
		if rec, ok := records[key]; ok {
			out["result"] = rec
		} else {
			out["error"] = map[string]interface{}{"code": -33404, "message": "cannot locate ledger for block"}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return &LiteClientAdapter{config: &LiteClientConfig{NetworkURL: srv.URL}, httpClient: srv.Client()}, &scopes
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestMinorBlockTime_ReadsThePartitionsOwnBlock(t *testing.T) {
	l, scopes := blockServer(t, map[string]map[string]interface{}{
		"acc://bvn-bvn1.acme/ledger|8000000": {
			"recordType": "minorBlock", "index": 8000000, "time": "2026-07-27T23:43:08Z", "source": "acc://bvn-BVN1.acme",
		},
	})
	// The intent carries its partition lowercased; Accumulate URLs are case-insensitive.
	got, err := l.MinorBlockTime(context.Background(), "acc://bvn-bvn1.acme/ledger", 8000000)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 7, 27, 23, 43, 8, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("block time %s, want %s", got, want)
	}
	if len(*scopes) != 1 || (*scopes)[0] != "acc://bvn-bvn1.acme/ledger" {
		t.Fatalf("queried %v", *scopes)
	}
}

// Live, acc://bvn1.acme/ledger is not BVN1's ledger: it is routed like any account and BVN3 answers
// with ITS block 8000000, 2 minutes off BVN1's. Such an answer must never be taken as the time.
func TestMinorBlockTime_RefusesAnAnswerFromAnotherPartition(t *testing.T) {
	l, _ := blockServer(t, map[string]map[string]interface{}{
		"acc://bvn1.acme/ledger|8000000": {
			"recordType": "minorBlock", "index": 8000000, "time": "2026-07-27T23:40:55Z", "source": "acc://bvn-BVN3.acme",
		},
	})
	if _, err := l.MinorBlockTime(context.Background(), "acc://bvn1.acme/ledger", 8000000); err == nil {
		t.Fatal("accepted BVN3's block as bvn1's")
	}
}

func TestMinorBlockTime_FailsRatherThanGuess(t *testing.T) {
	good := map[string]interface{}{"index": 7, "time": "2026-07-27T23:43:08Z", "source": "acc://bvn-BVN1.acme"}
	with := func(k string, v interface{}) map[string]interface{} {
		m := map[string]interface{}{}
		for kk, vv := range good {
			m[kk] = vv
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, rec := range map[string]map[string]interface{}{
		"another height": with("index", 8),
		"no height":      with("index", nil),
		"no time":        with("time", nil),
		"bad time":       with("time", "yesterday"),
		"no source":      with("source", nil),
	} {
		t.Run(name, func(t *testing.T) {
			l, _ := blockServer(t, map[string]map[string]interface{}{"acc://bvn-bvn1.acme/ledger|7": rec})
			if got, err := l.MinorBlockTime(context.Background(), "acc://bvn-BVN1.acme/ledger", 7); err == nil {
				t.Fatalf("returned %s", got)
			}
		})
	}
	t.Run("block not recorded", func(t *testing.T) {
		l, _ := blockServer(t, nil)
		if _, err := l.MinorBlockTime(context.Background(), "acc://bvn-BVN1.acme/ledger", 7); err == nil {
			t.Fatal("no error for a block the partition does not record")
		}
	})
	t.Run("no partition or height", func(t *testing.T) {
		l, scopes := blockServer(t, nil)
		if _, err := l.MinorBlockTime(context.Background(), "", 7); err == nil {
			t.Fatal("no error without a partition")
		}
		if _, err := l.MinorBlockTime(context.Background(), "acc://bvn-BVN1.acme/ledger", 0); err == nil {
			t.Fatal("no error without a height")
		}
		if len(*scopes) != 0 {
			t.Fatal("queried without a partition or height")
		}
	})
}
