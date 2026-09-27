package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// rangeClient serves an account chain of `size` entries; a page larger than maxPage cannot be delivered
// (the endpoint's cut), and `drop`/`misindex` corrupt one answer.
type rangeClient struct {
	size, maxPage  int
	drop, misindex int
	calls          []int
}

func (c *rangeClient) Query(ctx context.Context, scope string, q map[string]interface{}) (map[string]interface{}, error) {
	raw, err := c.QueryRaw(ctx, scope, q)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	return m, json.Unmarshal(raw, &m)
}

func (c *rangeClient) QueryRaw(_ context.Context, _ string, q map[string]interface{}) ([]byte, error) {
	rg := q["range"].(map[string]interface{})
	start, count := rg["start"].(int), rg["count"].(int)
	c.calls = append(c.calls, count)
	if count > c.maxPage {
		return nil, errors.New("Failed to read response: unexpected EOF")
	}
	var recs []interface{}
	for i := start; i < start+count && i < c.size; i++ {
		if i == c.drop {
			continue
		}
		idx := i
		if i == c.misindex {
			idx = i + 100
		}
		recs = append(recs, map[string]interface{}{"recordType": "chainEntry", "index": idx, "entry": "ab"})
	}
	return json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"recordType": "range", "records": recs}})
}

func (c *rangeClient) GetEndpoint() string { return "test" }

func TestTheRangeReaderReadsExactlyWhatWasAsked(t *testing.T) {
	am, err := NewArtifactManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Pages of 50 cannot be delivered; 12 can: the reader halves until they are, and reads all 120.
	c := &rangeClient{size: 120, maxPage: 12, drop: -1, misindex: -1}
	recs, err := readChainRange(context.Background(), am, c, "t", "acc://x.acme/data", "main", 0, 120, 50, true)
	if err != nil || len(recs) != 120 {
		t.Fatalf("(%d records, %v)", len(recs), err)
	}
	for i, r := range recs {
		if idx, _ := chainIndexOf(r); idx != i {
			t.Fatalf("record %d has index %d", i, idx)
		}
	}
	// A record that cannot be delivered even alone is an error.
	if _, err := readChainRange(context.Background(), am, &rangeClient{size: 10, maxPage: 0, drop: -1, misindex: -1}, "t", "s", "main", 0, 10, 50, true); err == nil {
		t.Fatal("an undeliverable chain was read")
	}
	// A short answer or one out of order is an error, never a shorter or reordered result.
	if _, err := readChainRange(context.Background(), am, &rangeClient{size: 30, maxPage: 50, drop: 17, misindex: -1}, "t", "s", "main", 0, 30, 50, true); err == nil {
		t.Fatal("a chain with a missing entry was read")
	}
	if _, err := readChainRange(context.Background(), am, &rangeClient{size: 30, maxPage: 50, drop: -1, misindex: 5}, "t", "s", "main", 0, 30, 50, true); err == nil {
		t.Fatal("a chain with an entry at the wrong index was read")
	}
}
