package main

import "testing"

// RB3-F18: a query states only fields the v3 server reads. Expand is a RangeOptions field; ChainQuery and
// DefaultQuery have none (accumulate pkg/api/v3 queries.yml), so a top-level "expand" was sent and ignored.
func TestQueriesCarryOnlyFieldsTheServerReads(t *testing.T) {
	qb := QueryBuilder{}
	start, count, yes := 0, 5, true
	ranged := qb.BuildChainQuery("main", nil, &start, &count, nil, &yes)
	if _, ok := ranged["expand"]; ok {
		t.Fatal("a range query carries a top-level expand")
	}
	if rng, _ := ranged["range"].(map[string]interface{}); rng["expand"] != true {
		t.Fatalf("the range's expand is not set: %v", ranged)
	}
	entry := "ab"
	if q := qb.BuildChainQuery("main", &entry, nil, nil, true, &yes); q["expand"] != nil || q["range"] != nil {
		t.Fatalf("an entry query carries expand or a range: %v", q)
	}
	if q := qb.BuildMsgIDQuery(); q["expand"] != nil {
		t.Fatalf("the message query carries expand: %v", q)
	}
}
