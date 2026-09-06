package chained_proof

import "testing"

// Two governing books on one partition must yield ONE leg for that partition, chosen the same
// way on every validator, not a refused second leg that fails the whole proof.
func TestOnePerPartitionCollapsesSharedPartitions(t *testing.T) {
	in := []SignerLeg{
		{Account: "acc://underwriting-57007.acme/book/1", Partition: "bvn1", MessageHash: "cc"},
		{Account: "acc://insurer-02873.acme/book/1", Partition: "bvn3", MessageHash: "aa"},
		{Account: "acc://bryan-policy-79140.acme/book/1", Partition: "BVN1", MessageHash: "bb"},
	}
	out := onePerPartition(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 legs (bvn1, bvn3), got %d: %+v", len(out), out)
	}
	if out[0].Partition != "BVN1" || out[0].Account != "acc://bryan-policy-79140.acme/book/1" {
		t.Fatalf("bvn1's leg must be the first account in canonical order, got %+v", out[0])
	}
	if out[1].Partition != "bvn3" {
		t.Fatalf("expected bvn3 second, got %+v", out[1])
	}
	// The input order must not matter.
	again := onePerPartition([]SignerLeg{in[2], in[0], in[1]})
	if again[0].Account != out[0].Account || again[1].Account != out[1].Account {
		t.Fatal("the choice depends on input order; two validators would disagree")
	}
	if len(onePerPartition(nil)) != 0 {
		t.Fatal("nil in, nil out")
	}
}
