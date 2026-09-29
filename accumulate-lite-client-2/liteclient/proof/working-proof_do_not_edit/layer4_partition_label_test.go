package chained_proof

import "testing"

// A BVN whose partition ID is not BVN<n> - MainNet's only BVN is "Cyclops" - must be addressable. The old parser
// turned every label into "BVN"+upper(suffix), so "Cyclops" was refused and "bvnCyclops" became the nonexistent
// acc://bvn-BVNCYCLOPS.acme (RB5-F21). Numbered labels keep exactly their previous meaning.
func TestBvnPartitionAndPool_PartitionIDsAndNumberedLabels(t *testing.T) {
	cases := []struct{ label, partition, pool string }{
		{"bvn1", "BVN1", "acc://bvn-BVN1.acme/anchors"},
		{"BVN2", "BVN2", "acc://bvn-BVN2.acme/anchors"},
		{" bvn3 ", "BVN3", "acc://bvn-BVN3.acme/anchors"},
		{"Cyclops", "Cyclops", "acc://bvn-Cyclops.acme/anchors"},
		{"Apollo", "Apollo", "acc://bvn-Apollo.acme/anchors"},
	}
	for _, c := range cases {
		p, pool, err := bvnPartitionAndPool(c.label)
		if err != nil {
			t.Errorf("%q: %v", c.label, err)
			continue
		}
		if p != c.partition || pool != c.pool {
			t.Errorf("%q: got (%s, %s), want (%s, %s)", c.label, p, pool, c.partition, c.pool)
		}
	}
	for _, bad := range []string{"", "  ", "bvn", "Directory", "directory", "a/b", "bvn-x.acme"} {
		if _, _, err := bvnPartitionAndPool(bad); err == nil {
			t.Errorf("%q: accepted, want refused", bad)
		}
	}
}
