// Copyright 2026 Certen Protocol

package main

import (
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func table() map[string]proofv2.ExecutorActivation { return proofv2.KermitExecutorActivations() }

func shows() map[string][]Observed {
	out := map[string][]Observed{}
	for k, a := range table() {
		out[k] = []Observed{{Version: a.Version, Block: a.Block}}
	}
	return out
}

func TestTheCompiledTableEqualsItself(t *testing.T) {
	if d := Compare(table(), shows()); len(d) != 0 {
		t.Fatal(d)
	}
}

func TestEveryKindOfDifferenceIsReported(t *testing.T) {
	for name, mut := range map[string]func(map[string][]Observed){
		"another block":   func(o map[string][]Observed) { o["bvn2"][0].Block++ },
		"another version": func(o map[string][]Observed) { o["bvn1"][0].Version = protocol.ExecutorVersionV2Baikonur },
		"a second activation": func(o map[string][]Observed) {
			o["directory"] = append(o["directory"], Observed{Version: protocol.ExecutorVersionV2Kourou + 1, Block: 9_999_999})
		},
		"no activation": func(o map[string][]Observed) { o["bvn3"] = nil },
		"a partition added": func(o map[string][]Observed) {
			o["bvn4"] = []Observed{{Version: protocol.ExecutorVersionV2Kourou, Block: 1}}
		},
		"a partition not read": func(o map[string][]Observed) { delete(o, "bvn1") },
	} {
		o := shows()
		mut(o)
		if d := Compare(table(), o); len(d) == 0 {
			t.Fatalf("%s: no difference reported", name)
		}
	}
}

func TestPartitionADIsAreTheCompiledPartitions(t *testing.T) {
	adis := partitionADIs(table())
	if len(adis) != 4 || adis["directory"].String() != "acc://dn.acme" || adis["bvn2"].String() != "acc://bvn-BVN2.acme" {
		t.Fatalf("%v", adis)
	}
}
