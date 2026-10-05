// Copyright 2026 Certen Protocol

package execution

import (
	"testing"

	"github.com/certen/independant-validator/pkg/intent"
)

// A leg that names no chain is not a Sepolia leg. extractLegsForExecCommitment used to give such a leg chain id
// 11155111 ("Default Sepolia"), so its execution commitment bound Sepolia's chain id to a call nobody addressed to
// Sepolia. The intent's legs are refused instead: no leg of it is extracted.
func TestExtractLegsRefusesALegThatNamesNoChain(t *testing.T) {
	ecm := &EthereumContractManager{}
	ci := &intent.CertenIntent{CrossChainData: []byte(`{"legs":[` +
		`{"legId":"a","to":"0x000000000000000000000000000000000000F57a","amountWei":"1","chainId":84532},` +
		`{"legId":"b","to":"0x000000000000000000000000000000000000F57a","amountWei":"1"}]}`)}
	if legs := ecm.extractLegsForExecCommitment(ci, nil); len(legs) != 0 {
		for _, l := range legs {
			t.Logf("leg %s chain %d", l.LegID, l.ChainID)
		}
		t.Fatalf("a leg without a chain id was extracted (%d legs); it must not be given a chain", len(legs))
	}
}

// The control: legs that each name their chain are extracted with that chain.
func TestExtractLegsKeepsEachLegsOwnChain(t *testing.T) {
	ecm := &EthereumContractManager{}
	ci := &intent.CertenIntent{CrossChainData: []byte(`{"legs":[` +
		`{"legId":"a","to":"0x000000000000000000000000000000000000F57a","amountWei":"1","chainId":84532},` +
		`{"legId":"b","to":"0x000000000000000000000000000000000000F57a","amountWei":"2","chainId":11155111}]}`)}
	legs := ecm.extractLegsForExecCommitment(ci, nil)
	if len(legs) != 2 || legs[0].ChainID != 84532 || legs[1].ChainID != 11155111 {
		t.Fatalf("legs = %+v, want chains 84532 and 11155111", legs)
	}
}
