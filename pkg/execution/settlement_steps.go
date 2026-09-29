// Copyright 2026 Certen Protocol

package execution

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// The calls a member was settled by
// =============================================================================
//
// The write-back's step entries (step1..3 contract and selector, anchor_contract, function_selector)
// used to be copied from a template consensus built for the retired per-intent workflow: CertenAnchorV3
// createAnchor / executeComprehensiveProof / executeWithGovernance, on the leg's self-declared anchor or
// a compiled-in retired one (0x4C8F… on Sepolia), for the intent's FIRST leg whichever chain the member
// settled on. Every record on Accumulate stated calls the batch path never makes (RB3-F66).
//
// They now state what happened: steps 1 and 2 are the batch anchor calls on the chain's CertenAnchorV8
// - the anchor the batch path settles on, as the strategy registry holds it - with the selectors of the
// ABIs the batch path packs those calls with; step 3 is the settlement transaction as observed on chain:
// the address it called and the function it called.

var (
	// batchAnchorCreateSelector is the V8.2 createBatchAnchor the batch path calls (contracts.CertenAnchorV8_2Batch).
	batchAnchorCreateSelector = hex.EncodeToString(contracts.CreateBatchAnchorV8_2Selector[:])
	// batchAnchorProveSelector is executeComprehensiveProof, packed from the CertenAnchorV4 binding the
	// batch path submits its quorum proof through (BatchProofSubmitter).
	batchAnchorProveSelector = func() string {
		parsed, err := abi.JSON(strings.NewReader(contracts.CertenAnchorV4ABI))
		if err != nil {
			panic(fmt.Sprintf("CertenAnchorV4 ABI: %v", err))
		}
		m, ok := parsed.Methods["executeComprehensiveProof"]
		if !ok {
			panic("CertenAnchorV4 ABI has no executeComprehensiveProof")
		}
		return hex.EncodeToString(m.ID)
	}()
)

// memberSettlementSteps is what a member's write-back says was called.
type memberSettlementSteps struct {
	anchor        common.Address
	step1Selector string
	step2Selector string
	step3Contract string
	step3Selector string
}

// settlementSteps derives the member's calls: the chain's anchor from the registry, and its settlement
// transaction from the observations. Without either, it is an error: nothing is stated in their place.
func (o *UnifiedOrchestrator) settlementSteps(targetChain string, observations []*chain.ObservationResult) (*memberSettlementSteps, error) {
	if o.config == nil || o.config.Registry == nil {
		return nil, fmt.Errorf("no strategy registry to name chain %s's anchor", targetChain)
	}
	cfg, err := o.config.Registry.GetChainConfig(targetChain)
	if err != nil {
		return nil, fmt.Errorf("chain %s: %w", targetChain, err)
	}
	if !common.IsHexAddress(cfg.ContractAddress) || common.HexToAddress(cfg.ContractAddress) == (common.Address{}) {
		return nil, fmt.Errorf("chain %s has no anchor address in the registry (%q)", targetChain, cfg.ContractAddress)
	}
	var settled *chain.ObservationResult
	for _, obs := range observations {
		if obs != nil && common.IsHexAddress(obs.TxTo) && len(obs.TxSelector) == 8 {
			settled = obs
			break
		}
	}
	if settled == nil {
		return nil, fmt.Errorf("no observed settlement transaction states what it called on chain %s", targetChain)
	}
	return &memberSettlementSteps{
		anchor:        common.HexToAddress(cfg.ContractAddress),
		step1Selector: batchAnchorCreateSelector,
		step2Selector: batchAnchorProveSelector,
		step3Contract: common.HexToAddress(settled.TxTo).Hex(),
		step3Selector: strings.ToLower(settled.TxSelector),
	}, nil
}
