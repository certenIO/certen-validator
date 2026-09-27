// Copyright 2026 Certen Protocol

package consensus

import (
	"fmt"
	"github.com/certen/independant-validator/pkg/envvar"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// RB-1 / CRITICAL-003: a leg executes exactly what the user committed to
// =============================================================================
//
// Enforced at batch admission (the only path that settles an intent). The per-intent path that
// was removed enforced these same rules at leg extraction; the batch path decoded calldata and
// enforced none of them (RB3-F40). They are the single definition now - pkg/execution delegates
// to ContractCallsAllowed and ComputeExecutionCommitment, so what admission checks is exactly what
// the member's leaf binds.

// ContractCallsAllowed reports whether this deployment executes arbitrary contract calls (legs with
// non-empty calldata). Default OFF: proof-gated arbitrary calls are a deliberate opt-in per
// deployment via CERTEN_ALLOW_CONTRACT_CALLS.
//
// A value that is not a switch is refused: it used to mean "off", so a typo in an opt-in was silent.
func ContractCallsAllowed() (bool, error) {
	return envvar.Bool("CERTEN_ALLOW_CONTRACT_CALLS", false)
}

// ComputeExecutionCommitment is keccak256(abi.encodePacked(uint256 chainId, address target,
// uint256 value, bytes32 keccak256(callData))) - the commitment CertenAccountV7 recomputes from
// the runtime call and a member's leaf binds.
func ComputeExecutionCommitment(chainID int64, target common.Address, value *big.Int, callData []byte) [32]byte {
	dataHash := crypto.Keccak256Hash(callData)

	chainIDBytes := make([]byte, 32)
	big.NewInt(chainID).FillBytes(chainIDBytes)

	valueBytes := make([]byte, 32)
	if value != nil {
		value.FillBytes(valueBytes)
	}

	packed := make([]byte, 0, 116) // 32 + 20 + 32 + 32
	packed = append(packed, chainIDBytes...)
	packed = append(packed, target.Bytes()...)
	packed = append(packed, valueBytes...)
	packed = append(packed, dataHash.Bytes()...)

	return crypto.Keccak256Hash(packed)
}

// checkLegCommitment refuses a leg whose executed (target, value, calldata) is not what the user
// committed to, or a contract call this deployment does not execute:
//
//   - calldata only when ContractCallsAllowed;
//   - a contract call must carry both dataHash and executionCommitment (never skip-then-run);
//   - keccak256(calldata) must equal dataHash when one is given;
//   - executionCommitment, when given, must equal ComputeExecutionCommitment for the chain the leg
//     EXECUTES on (the member's chain, not a self-declared one) and the executed target, value and
//     calldata;
//   - a contract call must commit the effects its success is proven by (checkCommittedEffects).
//
// A native transfer with no commitment is accepted: its leaf binds (target, value, empty calldata)
// all the same, and the account recomputes it from the runtime call.
func checkLegCommitment(i int, chainID int64, target [20]byte, value *big.Int, data []byte, ep *ExecutionPayload) error {
	isContractCall := len(data) > 0
	allowed, err := ContractCallsAllowed()
	if err != nil {
		return fmt.Errorf("leg %d: %w", i, err)
	}
	if isContractCall && !allowed {
		return fmt.Errorf("leg %d carries contract calldata but this deployment does not execute contract calls "+
			"(CERTEN_ALLOW_CONTRACT_CALLS is not enabled)", i)
	}
	if ep == nil {
		if isContractCall {
			return fmt.Errorf("leg %d is a contract call with no execution payload to commit it", i)
		}
		return nil
	}
	if isContractCall && (strings.TrimSpace(ep.ExecutionCommitment) == "" || strings.TrimSpace(ep.DataHash) == "") {
		return fmt.Errorf("leg %d is a contract call without both executionCommitment and dataHash", i)
	}
	if dh := strings.TrimSpace(ep.DataHash); dh != "" {
		if !isHash32(dh) {
			return fmt.Errorf("leg %d dataHash is not a 32-byte hex hash: %q", i, dh)
		}
		if crypto.Keccak256Hash(data) != common.HexToHash(dh) {
			return fmt.Errorf("leg %d calldata does not hash to its committed dataHash", i)
		}
	}
	if ec := strings.TrimSpace(ep.ExecutionCommitment); ec != "" {
		if !isHash32(ec) {
			return fmt.Errorf("leg %d executionCommitment is not a 32-byte hex hash: %q", i, ec)
		}
		if ep.ChainID != 0 && ep.ChainID != chainID {
			return fmt.Errorf("leg %d executionCommitment is declared for chain %d but the leg executes on chain %d",
				i, ep.ChainID, chainID)
		}
		want := ComputeExecutionCommitment(chainID, common.BytesToAddress(target[:]), value, data)
		if common.Hash(want) != common.HexToHash(ec) {
			return fmt.Errorf("leg %d executionCommitment does not match the target, value and calldata it would execute "+
				"on chain %d", i, chainID)
		}
	}
	if isContractCall {
		return checkCommittedEffects(i, ep)
	}
	return nil
}

// checkCommittedEffects refuses a contract call whose success could never be proven.
//
// A call that does not revert has not necessarily done anything: a call to an address with no code, or
// to a function that silently returns, succeeds too. So a contract call's result is attested only
// against the effects it committed to - at least one event it must emit (RB-4), and optionally storage
// slots it must set (RB-5) - which the Phase 7 gate proves from the inclusion-proven receipt. A call
// committing no event used to be admitted, settled and paid for, and then refused at attestation, its
// result written back nowhere (RB3-F65, intent 3b990fe3). It is refused here, by name, before anything
// is signed or spent. Each committed effect must also be well formed: the gate would read a malformed
// address as the zero address and skip an event without a topic.
func checkCommittedEffects(i int, ep *ExecutionPayload) error {
	if len(ep.ExpectedEvents) == 0 {
		return fmt.Errorf("leg %d is a contract call that commits no event: success could not be told apart from a call "+
			"that did nothing, so its result could never be attested - commit the event(s) it must emit (expectedEvents)", i)
	}
	for j, e := range ep.ExpectedEvents {
		if !common.IsHexAddress(strings.TrimSpace(e.Contract)) {
			return fmt.Errorf("leg %d expected event %d names no contract address (%q)", i, j, e.Contract)
		}
		if !isHash32(strings.TrimSpace(e.Topic0)) {
			return fmt.Errorf("leg %d expected event %d topic0 is not a 32-byte hash: %q", i, j, e.Topic0)
		}
		if dh := strings.TrimSpace(e.DataHash); dh != "" && !isHash32(dh) {
			return fmt.Errorf("leg %d expected event %d dataHash is not a 32-byte hash: %q", i, j, e.DataHash)
		}
	}
	for j, s := range ep.ExpectedState {
		if !common.IsHexAddress(strings.TrimSpace(s.Account)) {
			return fmt.Errorf("leg %d expected state %d names no account address (%q)", i, j, s.Account)
		}
		if !isHash32(strings.TrimSpace(s.Slot)) || !isHash32(strings.TrimSpace(s.Value)) {
			return fmt.Errorf("leg %d expected state %d slot and value must be 32-byte hashes", i, j)
		}
	}
	return nil
}

// isHash32 reports whether s is a 0x-prefixed or bare 64-hex-digit string.
func isHash32(s string) bool {
	h := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}
