// Copyright 2026 Certen Protocol

package consensus

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// A leg names the anchor its chain settles on, or is refused by name
// =============================================================================
//
// Every leg of a signed intent declares the anchor its chain settles on (anchorContract: address,
// functionSelector). The batch path never read it: it settles on the chain's configured
// CertenAnchorV8 (CERTEN_ANCHOR_V8_<chainId>) with createBatchAnchor, whatever the leg said, and the
// validator block recorded the declaration as "what will execute" anyway - the declared address, or
// the anchor's type string when there was none, with call data it made up (a sha256 "selector" and
// sha256(expiry) for a uint256). Intents were signed declaring a retired anchor (0x8398D7EB…5339,
// commitAnchor) and settled on another (RB4-F9).
//
// So an intent is settled only if each of its legs declares the anchor it will actually be settled
// on, and the call made on it; otherwise it is refused, before anything is signed, naming both.
// The bridge declares the live anchor since RB4-B1. The check is admission (pre-signing), where
// every honest validator applies it; the validator block then records the declaration, which is
// now the truth.

// ErrDeclaredAnchorNotLive is a leg that declares an anchor, or a call on it, other than the one its
// chain settles on.
var ErrDeclaredAnchorNotLive = errors.New("declared anchor is not the chain's live anchor")

// BatchAnchorCreateSignature is the call the batch path makes on a chain's anchor (step 1 of a
// member's settlement; pkg/execution settlement_steps.go packs it from the same ABI).
const BatchAnchorCreateSignature = "createBatchAnchor(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes32)"

// BatchAnchorCreateSelector is BatchAnchorCreateSignature's 4-byte selector.
var BatchAnchorCreateSelector = func() [4]byte {
	var s [4]byte
	copy(s[:], crypto.Keccak256([]byte(BatchAnchorCreateSignature))[:4])
	return s
}()

// DeclaredSelector reads a leg's declared function as a 4-byte selector: either the function's
// signature (as the bridge declares it) or its selector in hex.
func DeclaredSelector(declared string) ([4]byte, error) {
	var s [4]byte
	d := strings.TrimSpace(declared)
	if d == "" {
		return s, errors.New("no function declared")
	}
	if strings.Contains(d, "(") {
		copy(s[:], crypto.Keccak256([]byte(d))[:4])
		return s, nil
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(d), "0x"))
	if err != nil || len(raw) != 4 {
		return s, fmt.Errorf("%q is neither a function signature nor a 4-byte selector", declared)
	}
	copy(s[:], raw)
	return s, nil
}

// CheckDeclaredAnchors refuses an intent any of whose legs declares an anchor other than its chain's
// live one (anchorOf), or a call on it other than createBatchAnchor. anchorOf failing is CERTEN
// unable to name the chain's anchor now: that is retried (ErrBatchUnavailable), never held against
// the intent.
func CheckDeclaredAnchors(ci *CertenIntent, anchorOf func(chainID int64) (common.Address, error)) error {
	env, err := ci.ParseCrossChain()
	if err != nil {
		return fmt.Errorf("%w: its legs cannot be read: %v", ErrDeclaredAnchorNotLive, err)
	}
	for i, leg := range env.Legs {
		live, err := anchorOf(leg.ChainID)
		if err != nil {
			return fmt.Errorf("%w: chain %d's anchor cannot be named: %v", ErrBatchUnavailable, leg.ChainID, err)
		}
		declared := strings.TrimSpace(leg.AnchorContract.Address)
		if !common.IsHexAddress(declared) {
			return fmt.Errorf("%w: leg %d (chain %d) declares no anchor address (%q); its chain settles on %s",
				ErrDeclaredAnchorNotLive, i, leg.ChainID, declared, live.Hex())
		}
		if common.HexToAddress(declared) != live {
			return fmt.Errorf("%w: leg %d declares anchor %s on chain %d, which settles on %s",
				ErrDeclaredAnchorNotLive, i, common.HexToAddress(declared).Hex(), leg.ChainID, live.Hex())
		}
		sel, err := DeclaredSelector(leg.AnchorContract.FunctionSelector)
		if err != nil {
			return fmt.Errorf("%w: leg %d (chain %d): %v; the anchor is called with %s",
				ErrDeclaredAnchorNotLive, i, leg.ChainID, err, BatchAnchorCreateSignature)
		}
		if sel != BatchAnchorCreateSelector {
			return fmt.Errorf("%w: leg %d (chain %d) declares the call 0x%x (%s); the anchor is called with %s (0x%x)",
				ErrDeclaredAnchorNotLive, i, leg.ChainID, sel, leg.AnchorContract.FunctionSelector, BatchAnchorCreateSignature, BatchAnchorCreateSelector)
		}
	}
	return nil
}
