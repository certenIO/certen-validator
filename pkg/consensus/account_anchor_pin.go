// Copyright 2026 Certen Protocol

package consensus

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// Account anchor pin — no intent may point an account away from CERTEN's anchors
// =============================================================================
//
// A CertenAccountV7 trusts exactly one anchor contract (anchorContract) to say whether an anchor
// exists and whether a proof is valid. The account can change that pointer only by calling its own
// setAnchorContract (onlySelf), which an attested intent reaches with a leg whose target is the
// account itself. Pointed at a contract that answers "yes" to everything, the account would execute
// anything anyone sends - it would have left CERTEN, irreversibly, and every guarantee CERTEN gives
// about it (including that a failure it recorded stays final) would be void.
//
// So validators refuse any intent with such a leg unless its new anchor is one CERTEN runs on that
// chain. Every other call an account makes to itself - roles, key books, operation requirements -
// changes only its internal governance, never what authorizes an execution, and is allowed. This
// needs no contract change; the upcoming contract release can pin it on chain.

// ErrAnchorRepointRefused is an intent that would point an account at an anchor CERTEN does not run.
var ErrAnchorRepointRefused = errors.New("account anchor repoint refused")

// setAnchorContractSelector is CertenAccountV7.setAnchorContract(address).
var setAnchorContractSelector = crypto.Keccak256([]byte("setAnchorContract(address)"))[:4]

// AccountAnchorPolicy names the anchors an account may be pointed at on a chain.
type AccountAnchorPolicy interface {
	AllowedAccountAnchor(chainID int64, anchor common.Address) bool
}

// CheckAccountAnchorCall checks one call an account makes: target is where it is sent, data its
// calldata. A call to the account itself that selects setAnchorContract must name an allowed anchor;
// a malformed one is refused, since what it would do cannot be read. A nil policy allows nothing.
func CheckAccountAnchorCall(policy AccountAnchorPolicy, chainID int64, account, target common.Address, data []byte) error {
	if target != account || len(data) < 4 || !bytes.Equal(data[:4], setAnchorContractSelector) {
		return nil
	}
	if len(data) != 4+32 || !bytes.Equal(data[4:16], make([]byte, 12)) {
		return fmt.Errorf("%w: account %s: malformed setAnchorContract call", ErrAnchorRepointRefused, account.Hex())
	}
	anchor := common.BytesToAddress(data[16:36])
	if policy == nil || !policy.AllowedAccountAnchor(chainID, anchor) {
		return fmt.Errorf("%w: account %s on chain %d would be pointed at %s, which is not a CERTEN anchor on that chain",
			ErrAnchorRepointRefused, account.Hex(), chainID, anchor.Hex())
	}
	return nil
}

// CheckIntentAccountAnchors applies CheckAccountAnchorCall to every leg of an intent, from the raw
// execution payloads the user signed. It reads the legs directly rather than through batch
// extraction, so an intent the batch path cannot represent is checked all the same. A leg whose
// source or target cannot be read, but whose calldata selects setAnchorContract, is refused.
func CheckIntentAccountAnchors(policy AccountAnchorPolicy, ci *CertenIntent) error {
	if ci == nil {
		return nil
	}
	env, err := ci.ParseCrossChain()
	if err != nil {
		// No legs can be read, so none can be executed either; the intent fails elsewhere.
		return nil
	}
	for i, leg := range env.Legs {
		ep := leg.ExecutionPayload
		if ep == nil {
			continue
		}
		var data []byte
		if cd := strings.TrimPrefix(ep.CallData, "0x"); cd != "" {
			data, err = hex.DecodeString(cd)
			if err != nil {
				continue // malformed calldata cannot be executed; the intent fails elsewhere
			}
		}
		if len(data) < 4 || !bytes.Equal(data[:4], setAnchorContractSelector) {
			continue
		}
		if !common.IsHexAddress(leg.From) || !common.IsHexAddress(ep.Target) {
			return fmt.Errorf("%w: leg %d selects setAnchorContract with an unreadable source or target",
				ErrAnchorRepointRefused, i)
		}
		chainID := ep.ChainID
		if chainID == 0 {
			chainID = leg.ChainID
		}
		if err := CheckAccountAnchorCall(policy, chainID, common.HexToAddress(leg.From),
			common.HexToAddress(ep.Target), data); err != nil {
			return fmt.Errorf("leg %d: %w", i, err)
		}
	}
	return nil
}
