// Copyright 2026 Certen Protocol

package execution

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================================
// The sending key is the validator's registered identity
// =============================================================================
//
// A validator is two addresses that must be one. Its IDENTITY is the registry entry whose BLS key it
// holds: what it attests as, what the settlement windows name, what peers count. Its SENDER is the
// address of the key it signs transactions with (ETH_PRIVATE_KEY): what a settlement's LeafConsumed
// log names, and what it recognises as its own (ownAddress).
//
// Nothing tied them. Live on 2026-09-27 (intent 3b990fe3) validators 4 and 5 attested as their own
// identities but sent - and so recognised as their own - with validator 1's key: each claimed
// validator 1's settlements as "this validator's settlement" and ran its proof cycle, and every
// validator sharing the key raced one nonce sequence (RB3-F64). A validator whose sender is not its
// identity cannot tell its own work from another's, so it does not start.

// SenderAddress is the address this manager signs transactions with; zero when it has no key.
func (ecm *EthereumContractManager) SenderAddress() common.Address {
	if ecm == nil || ecm.auth == nil {
		return common.Address{}
	}
	return ecm.auth.From
}

// CheckSendersAreIdentity requires every configured chain's sending key to be the validator's
// registered identity.
// sendersVerified is set once this process has proven that every chain's sending key is the validator's
// registered identity. Until then nothing is sent and no settlement is claimed (RB3-F64): the check used to
// run in the background after batching was live, so a node with another validator's key could act first.
var sendersVerified atomic.Bool

// errSendersUnverified is why a send or a settlement decision waits.
var errSendersUnverified = errors.New("the sending key has not yet been verified to be this validator's registered " +
	"identity; nothing is sent or claimed until it is (RB3-F64)")

// SendersVerified reports whether the sending keys have been verified this process.
func SendersVerified() bool { return sendersVerified.Load() }

// VerifySendersAreIdentity checks the sending keys against the identity and, when they match, lets this
// process send and claim settlements.
func VerifySendersAreIdentity(resolver *EVMChainResolverImpl, identity string) error {
	if err := CheckSendersAreIdentity(resolver, identity); err != nil {
		return err
	}
	sendersVerified.Store(true)
	return nil
}

func CheckSendersAreIdentity(resolver *EVMChainResolverImpl, identity string) error {
	if resolver == nil {
		return fmt.Errorf("no chain resolver")
	}
	senders := map[int64]common.Address{}
	for _, id := range resolver.Chains() {
		ecm, _, err := resolver.ManagerForChain(id)
		if err != nil {
			return fmt.Errorf("chain %d: %w", id, err)
		}
		senders[id] = ecm.SenderAddress()
	}
	return sendersMatchIdentity(senders, identity)
}

// sendersMatchIdentity is the pure core of CheckSendersAreIdentity.
func sendersMatchIdentity(senders map[int64]common.Address, identity string) error {
	if !common.IsHexAddress(strings.TrimSpace(identity)) {
		return fmt.Errorf("identity %q is not an address", identity)
	}
	want := common.HexToAddress(strings.TrimSpace(identity))
	if len(senders) == 0 {
		return fmt.Errorf("no chain configured to check the sending key against identity %s", want.Hex())
	}
	var bad []string
	for id, s := range senders {
		if s != want {
			bad = append(bad, fmt.Sprintf("chain %d sends as %s", id, s.Hex()))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("this validator's sending key is not its registered identity %s (%s): it would send "+
			"and claim settlements as another validator - set ETH_PRIVATE_KEY to this validator's own key",
			want.Hex(), strings.Join(bad, "; "))
	}
	return nil
}
