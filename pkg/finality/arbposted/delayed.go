// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// L1 message type of an ETH deposit (nitro arbos/l1pricing / arbostypes L1MessageType_EthDeposit); it becomes an
// ArbitrumDepositTx (type 0x64) whose request id is the delayed message index.
const (
	msgKindEthDeposit = 12
	txDeposit         = 0x64
)

// depositTx is the RLP body of an ArbitrumDepositTx after its type byte.
type depositTx struct {
	ChainID   *big.Int
	RequestID common.Hash
	From      common.Address
	To        common.Address
	Value     *big.Int
}

func delayedUnproven(types []uint64, nonce uint64, kv ...any) *finality.StateError {
	return finality.NewState(CodeDelayedOriginUnproven, append([]any{"block_tx_types", types, "header_nonce", nonce}, kv...)...)
}

// nonceOf is the L2 header's nonce (RLP item 14, the delayed-message count the block has read, annex A6.5), read
// positionally; ok is false if the header has no such item.
func headerNonce(raw []byte) (uint64, bool) {
	content, _, err := rlp.SplitList(raw)
	if err != nil {
		return 0, false
	}
	for i := 0; i <= 14; i++ {
		kind, val, rest, err := rlp.Split(content)
		if err != nil {
			return 0, false
		}
		if i == 14 {
			if kind != rlp.String || len(val) != 8 {
				return 0, false
			}
			var n uint64
			for _, c := range val {
				n = n<<8 | uint64(c)
			}
			return n, true
		}
		content = rest
	}
	return 0, false
}

// verifyDelayed proves the delayed-origin transactions of a block (annex A6.5): the delayed message hashes into
// delayedInboxAccs[k] from delayedInboxAccs[k-1] (both proven under stateRoot_S, slot 6); this batch consumed it (k lies in
// [afterDelayedMessagesRead - delayedSegments, afterDelayedMessagesRead)); and each 0x64 deposit transaction of the block is
// the one the message derives (request id k, sender, recipient, value). Delayed message kinds other than the ETH
// deposit have no derivation here and stay the named state l1_posted_delayed_origin_unproven, never a weaker level.
func verifyDelayed(arb *arbPins, root common.Hash, bridge *ethproof.AccountState, e Evidence, res payloadResult, types []uint64, nonce uint64) (uint64, error) {
	d := e.Delayed
	if d == nil {
		return 0, delayedUnproven(types, nonce)
	}
	after := e.Header40[4]
	n := uint64(res.delayedSegments)
	if n > after || d.K >= after || d.K < after-n {
		return 0, delayedUnproven(types, nonce, "k", d.K, "message_kind", d.MsgKind)
	}
	accK, err := ethproof.VerifySlot(bridge.StorageRoot, arrayElementSlot(arb.Layout.DelayedAccArraySlot, d.K), e.Nodes)
	if err != nil {
		return 0, stateProofInvalid("slot")
	}
	var prev common.Hash
	if d.K > 0 {
		if prev, err = ethproof.VerifySlot(bridge.StorageRoot, arrayElementSlot(arb.Layout.DelayedAccArraySlot, d.K-1), e.Nodes); err != nil {
			return 0, stateProofInvalid("slot")
		}
	}
	mh := DelayedMessageHash(*d)
	if crypto.Keccak256Hash(prev[:], mh[:]) != accK {
		return 0, delayedUnproven(types, nonce, "k", d.K, "message_kind", d.MsgKind)
	}
	for _, tx := range e.BlockTxs {
		t := ethproof.TxType(tx)
		if !isDelayedOriginType(t) {
			continue
		}
		if t != txDeposit || d.MsgKind != msgKindEthDeposit || len(d.Data) != 52 {
			return 0, delayedUnproven(types, nonce, "k", d.K, "message_kind", d.MsgKind)
		}
		var dep depositTx
		if err := rlp.DecodeBytes(tx[1:], &dep); err != nil || dep.Value == nil {
			return 0, delayedUnproven(types, nonce, "k", d.K, "message_kind", d.MsgKind)
		}
		if dep.RequestID != w32(d.K) || dep.From != common.Address(d.Sender) || !bytes.Equal(dep.To[:], d.Data[:20]) ||
			dep.Value.Cmp(new(big.Int).SetBytes(d.Data[20:52])) != 0 {
			return 0, delayedUnproven(types, nonce, "k", d.K, "message_kind", d.MsgKind)
		}
	}
	return d.K, nil
}
