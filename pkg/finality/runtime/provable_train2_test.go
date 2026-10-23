// Copyright 2026 Certen Protocol

package runtime

import (
	"crypto/ecdsa"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
	"github.com/certen/independant-validator/pkg/finality/baseposted/synthstate"
)

// RB12-GO-INT D2: the Base capture authenticates what it stores (the SystemConfig proof under the header's state root, the sender of every
// inbox transaction against the batcher it establishes), so the fake L1 sources of the loop tests serve a state that proves a test batcher,
// inbox transactions that batcher signed, and blocks whose headers hash and commit to their transactions.

var (
	rtSysCfg   = [20]byte{0x5c, 0x01}
	rtImpl     = [20]byte{0x1a, 0x02}
	rtImplCode = [32]byte(crypto.Keccak256Hash([]byte("rt syscfg implementation")))

	rtOnce        sync.Once
	rtBatcherPriv *ecdsa.PrivateKey
	rtState       *synthstate.State
)

func rtProvable() (*ecdsa.PrivateKey, *synthstate.State) {
	rtOnce.Do(func() {
		k, err := crypto.ToECDSA(crypto.Keccak256([]byte("rt batcher")))
		if err != nil {
			panic(err)
		}
		rtBatcherPriv = k
		rtState = synthstate.New(rtSysCfg, rtImpl, rtImplCode, [20]byte(crypto.PubkeyToAddress(k.PublicKey)))
	})
	return rtBatcherPriv, rtState
}

// rtPins are the pins a capturer under test authenticates with.
func rtPins() *baseposted.Pins {
	return &baseposted.Pins{BatchInbox: rtInbox, SystemConfig: rtSysCfg, L1ChainID: 11155111, SystemConfigImplHashes: map[[32]byte]bool{rtImplCode: true}}
}

// rtHeaderFor is the header of block n over the given transactions, with the state root of the provable state.
func rtHeaderFor(n uint64, raws [][]byte) ([]byte, [32]byte) {
	_, st := rtProvable()
	hdr, err := rlp.EncodeToBytes(&types.Header{Number: new(big.Int).SetUint64(n), Difficulty: big.NewInt(0), Root: common.Hash(st.Root), TxHash: ethproof.TrieRoot(raws),
		Time: 1_700_000_000, UncleHash: types.EmptyUncleHash, ReceiptHash: types.EmptyReceiptsHash})
	if err != nil {
		panic(err)
	}
	return hdr, [32]byte(crypto.Keccak256Hash(hdr))
}

// rtEmptyBlock is a verifiable block without transactions.
func rtEmptyBlock(n uint64) baseposted.L1BlockData {
	hdr, h := rtHeaderFor(n, nil)
	return baseposted.L1BlockData{Number: n, Hash: h, HeaderRLP: hdr, Timestamp: 1_700_000_000}
}

// rtInboxTx is a calldata transaction to the batch inbox signed by the provable batcher.
func rtInboxTx(nonce uint64) []byte {
	k, _ := rtProvable()
	to := common.Address(rtInbox)
	tx, err := types.SignNewTx(k, types.LatestSignerForChainID(big.NewInt(11155111)), &types.DynamicFeeTx{ChainID: big.NewInt(11155111), Nonce: nonce, GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(10), Gas: 21000, To: &to, Data: []byte{byte(nonce), 1, 2}})
	if err != nil {
		panic(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return raw
}

// rtProve answers eth_getProof from the provable state.
func rtProve(addr [20]byte, slots [][32]byte) baseposted.StateProof {
	_, st := rtProvable()
	nodes, values := st.Proof(addr, slots)
	return baseposted.StateProof{Nodes: nodes, Values: values}
}
