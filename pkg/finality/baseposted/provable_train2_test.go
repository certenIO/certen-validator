// Copyright 2026 Certen Protocol

package baseposted

import (
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality/baseposted/synthstate"
)

// provable is the synthetic L1 state the fake L1 sources of this package's tests serve: a SystemConfig proxy whose batcherHash is the
// test batcher, proven under the state root the synthetic headers carry (RB12-GO-INT D2: the capture authenticates what it stores).
type provable struct{ st *synthstate.State }

var (
	provableOnce sync.Once
	provableVal  *provable
)

func testBatcherAddress() [20]byte {
	return [20]byte(crypto.PubkeyToAddress(testKey("batcher").PublicKey))
}

func testProvable() *provable {
	provableOnce.Do(func() {
		provableVal = &provable{st: synthstate.New(testSysConfig, testImpl, [32]byte(testImplCode), testBatcherAddress())}
	})
	return provableVal
}

func (p *provable) proof(addr [20]byte, slots [][32]byte) StateProof {
	nodes, values := p.st.Proof(addr, slots)
	return StateProof{Nodes: nodes, Values: values}
}

// emptyBlockAt is a verifiable block without transactions: a real header that hashes to the block hash and commits to the empty list.
func emptyBlockAt(n uint64) L1BlockData {
	h := &types.Header{Number: new(big.Int).SetUint64(n), TxHash: types.EmptyTxsHash, Root: common.Hash(testProvable().st.Root), ParentHash: common.Hash{8}, Time: 1655733600 + 12*n,
		Difficulty: big.NewInt(0), UncleHash: types.EmptyUncleHash, ReceiptHash: types.EmptyReceiptsHash}
	hdr, err := rlp.EncodeToBytes(h)
	if err != nil {
		panic(err)
	}
	return L1BlockData{Number: n, Hash: [32]byte(crypto.Keccak256Hash(hdr)), HeaderRLP: hdr, Timestamp: h.Time}
}
