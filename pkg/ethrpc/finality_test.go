package ethrpc

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// RB5-F49: the shared rule - a receipt is taken from the finalized, canonical block at its height.

type fakeFinality struct {
	finalized uint64
	canonical *types.Header
	indexed   *types.Receipt // what eth_getTransactionReceipt answers
	inBlock   []*types.Receipt
}

func (f *fakeFinality) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	return f.indexed, nil
}
func (f *fakeFinality) HeaderByNumber(_ context.Context, n *big.Int) (*types.Header, error) {
	h := *f.canonical
	if n != nil && n.Int64() == int64(rpc.FinalizedBlockNumber) {
		h.Number = new(big.Int).SetUint64(f.finalized)
	}
	return &h, nil
}
func (f *fakeFinality) HeaderByHash(_ context.Context, h common.Hash) (*types.Header, error) {
	if f.canonical.Hash() != h {
		return nil, errors.New("not found")
	}
	return f.canonical, nil
}
func (f *fakeFinality) BlockReceipts(context.Context, rpc.BlockNumberOrHash) ([]*types.Receipt, error) {
	return f.inBlock, nil
}

func TestTheReceiptIsTheFinalizedCanonicalBlocksOwn(t *testing.T) {
	tx := common.HexToHash("0x01")
	canon := &types.Header{Number: big.NewInt(11832868), Difficulty: big.NewInt(0), Extra: []byte("canonical")}
	stale := &types.Receipt{TxHash: tx, BlockNumber: big.NewInt(11832868), BlockHash: common.HexToHash("0x0ff1ce"), Status: 1}
	own := &types.Receipt{TxHash: tx, BlockNumber: big.NewInt(11832868), BlockHash: canon.Hash(), Status: 1}
	f := &fakeFinality{finalized: 11832900, canonical: canon, indexed: stale, inBlock: []*types.Receipt{own}}
	got, err := SettledInFinalizedChain(context.Background(), f, tx, time.Now().Add(time.Second), time.Millisecond, nil)
	if err != nil || got.BlockHash != canon.Hash() {
		t.Fatalf("a stale index: (%v, %v)", got, err)
	}
	f.finalized = 11832867
	if _, err := SettledInFinalizedChain(context.Background(), f, tx, time.Now().Add(20*time.Millisecond), time.Millisecond, nil); !errors.Is(err, ErrNotYetFinalized) {
		t.Fatalf("a block one short of finality: %v", err)
	}
	f.finalized, f.inBlock = 11832900, nil
	if _, err := SettledInFinalizedChain(context.Background(), f, tx, time.Now().Add(20*time.Millisecond), time.Millisecond, nil); err == nil {
		t.Fatal("a transaction the finalized block does not hold was accepted")
	}
	f.inBlock = []*types.Receipt{{TxHash: tx, BlockNumber: big.NewInt(11832868), BlockHash: common.HexToHash("0xbad"), Status: 1}}
	if _, err := SettledInFinalizedChain(context.Background(), f, tx, time.Now().Add(20*time.Millisecond), time.Millisecond, nil); err == nil {
		t.Fatal("a block whose receipts name another block was trusted")
	}
}
