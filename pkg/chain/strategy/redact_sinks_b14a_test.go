package strategy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// RB10-B14a (V-R10B5 D3): the strategy observer's log lines and returned errors carry no provider credential.

type leakyReader struct {
	receiptErr, headerErr error
	canon                 *types.Header
	receipt               *types.Receipt
}

func (f *leakyReader) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	if f.receiptErr != nil {
		return nil, f.receiptErr
	}
	return f.receipt, nil
}
func (f *leakyReader) HeaderByNumber(_ context.Context, n *big.Int) (*types.Header, error) {
	h := *f.canon
	if n != nil && n.Int64() == int64(rpc.FinalizedBlockNumber) {
		h.Number = new(big.Int).Add(f.canon.Number, big.NewInt(10))
	}
	return &h, nil
}
func (f *leakyReader) HeaderByHash(context.Context, common.Hash) (*types.Header, error) {
	return nil, f.headerErr
}
func (f *leakyReader) BlockReceipts(context.Context, rpc.BlockNumberOrHash) ([]*types.Receipt, error) {
	return []*types.Receipt{f.receipt}, nil
}

func TestB14a_TheStrategyObserverReturnsAndLogsNoProviderKey(t *testing.T) {
	const key = "SECRETKEY-strategy-0201a"
	leak := &url.Error{Op: "Post", URL: "https://eth-sepolia.g.alchemy.com/v2/" + key, Err: syscall.ECONNREFUSED}
	tx := common.HexToHash("0x01")
	canon := &types.Header{Number: big.NewInt(5), Difficulty: big.NewInt(0)}
	rc := &types.Receipt{TxHash: tx, BlockNumber: big.NewInt(5), BlockHash: canon.Hash(), Status: 1}

	var logged bytes.Buffer
	saved := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(saved)

	// the finality reader cannot read the receipt: the log line of the wait carries the provider's error
	o := &EVMObserver{chainID: 11155111, pollingInterval: time.Millisecond, finality: &leakyReader{receiptErr: leak, canon: canon, receipt: rc}}
	if _, err := o.observeSettled(context.Background(), tx, time.Now().Add(30*time.Millisecond)); err == nil {
		t.Fatal("an unreadable receipt was observed")
	} else if strings.Contains(err.Error(), key) {
		t.Fatalf("the returned error holds the key: %v", err)
	}
	if logged.Len() == 0 {
		t.Fatal("nothing was logged")
	}
	if strings.Contains(logged.String(), key) {
		t.Fatalf("the log holds the key:\n%s", logged.String())
	}

	// the header by hash fails with the key in the error: the returned error names the read and not the key, and keeps the cause
	logged.Reset()
	o = &EVMObserver{chainID: 11155111, pollingInterval: time.Millisecond, finality: &leakyReader{headerErr: leak, canon: canon, receipt: rc}}
	_, err := o.observeSettled(context.Background(), tx, time.Now().Add(time.Second))
	if err == nil || !strings.Contains(err.Error(), "read the finalized header") {
		t.Fatalf("the header read should fail by name: %v", err)
	}
	if strings.Contains(err.Error(), key) || strings.Contains(logged.String(), key) {
		t.Fatalf("the key is left:\nerror: %v\nlog: %s", err, logged.String())
	}
	var ue *url.Error
	if !errors.As(err, &ue) || ue != leak || !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("the original error is no longer reachable: %v", err)
	}

	// no agreeing providers: the refusal names the cause, not the key
	o = &EVMObserver{chainID: 11155111, finalityErr: fmt.Errorf("chain 1: %w", leak)}
	if _, err := o.observeSettled(context.Background(), tx, time.Now().Add(time.Second)); err == nil || strings.Contains(err.Error(), key) {
		t.Fatalf("the refusal: %v", err)
	}
}
