// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// rangeCappedReader answers eth_getLogs like a provider that refuses wide ranges (drpc's free plan: "ranges over 10000
// blocks are not supported"), and serves the Transfer logs it holds inside any range it accepts.
type rangeCappedReader struct {
	chainReader
	maxSpan uint64
	logs    []types.Log
	refuse  error // when set, every query is refused with it
	queries int
}

func (r *rangeCappedReader) FilterLogs(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	r.queries++
	lo, hi := q.FromBlock.Uint64(), q.ToBlock.Uint64()
	if r.refuse != nil {
		return nil, r.refuse
	}
	if hi-lo+1 > r.maxSpan {
		return nil, fmt.Errorf("400 Bad Request: ranges over %d blocks are not supported on free plan", r.maxSpan)
	}
	var out []types.Log
	for _, l := range r.logs {
		if l.BlockNumber >= lo && l.BlockNumber <= hi {
			out = append(out, l)
		}
	}
	return out, nil
}

func transferTo(token, to common.Address, block uint64) types.Log {
	return types.Log{Address: token, BlockNumber: block,
		Topics: []common.Hash{transferTopic, common.BytesToHash(common.Address{0xff}.Bytes()), common.BytesToHash(to.Bytes())}}
}

func TestATokenTransferInsideARangeTheProviderRefusesIsStillFound(t *testing.T) {
	acct := common.HexToAddress("0x1019dbd51aaDAb221fEB6D7b6ffc96D4e5e321AC")
	tokA, tokB := common.HexToAddress("0x000000000000000000000000000000000000a001"), common.HexToAddress("0x000000000000000000000000000000000000b002")
	r := &rangeCappedReader{maxSpan: 1000, logs: []types.Log{transferTo(tokA, acct, 1_000_123), transferTo(tokB, acct, 1_009_876)}}
	got, err := tokensReceived(context.Background(), r, []common.Address{acct}, 1_000_000, 1_009_999, 10_000)
	if err != nil {
		t.Fatalf("a provider capping eth_getLogs at 1,000 blocks stopped the inventory: %v", err)
	}
	if len(got) != 2 || got[0] != tokA || got[1] != tokB {
		t.Fatalf("tokens received %v, want both %s and %s", got, tokA, tokB)
	}
}

func TestAQueryTheProviderRefusesAtEveryWidthIsReportedByName(t *testing.T) {
	r := &rangeCappedReader{refuse: errors.New("400 Bad Request: method not allowed")}
	_, err := tokensReceived(context.Background(), r, []common.Address{{0x01}}, 0, 9_999, 10_000)
	if err == nil || !strings.Contains(err.Error(), "method not allowed") {
		t.Fatalf("want the provider's refusal by name, got %v", err)
	}
	// 10,000 blocks halved down to minLogSpan is a bounded number of queries, not an unbounded walk.
	if r.queries > 2*10_000/minLogSpan {
		t.Fatalf("%d queries for one refused range", r.queries)
	}
}

func TestARateRefusalIsNotSplit(t *testing.T) {
	r := &rangeCappedReader{refuse: errors.New("429 Too Many Requests")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // rateLimited returns at once on a cancelled context instead of waiting out its back-off
	_, err := transferLogsSplitting(ctx, r, []common.Hash{{0x01}}, 0, 9_999)
	if err == nil || r.queries != 1 {
		t.Fatalf("a rate refusal was split or swallowed: %d queries, err %v", r.queries, err)
	}
}
