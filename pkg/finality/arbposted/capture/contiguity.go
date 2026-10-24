// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"fmt"

	"github.com/certen/independant-validator/pkg/finality"
)

// checkContiguity is the cheap evidence that a log answer is complete: the batches of a SequencerInbox are one accumulator chain, so the
// events of a range are consecutive sequence numbers and each batch's beforeAcc is the previous batch's afterAcc, and the first and the
// last event must join the batches already captured next to them. An answer that omits an event inside the range, or at an edge whose
// neighbour is stored, fails here and the range is read again. Omitting a whole range, or an edge event whose neighbour is not stored, is
// not detectable this way; such a lie can only make a leg look absent (never accepted: the verifier accepts a batch only through the
// Bridge's accumulator proof), which is why the state it can cause names the window it was judged at.
func (c *Capturer) checkContiguity(ctx context.Context, recs []BatchRecord) error {
	for i := 1; i < len(recs); i++ {
		if recs[i].N != recs[i-1].N+1 || recs[i].BeforeAcc != recs[i-1].AfterAcc {
			return fmt.Errorf("batch %d does not follow batch %d in the accumulator chain (an event is missing or the answer is inconsistent)", recs[i].N, recs[i-1].N)
		}
	}
	if len(recs) == 0 {
		return nil
	}
	keys, err := c.Store.ListByRange(ctx, c.Cfg.Chain, 0, finality.MaxCaptureBlock, "batch/")
	if err != nil {
		return err
	}
	byN := map[uint64]Key{}
	for _, k := range keys {
		var n uint64
		if _, e := fmt.Sscanf(k.Item, "batch/%d", &n); e == nil && k.Item == ItemBatch(n) {
			byN[n] = k
		}
	}
	read := func(n uint64) (*BatchRecord, error) {
		k, ok := byN[n]
		if !ok {
			return nil, nil
		}
		b, found, err := c.Store.Get(ctx, k)
		if err != nil || !found {
			return nil, fmt.Errorf("the captured batch %d is unreadable", n)
		}
		r, err := DecodeBatchRecord(b)
		if err != nil {
			return nil, err
		}
		return &r, nil
	}
	first, last := recs[0], recs[len(recs)-1]
	if first.N > 0 {
		prev, err := read(first.N - 1)
		if err != nil {
			return err
		}
		if prev != nil && prev.AfterAcc != first.BeforeAcc {
			return fmt.Errorf("batch %d does not follow the captured batch %d in the accumulator chain", first.N, first.N-1)
		}
	}
	next, err := read(last.N + 1)
	if err != nil {
		return err
	}
	if next != nil && next.BeforeAcc != last.AfterAcc {
		return fmt.Errorf("the captured batch %d does not follow batch %d in the accumulator chain", last.N+1, last.N)
	}
	return nil
}
