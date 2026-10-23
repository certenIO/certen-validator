// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-INDEX-FIX F19: the capture keeps every transaction sent TO the batch inbox, whoever signed it (capture.go filters on the
// destination only), so a junk channel, or a copy of a real channel's public frames, from ANY sender could be the first candidate of a
// leg, in the window reader and in the index alike. Channels are derived from the frames of the BATCHER's transactions only.
//
// The rule is the verifier's own (verify.go verifyChannel, "Authentication"): a frame transaction is accepted only if its sender, recovered
// with the L1 chain's signer, is SystemConfig.batcherHash as proven by systemConfigAt under the state root of the transaction's own L1
// block. The reader applies the same function to the block's own captured rows: the header row (its state root) and the syscfg row (the
// proof nodes the capturer stored). It relies on nothing else.
//
// When the captured rows of a block cannot establish the batcher (no header or syscfg row, a proof that does not verify, an implementation
// that is not pinned), nothing of that block is filtered: its frames stay candidates and the verifier names what is wrong with the proof
// (contract_identity_unproven, l1_state_proof_invalid, ...), instead of the leg waiting silently. The count of such blocks is a metric.

// senderFilter says which transactions of one captured block the batcher sent.
type senderFilter struct {
	want   [20]byte
	signer types.Signer
}

// batcherFromRows is the batcher address the rows of a block prove: systemConfigAt over the nodes of the syscfg row under the state root
// of the header row. ok is false when the rows cannot establish it.
func batcherFromRows(bp *Pins, hdrRaw, sysRow []byte) (addr [20]byte, ok bool) {
	h, err := finality.ReadHeader(hdrRaw)
	if err != nil {
		return addr, false
	}
	nodes, err := finality.NewReader(sysRow, finality.DefaultLimits()).LPList("syscfg", 256, finality.DefaultLimits().MaxTxLeafBytes)
	if err != nil {
		return addr, false
	}
	addr, err = systemConfigAt(newNodeDB(nodes), bp, h.StateRoot, h.Number)
	if err != nil {
		return [20]byte{}, false
	}
	return addr, true
}

// loadSenderFilter reads the header and syscfg rows of the captured block bk (chain, number, hash) and returns its filter, or nil when the
// rows cannot establish the batcher (counted). The two rows are reserved against hold (nil: unbounded). Only a failing store is an error.
func loadSenderFilter(ctx context.Context, store finality.CaptureStore, bk finality.CaptureKey, bp *Pins, hold *finality.Hold) (*senderFilter, error) {
	var rows [2][]byte
	for i, item := range []string{ItemHeader, ItemSysCfg} {
		k := bk
		k.Item = item
		b, ok, err := store.Get(ctx, k)
		if err != nil {
			return nil, err
		}
		if !ok {
			metrics.IncFinalityBatcherUnestablished(uint64(Chain))
			return nil, nil
		}
		if hold != nil {
			if err := hold.Add(rowCost(len(b))); err != nil {
				return nil, err
			}
		}
		rows[i] = b
	}
	want, ok := batcherFromRows(bp, rows[0], rows[1])
	if !ok {
		metrics.IncFinalityBatcherUnestablished(uint64(Chain))
		return nil, nil
	}
	return &senderFilter{want: want, signer: types.LatestSignerForChainID(new(big.Int).SetUint64(bp.L1ChainID))}, nil
}

// foreign reports whether raw is a transaction the batcher did not send (verifyChannel: the sender cannot be recovered, or is not the
// batcher). A nil filter (batcher not established) filters nothing. A transaction that does not parse is not judged here: its reader fails
// on it by name, as before.
func (f *senderFilter) foreign(raw []byte) bool {
	if f == nil {
		return false
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		return false
	}
	from, err := f.signer.Sender(&tx)
	return err != nil || [20]byte(from) != f.want
}
