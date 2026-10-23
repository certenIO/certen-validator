// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"

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

// senderFilter says which transactions of one captured block the batcher sent. It IS the capture's authorizer (authorize.go): the live capture
// and the backfill keep only the batcher's transactions by the same function, the readers skip the rest of rows stored before that rule by the
// same function, and the verifier's rule is the one both reproduce.
type senderFilter = batcherAuthorizer

// batcherFromRows is the batcher address the rows of a block prove: systemConfigAt over the nodes of the syscfg row under the state root
// of the header row. ok is false when the rows cannot establish it.
func batcherFromRows(bp *Pins, hdrRaw, sysRow []byte) (addr [20]byte, ok bool) {
	a, ok := authorizerFromRows(bp, hdrRaw, sysRow)
	if !ok {
		return addr, false
	}
	return a.want, true
}

// authorizerFromRows is authorizerAt over the header row and the syscfg row of a captured block.
func authorizerFromRows(bp *Pins, hdrRaw, sysRow []byte) (*batcherAuthorizer, bool) {
	h, err := finality.ReadHeader(hdrRaw)
	if err != nil {
		return nil, false
	}
	nodes, err := finality.NewReader(sysRow, finality.DefaultLimits()).LPList("syscfg", 256, finality.DefaultLimits().MaxTxLeafBytes)
	if err != nil {
		return nil, false
	}
	a, err := authorizerAt(bp, nodes, h.StateRoot, h.Number)
	if err != nil {
		return nil, false
	}
	return a, true
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
	a, ok := authorizerFromRows(bp, rows[0], rows[1])
	if !ok {
		metrics.IncFinalityBatcherUnestablished(uint64(Chain))
		return nil, nil
	}
	return a, nil
}
