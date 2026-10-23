// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-INDEX-FIX (merge of Train 2 d6a9eef1): the capture (CaptureBlock: only the batcher's inbox transactions are stored) and the readers (the
// window reader and the index writer skip, in rows stored before that rule, the transactions the batcher did not send) are ONE rule, ONE
// function (authorize.go). These tests pin that they cannot diverge: on the real published evidence and on a junk transaction both give the
// same authorized set, and the held answer of a window changes when the rows the authorization depends on arrive.

func rowOf(t testing.TB, st finality.CaptureStore, k finality.CaptureKey, item string) []byte {
	t.Helper()
	k.Item = item
	b, ok, err := st.Get(context.Background(), k)
	if err != nil || !ok {
		t.Fatalf("row %s: %v %v", k, ok, err)
	}
	return b
}

func TestRB12CaptureAndReadersAuthorizeTheSameTransactionsOnTheRealEvidence(t *testing.T) {
	ctx := context.Background()
	for _, c := range realCases {
		t.Run(c.ev, func(t *testing.T) {
			w := newBuildWorld(t, c.ev, c.leg)
			bp := realWorldPins(t, w)
			keys, err := finality.CaptureKeysOfItemIn(ctx, w.store, uint64(Chain), 0, finality.MaxCaptureBlock, ItemInbox)
			if err != nil || len(keys) == 0 {
				t.Fatalf("the real evidence has captured inbox blocks: %v %v", keys, err)
			}
			signer := mustSigner(bp)
			to := common.Address(bp.BatchInbox)
			junk, err := types.SignNewTx(testKey("junk"), signer, &types.DynamicFeeTx{ChainID: signer.ChainID(), Nonce: 1, GasTipCap: bigInt(1), GasFeeCap: bigInt(2), Gas: 21000, To: &to, Data: []byte{0}})
			if err != nil {
				t.Fatal(err)
			}
			junkRaw, _ := junk.MarshalBinary()
			authorized := 0
			for _, k := range keys {
				h, err := finality.ReadHeader(rowOf(t, w.store, k, ItemHeader))
				if err != nil {
					t.Fatal(err)
				}
				nodes, err := finality.NewReader(rowOf(t, w.store, k, ItemSysCfg), finality.DefaultLimits()).LPList("syscfg", 256, finality.DefaultLimits().MaxTxLeafBytes)
				if err != nil {
					t.Fatal(err)
				}
				capture, err := authorizerAt(bp, nodes, h.StateRoot, h.Number) // the call CaptureBlock makes
				if err != nil {
					t.Fatalf("the real SystemConfig proof verifies under the header's state root: %v", err)
				}
				reader, err := loadSenderFilter(ctx, w.store, k, bp, nil) // the call the window reader and the index writer make
				if err != nil || reader == nil {
					t.Fatalf("the readers establish the same batcher: %v %v", reader, err)
				}
				if capture.want != reader.want {
					t.Fatalf("block %d: capture says the batcher is %x, the readers %x", k.L1Block, capture.want, reader.want)
				}
				ir := finality.NewReader(rowOf(t, w.store, k, ItemInbox), finality.DefaultLimits())
				n, err := ir.Count("inbox", 4096, 4)
				if err != nil {
					t.Fatal(err)
				}
				raws := [][]byte{junkRaw}
				for i := 0; i < n; i++ {
					idx, err := ir.U32("inbox.index")
					if err != nil {
						t.Fatal(err)
					}
					raws = append(raws, rowOf(t, w.store, k, ItemTx(idx)))
				}
				for i, raw := range raws {
					kept, skipped := capture.sent(raw), reader.foreign(raw)
					if kept == skipped {
						t.Fatalf("block %d tx %d: the capture keeps it (%v) and the readers skip it (%v): one rule gives one answer", k.L1Block, i, kept, skipped)
					}
					if i == 0 && kept {
						t.Fatal("a transaction signed by another key is authorized")
					}
					if i > 0 && kept {
						authorized++
					}
				}
			}
			if authorized == 0 {
				t.Fatal("the real evidence's own frame transactions are authorized by the rule")
			}
		})
	}
}

// The held answer of a window (RB12-GO-INT D4) depends on which inbox transactions are the batcher's, which depends on the header and syscfg
// rows of each block: a block whose rows complete after the answer was held changes the answer, so the fingerprint covers them.
func TestRB12HeldAnswerChangesWhenTheRowsTheAuthorizationDependsOnArrive(t *testing.T) {
	// the junk block is built in a scratch store and copied row by row, the syscfg row last
	scratch := NewMemStore()
	sw := newF19(t, scratch)
	st := NewMemStore()
	w := newF19(t, st)
	E := uint64(1000)
	H := channelFrames("honest", 1_790_100_000, 30, E, 2)
	w.putBlock(1020, w.honest, f19Tx{key: w.honest, frames: H[:1]})
	w.putBlock(1022, w.honest, f19Tx{key: w.honest, frames: H[1:]})
	hash := sw.putBlock(1010, sw.honest, f19Tx{key: sw.junk, frames: []Frame{H[0], H[1]}}) // the junk block: copies of the honest frames
	rows, err := scratch.ListByBlock(context.Background(), uint64(Chain), 1010)
	if err != nil {
		t.Fatal(err)
	}
	var sysRow finality.CaptureRow
	for _, r := range rows {
		if r.Item == ItemSysCfg {
			sysRow = r
			continue
		}
		if err := st.Put(context.Background(), r.CaptureKey, r.Bytes); err != nil {
			t.Fatal(err)
		}
	}
	if sysRow.L1Hash != hash {
		t.Fatalf("the syscfg row of the junk block: %v", sysRow)
	}
	rawGapRow(t, st, 1100, 1110, "state_proof_unavailable") // an open gap in the window: the answer for a missing channel is l1_capture_gap
	T := uint64(1_790_100_030)
	b := w.builder(false, E, st)
	ask := func() (searched, error) {
		return b.search(context.Background(), w.bp, finality.HeaderFields{Number: 5, Timestamp: T}, nil)
	}
	// the junk block has no syscfg row yet: its batcher cannot be established, nothing is filtered, the copies duplicate the honest frames
	// and the channel is incomplete: not found, held as the gap
	for i := 0; i < 2; i++ {
		_, err := ask()
		if se, ok := finality.AsNamed(err); !ok || se.Code != "l1_capture_gap" {
			t.Fatalf("ask %d: want the held l1_capture_gap, got %v", i, err)
		}
	}
	// its syscfg row arrives: the copies are the junk key's and are skipped, the honest channel is complete and found
	if err := st.Put(context.Background(), sysRow.CaptureKey, sysRow.Bytes); err != nil {
		t.Fatal(err)
	}
	sr, err := ask()
	if err != nil || sr.ch == nil || sr.ch.ID != H[0].ID {
		t.Fatalf("the held answer is stale: after the block's syscfg row arrived the channel is found; got ch=%v err=%v", sr.ch, err)
	}
}
