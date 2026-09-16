package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/metrics"
)

// AnchorQuorumStore is the database side of anchor evidence (database.BatchRepository).
type AnchorQuorumStore interface {
	RecordAnchorQuorum(ctx context.Context, rec *database.AnchorQuorumRecord) (bool, error)
}

// AnchorQuorumWriter persists anchor quorum evidence off the proving path.
//
// Proving already costs a peer round trip, a transaction and a confirmation read; the database write must
// not extend it, and a database that is down must not stop anchors from being proven. So the hook hands
// off and returns, exactly like the consensus persister: a bounded queue, retries with backoff, and
// counters an operator can alert on.
//
// A refused hand-off is not silently lost — it is counted and logged, and the chain remains the source of
// truth. Re-deriving a dropped anchor from the chain is what `backfill anchor-quorum` is for.
type AnchorQuorumWriter struct {
	store  AnchorQuorumStore
	logf   func(string, ...interface{})
	queue  chan *database.AnchorQuorumRecord
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once

	written   atomic.Uint64
	duplicate atomic.Uint64
	conflicts atomic.Uint64
	dropped   atomic.Uint64
	failed    atomic.Uint64

	retryBase   time.Duration
	retryMax    time.Duration
	callTimeout time.Duration
}

const (
	anchorQuorumQueueCapacity = 256
	anchorQuorumRetryBase     = 500 * time.Millisecond
	anchorQuorumRetryMax      = 30 * time.Second
	anchorQuorumCallTimeout   = 60 * time.Second
)

func NewAnchorQuorumWriter(store AnchorQuorumStore, logf func(string, ...interface{})) *AnchorQuorumWriter {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	return &AnchorQuorumWriter{
		store:       store,
		logf:        logf,
		queue:       make(chan *database.AnchorQuorumRecord, anchorQuorumQueueCapacity),
		done:        make(chan struct{}),
		retryBase:   anchorQuorumRetryBase,
		retryMax:    anchorQuorumRetryMax,
		callTimeout: anchorQuorumCallTimeout,
	}
}

func (w *AnchorQuorumWriter) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	go w.run(ctx)
}

func (w *AnchorQuorumWriter) Stop() {
	w.once.Do(func() {
		if w.cancel != nil {
			w.cancel()
			<-w.done
		}
	})
}

// Hook returns the AnchorAttestedHook to install on the attestor.
func (w *AnchorQuorumWriter) Hook() AnchorAttestedHook {
	return func(_ context.Context, ev *AnchorQuorumEvidence) {
		rec := AnchorQuorumRecordFrom(ev)
		if rec == nil {
			return
		}
		select {
		case w.queue <- rec:
		default:
			n := w.dropped.Add(1)
			metrics.RecordAnchorQuorumDropped()
			w.logf("⚠️ [ANCHOR-QUORUM] write queue full; evidence for chain %d bundle %s not queued "+
				"(dropped=%d) — recoverable with `backfill anchor-quorum`", rec.ChainID, rec.BundleID, n)
		}
	}
}

func (w *AnchorQuorumWriter) run(ctx context.Context) {
	defer close(w.done)
	for {
		select {
		case <-ctx.Done():
			return
		case rec := <-w.queue:
			if !w.write(ctx, rec) {
				return
			}
		}
	}
}

// write persists one record, retrying transport failures until it succeeds or ctx ends. A conflict is
// never retried: it is a disagreement about what the chain executed, and repeating the write cannot
// settle it.
func (w *AnchorQuorumWriter) write(ctx context.Context, rec *database.AnchorQuorumRecord) bool {
	for attempt := 1; ; attempt++ {
		cctx, cancel := context.WithTimeout(ctx, w.callTimeout)
		written, err := w.store.RecordAnchorQuorum(cctx, rec)
		cancel()

		if err == nil {
			if written {
				w.written.Add(1)
				metrics.RecordAnchorQuorumWritten()
				w.logf("✅ [ANCHOR-QUORUM] chain=%d bundle=%s recorded: %d member(s), %d signer(s), verify tx %s",
					rec.ChainID, rec.BundleID, len(rec.Members), len(rec.Signers), rec.VerifyTx)
			} else {
				w.duplicate.Add(1)
			}
			return true
		}

		var conflict *database.AnchorQuorumConflict
		if errors.As(err, &conflict) {
			n := w.conflicts.Add(1)
			metrics.RecordAnchorQuorumConflict()
			// Loud on purpose: two nodes describing the same anchor differently is either a bug in the
			// evidence path or a node talking to a different chain. Neither is resolved by a retry.
			w.logf("❌ [ANCHOR-QUORUM] CONFLICT (conflicts=%d): %v — the stored row was NOT changed", n, conflict)
			return true
		}

		if ctx.Err() != nil {
			return false
		}
		w.failed.Add(1)
		metrics.RecordAnchorQuorumWriteError()
		w.logf("⚠️ [ANCHOR-QUORUM] could not record chain=%d bundle=%s (attempt %d): %v",
			rec.ChainID, rec.BundleID, attempt, err)
		if !w.sleep(ctx, attempt) {
			return false
		}
	}
}

func (w *AnchorQuorumWriter) sleep(ctx context.Context, attempt int) bool {
	d := w.retryBase
	for i := 1; i < attempt && d < w.retryMax; i++ {
		d *= 2
	}
	if d > w.retryMax {
		d = w.retryMax
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Stats reports what this writer has done, for tests and for the startup log.
func (w *AnchorQuorumWriter) Stats() (written, duplicate, conflicts, dropped, failed uint64) {
	return w.written.Load(), w.duplicate.Load(), w.conflicts.Load(), w.dropped.Load(), w.failed.Load()
}

// AnchorQuorumRecordFrom converts proven evidence into the row shape, without inventing anything: every
// field is a re-encoding of what prove() verified and confirmed.
func AnchorQuorumRecordFrom(ev *AnchorQuorumEvidence) *database.AnchorQuorumRecord {
	if ev == nil {
		return nil
	}
	signers := make([]database.AnchorQuorumSigner, 0, len(ev.Signers))
	for i, addr := range ev.Signers {
		s := database.AnchorQuorumSigner{Address: addr}
		if i < len(ev.SignerPowers) {
			s.VotingPower = ev.SignerPowers[i]
		}
		signers = append(signers, s)
	}

	members := make([]database.AnchorQuorumMemberRecord, 0, len(ev.Members))
	for _, m := range ev.Members {
		branch := make([]database.MerklePathNode, 0, len(m.Branch))
		for _, node := range m.Branch {
			branch = append(branch, database.MerklePathNode{Hash: hexPrefixed(node[:])})
		}
		members = append(members, database.AnchorQuorumMemberRecord{
			IntentID: m.IntentID,
			// The Accumulate 4-blob intent hash is what binds a member to its transaction, and it is the
			// value bound into the on-chain leaf.
			AccumTxHash: hex.EncodeToString(m.OperationID[:]),
			ADIURL:      m.ADIURL,
			OperationID: hexPrefixed(m.OperationID[:]),
			Leaf:        append([]byte(nil), m.Leaf[:]...),
			LeafIndex:   m.LeafIndex,
			Branch:      branch,
		})
	}

	return &database.AnchorQuorumRecord{
		ChainID:            ev.ChainID,
		BundleID:           hexPrefixed(ev.BundleID[:]),
		Root:               append([]byte(nil), ev.Root[:]...),
		BatchOperationID:   hexPrefixed(ev.BatchOperationID[:]),
		MessageHash:        hexPrefixed(ev.MessageHash[:]),
		VerifyTx:           ev.VerifyTx,
		VerifiedAt:         ev.AttestedAt,
		AggregateSignature: decodeHexOrNil(ev.AggregateSignatureHex),
		AggregatePubKey:    decodeHexOrNil(ev.AggregatePublicKeyHex),
		Signers:            signers,
		SignedVotingPower:  ev.SignedVotingPower,
		TotalVotingPower:   ev.TotalVotingPower,
		Lane:               ev.Lane,
		EvidenceSource:     "live",
		TargetChain:        chainName(ev.ChainID),
		Members:            members,
	}
}

func hexPrefixed(b []byte) string { return "0x" + hex.EncodeToString(b) }

func decodeHexOrNil(s string) []byte {
	trimmed := s
	if len(trimmed) >= 2 && (trimmed[:2] == "0x" || trimmed[:2] == "0X") {
		trimmed = trimmed[2:]
	}
	if trimmed == "" {
		return nil
	}
	b, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil
	}
	return b
}

// chainName keeps target_chain readable for the rows an operator reads by hand. The canonical identity is
// chain_id; this is a label.
func chainName(chainID int64) string {
	switch chainID {
	case 11155111:
		return "sepolia"
	case 84532:
		return "base-sepolia"
	case 421614:
		return "arbitrum-sepolia"
	default:
		return fmt.Sprintf("chain-%d", chainID)
	}
}
