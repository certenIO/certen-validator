// Copyright 2025 Certen Protocol
//
// Block-checkpoint anchor (P3): asynchronously writes compact, tamper-evident per-block
// checkpoints to an Accumulate data account (e.g. acc://certen-protocol.acme/block-history).
//
// Design constraints:
//   - OFF the consensus hot path: Enqueue never blocks; a background goroutine performs the
//     WriteData. If Accumulate is slow/unavailable the buffer fills and the oldest checkpoints
//     are dropped (logged, counted) so block production is never impacted.
//   - Roots only, never full blocks: entries carry height + block hash + app hash (+ a hash
//     chain via prev_app_hash), not block bodies. Entries are small and cheap.
//   - Height is embedded in every entry; correctness never relies on positional entry index.
//   - Single designated writer: only one validator runs an anchor (selected by the caller), so
//     there are no duplicate writes or key-page nonce races.

package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log"
	"sync"
	"time"
)

// RawWriteDataSubmitter is the narrow capability the checkpoint anchor needs from a submitter.
// *AccumulateSubmitterImpl satisfies it.
type RawWriteDataSubmitter interface {
	SubmitRawWriteData(ctx context.Context, entries [][]byte) (string, error)
}

// CheckpointRecord is the compact checkpoint serialized into a single Accumulate data entry.
type CheckpointRecord struct {
	Version     string `json:"v"`
	ValidatorID string `json:"validator"`
	Height      int64  `json:"height"`
	BlockHash   string `json:"block_hash"`
	AppHash     string `json:"app_hash"`
	PrevAppHash string `json:"prev_app_hash"` // hash-chain to the previously written checkpoint
	TimestampMs int64  `json:"ts_ms"`
}

// CheckpointAnchor asynchronously mirrors committed block roots to Accumulate.
type CheckpointAnchor struct {
	submitter    RawWriteDataSubmitter
	validatorID  string
	ch           chan CheckpointRecord
	logger       *log.Logger
	writeTimeout time.Duration

	mu          sync.Mutex
	prevAppHash string
	dropped     uint64
	written     uint64

	done chan struct{}
	wg   sync.WaitGroup
}

// NewCheckpointAnchor starts the background writer and returns the anchor.
// bufSize <= 0 defaults to 256.
func NewCheckpointAnchor(submitter RawWriteDataSubmitter, validatorID string, bufSize int, logger *log.Logger) *CheckpointAnchor {
	if bufSize <= 0 {
		bufSize = 256
	}
	if logger == nil {
		logger = log.New(log.Writer(), "[CHECKPOINT] ", log.LstdFlags)
	}
	a := &CheckpointAnchor{
		submitter:    submitter,
		validatorID:  validatorID,
		ch:           make(chan CheckpointRecord, bufSize),
		logger:       logger,
		writeTimeout: 30 * time.Second,
		done:         make(chan struct{}),
	}
	a.wg.Add(1)
	go a.run()
	return a
}

// Enqueue records a checkpoint for a committed block. It NEVER blocks: on a full buffer the
// checkpoint is dropped and counted (an audit anchor must not gate consensus). The signature
// matches ValidatorApp's checkpoint hook.
func (a *CheckpointAnchor) Enqueue(height int64, blockHash string, appHash []byte, ts time.Time) {
	rec := CheckpointRecord{
		Version:     "1.0",
		ValidatorID: a.validatorID,
		Height:      height,
		BlockHash:   blockHash,
		AppHash:     hex.EncodeToString(appHash),
		TimestampMs: ts.UnixMilli(),
	}
	select {
	case a.ch <- rec:
	default:
		a.mu.Lock()
		a.dropped++
		d := a.dropped
		a.mu.Unlock()
		a.logger.Printf("⚠️ [CHECKPOINT] buffer full, dropped height=%d (total dropped=%d)", height, d)
	}
}

func (a *CheckpointAnchor) run() {
	defer a.wg.Done()
	for {
		select {
		case <-a.done:
			return
		case rec := <-a.ch:
			a.write(rec)
		}
	}
}

func (a *CheckpointAnchor) write(rec CheckpointRecord) {
	a.mu.Lock()
	rec.PrevAppHash = a.prevAppHash
	a.mu.Unlock()

	payload, err := json.Marshal(rec)
	if err != nil {
		a.logger.Printf("❌ [CHECKPOINT] marshal height=%d: %v", rec.Height, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.writeTimeout)
	defer cancel()

	txID, err := a.submitter.SubmitRawWriteData(ctx, [][]byte{payload})
	if err != nil {
		a.logger.Printf("❌ [CHECKPOINT] write height=%d failed: %v", rec.Height, err)
		return
	}

	a.mu.Lock()
	a.prevAppHash = rec.AppHash
	a.written++
	w := a.written
	a.mu.Unlock()
	a.logger.Printf("⚓ [CHECKPOINT] height=%d appHash=%s -> %s (total written=%d)", rec.Height, rec.AppHash, txID, w)
}

// Stats returns counts of written and dropped checkpoints (for health/metrics).
func (a *CheckpointAnchor) Stats() (written, dropped uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.written, a.dropped
}

// Close stops the background writer and waits for it to exit.
func (a *CheckpointAnchor) Close() {
	close(a.done)
	a.wg.Wait()
}
