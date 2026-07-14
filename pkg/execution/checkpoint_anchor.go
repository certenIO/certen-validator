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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// RawWriteDataSubmitter is the narrow capability the checkpoint anchor needs from a submitter.
// *AccumulateSubmitterImpl satisfies it.
type RawWriteDataSubmitter interface {
	SubmitRawWriteData(ctx context.Context, entries [][]byte) (string, error)
}

// CheckpointRecord is the compact checkpoint serialized into a single Accumulate data entry.
// The `Prev` field makes the on-chain log a tamper-evident hash chain: Prev = hex(SHA256(the
// exact bytes of the previous entry)). A verifier reads each entry's raw bytes, hashes them, and
// checks the next entry's Prev — walking back to the origin (Prev==""). Continuity survives
// restarts via a locally-persisted chain head (see CheckpointAnchor.stateFile).
type CheckpointRecord struct {
	Version     string `json:"v"`
	ValidatorID string `json:"validator"`
	Height      int64  `json:"height"`
	BlockHash   string `json:"block_hash"`
	AppHash     string `json:"app_hash"`
	Prev        string `json:"prev"` // hex(SHA256(previous entry bytes)); "" for the first entry
	TimestampMs int64  `json:"ts_ms"`
}

// CheckpointAnchor asynchronously mirrors committed block roots to Accumulate.
type CheckpointAnchor struct {
	submitter    RawWriteDataSubmitter
	validatorID  string
	stateFile    string // persists the chain head (hex SHA256 of last written entry) across restarts
	ch           chan CheckpointRecord
	logger       *log.Logger
	writeTimeout time.Duration

	mu       sync.Mutex
	prevHash string // hex(SHA256(last written entry bytes)); seeds the next entry's Prev
	dropped  uint64
	written  uint64

	done chan struct{}
	wg   sync.WaitGroup
}

// NewCheckpointAnchor starts the background writer and returns the anchor. bufSize <= 0 defaults
// to 256. stateFile (may be "") persists the chain head so the hash chain continues unbroken
// across restarts; it lives in the validator data dir and is cleared only by a genesis reset.
func NewCheckpointAnchor(submitter RawWriteDataSubmitter, validatorID, stateFile string, bufSize int, logger *log.Logger) *CheckpointAnchor {
	if bufSize <= 0 {
		bufSize = 256
	}
	if logger == nil {
		logger = log.New(log.Writer(), "[CHECKPOINT] ", log.LstdFlags)
	}
	a := &CheckpointAnchor{
		submitter:    submitter,
		validatorID:  validatorID,
		stateFile:    stateFile,
		ch:           make(chan CheckpointRecord, bufSize),
		logger:       logger,
		writeTimeout: 30 * time.Second,
		done:         make(chan struct{}),
	}
	// Seed the chain head from the persisted state file so the chain continues unbroken.
	if stateFile != "" {
		if b, err := os.ReadFile(stateFile); err == nil {
			a.prevHash = strings.TrimSpace(string(b))
			if a.prevHash != "" {
				a.logger.Printf("🔗 [CHECKPOINT] resuming chain from persisted head %s…", head8(a.prevHash))
			}
		}
	}
	a.wg.Add(1)
	go a.run()
	return a
}

func head8(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
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
	rec.Prev = a.prevHash
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

	// Advance the chain head to hex(SHA256(this entry's exact bytes)) and persist it so the
	// hash chain continues unbroken across restarts.
	sum := sha256.Sum256(payload)
	next := hex.EncodeToString(sum[:])
	a.mu.Lock()
	a.prevHash = next
	a.written++
	w := a.written
	a.mu.Unlock()
	a.persistHead(next)
	a.logger.Printf("⚓ [CHECKPOINT] height=%d appHash=%s prev=%s -> %s (total written=%d)", rec.Height, rec.AppHash, head8(rec.Prev), txID, w)
}

// persistHead atomically writes the chain head to the state file (best effort).
func (a *CheckpointAnchor) persistHead(head string) {
	if a.stateFile == "" {
		return
	}
	tmp := a.stateFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(head), 0600); err != nil {
		a.logger.Printf("⚠️ [CHECKPOINT] persist chain head failed: %v", err)
		return
	}
	if err := os.Rename(tmp, a.stateFile); err != nil {
		a.logger.Printf("⚠️ [CHECKPOINT] rename chain head failed: %v", err)
	}
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
