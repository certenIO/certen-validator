package consensus

// Consensus persistence, off the ABCI Commit path.
//
// WHAT WAS WRONG (testnet fleet, 2026-09-15)
//
// Commit iterated the whole in-memory ValidatorBlock cache (up to 1000 entries) on every block: it
// rewrote every cached block into consensus_entries and batch_attestations, then looked each one up in
// anchor_batches by its governance merkle root. That root is computed over governance leaves; the batch
// root is computed over transactions, so the lookup could never match (0 of 231 in three days) and each
// miss walked all 71,067 rows (44 ms). With ~350 cached blocks Commit took 14-16 s.
//
// CometBFT serialises CheckTx with Commit and its RPC write timeout is 11 s, so every BroadcastTxSync
// overlapping a commit answered EOF, validators marked committed ValidatorBlocks as failed, quorum never
// formed, and intents stayed `anchoring`. The rewrite was also destructive: its upsert reset state,
// completed_at, aggregates and result_json of every cached entry each block, and signature_valid of its
// attestation, so no later update to those columns could last.
//
// WHAT THIS DOES
//
//   - Commit performs no database I/O. It hands the ValidatorBlocks FinalizeBlock accepted for THIS block
//     to a background writer with a non-blocking send (like the checkpoint hook).
//   - The writer inserts each block's rows once (ON CONFLICT DO NOTHING) and advances a per-writer
//     persisted-height watermark in the same transaction.
//   - Rows are a pure function of the committed block (its accepted transactions, height and time). If the
//     hand-off queue is full, the database is down, or the process restarts, the writer rebuilds the
//     missing heights from the CometBFT block store and resumes from the watermark. A height the block
//     store no longer holds is logged as a gap; nothing is invented.
//   - Phase 5 (anchor_batches quorum fields) is not written here: it belongs to the batch
//     ConsensusCoordinator, which holds the real attestation data.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/metrics"
	"github.com/google/uuid"
)

// committedBlock is one committed CometBFT block's accepted ValidatorBlocks, with ABCI commit metadata
// (height, block time, validator id default) already applied.
type committedBlock struct {
	height int64
	time   time.Time
	blocks []ValidatorBlock
}

// consensusRecordStore is the database side of consensus persistence (database.ConsensusRepository).
type consensusRecordStore interface {
	PersistCommittedBlock(ctx context.Context, writerID string, rec *database.CommittedConsensusRecords) ([]database.RejectedRecord, error)
	LoadPersistedHeight(ctx context.Context, writerID string) (height int64, found bool, err error)
	ResetPersistedHeight(ctx context.Context, writerID string, height int64) error
	EnsurePersistenceProgressTable(ctx context.Context) error
}

// errCommittedBlockUnavailable reports a height the block store can no longer serve (pruned). It is not
// retried: the rows for that height cannot be rebuilt.
var errCommittedBlockUnavailable = errors.New("committed block unavailable")

// committedBlockSource rebuilds a committed block from the node's block store, for heights the writer
// never received (dropped hand-off, restart).
type committedBlockSource interface {
	CommittedValidatorBlocks(ctx context.Context, height int64) (*committedBlock, error)
}

// persistJob is one hand-off from Commit.
type persistJob struct {
	block          committedBlock
	validatorCount int
}

const (
	persistQueueCapacity = 1024
	persistRetryBase     = 500 * time.Millisecond
	persistRetryMax      = 30 * time.Second
	persistIdleCheck     = 1 * time.Second
	// persistCallTimeout bounds one database call, so a hung connection surfaces as a retried error
	// instead of a silent stall.
	persistCallTimeout = 60 * time.Second
)

// consensusPersister owns the background writer.
type consensusPersister struct {
	store    consensusRecordStore
	writerID string
	logger   *log.Logger

	queue  chan persistJob
	cancel context.CancelFunc
	done   chan struct{}

	sourceMu sync.RWMutex
	source   committedBlockSource

	// Committed heights seen by enqueue, INCLUDING refused hand-offs. The writer uses them to rebuild a
	// dropped tail without waiting for another block: this chain produces blocks only for real work, so
	// the next hand-off can be hours away.
	firstSeen      atomic.Int64 // first height ever offered (0 = none)
	latest         atomic.Int64 // highest height offered
	validatorCount atomic.Int64 // validator count of the latest offer, for rebuilt heights

	// Observability for operators and tests.
	dropped   atomic.Uint64 // hand-offs refused because the queue was full
	persisted atomic.Int64  // highest height persisted by this process (0 = none yet)
	gaps      atomic.Uint64 // heights that could not be rebuilt
	rejected  atomic.Uint64 // rows the database refused on content (skipped, never retried)

	rewinds atomic.Uint64 // watermark found ahead of the chain

	retryBase   time.Duration
	retryMax    time.Duration
	idleCheck   time.Duration // how often an idle writer looks for heights it was not handed
	callTimeout time.Duration
}

func newConsensusPersister(store consensusRecordStore, writerID string, logger *log.Logger) *consensusPersister {
	if logger == nil {
		logger = log.New(log.Writer(), "[Persist] ", log.LstdFlags)
	}
	return &consensusPersister{
		store:       store,
		writerID:    writerID,
		logger:      logger,
		queue:       make(chan persistJob, persistQueueCapacity),
		done:        make(chan struct{}),
		retryBase:   persistRetryBase,
		retryMax:    persistRetryMax,
		idleCheck:   persistIdleCheck,
		callTimeout: persistCallTimeout,
	}
}

// call bounds one database call.
func (p *consensusPersister) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, p.callTimeout)
}

// seedCommitted tells a writer that heights (startHeight, latestHeight] were committed by this process before
// persistence was enabled (the CometBFT handshake replays blocks before the database is wired). They are
// rebuilt from the block store like dropped hand-offs. It must be called before start.
func (p *consensusPersister) seedCommitted(startHeight, latestHeight int64) {
	p.firstSeen.CompareAndSwap(0, startHeight+1)
	if latestHeight > p.latest.Load() {
		p.latest.Store(latestHeight)
	}
}

// start launches the writer. It must be called once.
func (p *consensusPersister) start() {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go p.run(ctx)
}

// stop cancels the writer and waits for it to exit. Blocks still queued are not written; they are
// rebuilt from the block store on the next start.
func (p *consensusPersister) stop() {
	if p.cancel != nil {
		p.cancel()
		<-p.done
	}
}

func (p *consensusPersister) setSource(s committedBlockSource) {
	p.sourceMu.Lock()
	p.source = s
	p.sourceMu.Unlock()
}

func (p *consensusPersister) getSource() committedBlockSource {
	p.sourceMu.RLock()
	defer p.sourceMu.RUnlock()
	return p.source
}

// enqueue hands a committed block to the writer WITHOUT blocking. It is called from ABCI Commit, which
// must never wait on the database. A refused hand-off is not lost: the writer rebuilds that height from
// the block store before its next hand-off, or as soon as its queue is empty.
func (p *consensusPersister) enqueue(b committedBlock, validatorCount int) bool {
	// firstSeen before the send, so the writer never handles a job without knowing where it started;
	// latest after it, so an idle writer never races a job that is about to be queued.
	p.firstSeen.CompareAndSwap(0, b.height)
	p.validatorCount.Store(int64(validatorCount))
	defer func() {
		for {
			cur := p.latest.Load()
			if b.height <= cur || p.latest.CompareAndSwap(cur, b.height) {
				return
			}
		}
	}()
	select {
	case p.queue <- persistJob{block: b, validatorCount: validatorCount}:
		return true
	default:
		n := p.dropped.Add(1)
		metrics.RecordConsensusPersistDropped()
		p.logger.Printf("⚠️ [PERSIST] hand-off queue full; height %d will be rebuilt from the block store (dropped=%d)", b.height, n)
		return false
	}
}

func (p *consensusPersister) run(ctx context.Context) {
	defer close(p.done)

	// last is the highest height known to be persisted for this writer; -1 until established.
	last := int64(-1)
	for attempt := 1; ; attempt++ {
		cctx, cancel := p.call(ctx)
		err := p.store.EnsurePersistenceProgressTable(cctx)
		cancel()
		if err != nil {
			metrics.RecordConsensusPersistError("ensure_table")
			p.logger.Printf("⚠️ [PERSIST] could not ensure the persisted-height table (attempt %d; consensus is unaffected, rows are not being written): %v", attempt, err)
			if !p.sleep(ctx, attempt) {
				return
			}
			continue
		}
		cctx, cancel = p.call(ctx)
		h, found, err := p.store.LoadPersistedHeight(cctx, p.writerID)
		cancel()
		if err == nil {
			if found {
				last = h
			}
			break
		}
		metrics.RecordConsensusPersistError("load_watermark")
		p.logger.Printf("⚠️ [PERSIST] could not load the persisted height for %s (attempt %d; consensus is unaffected, rows are not being written): %v", p.writerID, attempt, err)
		if !p.sleep(ctx, attempt) {
			return
		}
	}

	// startAt runs once, at the first height this process is offered:
	//   - no watermark: begin there. History before it was written by earlier binaries; rebuilding it is not
	//     this writer's job.
	//   - watermark at or above it: persistence can only trail commits, so the chain was reset (or replayed
	//     from an earlier app state). Skipping to the old watermark would silently persist nothing until the
	//     new chain passed it; rewind instead. Re-persisting a replayed height is harmless (insert-once).
	started := false
	startAt := func() bool {
		if started {
			return true
		}
		first := p.firstSeen.Load()
		if first <= 0 {
			return false
		}
		if last >= first {
			n := p.rewinds.Add(1)
			metrics.RecordConsensusPersistRewind()
			p.logger.Printf("⚠️ [PERSIST] persisted height %d for %s is at or above the first committed height %d of this run: the chain was reset or replayed; rewinding to %d (rewinds=%d)",
				last, p.writerID, first, first-1, n)
			for attempt := 1; ; attempt++ {
				cctx, cancel := p.call(ctx)
				err := p.store.ResetPersistedHeight(cctx, p.writerID, first-1)
				cancel()
				if err == nil {
					break
				}
				metrics.RecordConsensusPersistError("rewind_watermark")
				p.logger.Printf("⚠️ [PERSIST] could not rewind the persisted height for %s (attempt %d): %v", p.writerID, attempt, err)
				if !p.sleep(ctx, attempt) {
					return false
				}
			}
			last = first - 1
		} else if last < 0 {
			last = first - 1
		}
		started = true
		return true
	}

	idle := time.NewTicker(p.idleCheck)
	defer idle.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case job := <-p.queue:
			if !startAt() {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			h := job.block.height
			if h <= last {
				continue // already persisted (a replayed or duplicate hand-off, or rebuilt while idle)
			}
			for gap := last + 1; gap < h; gap++ {
				if !p.rebuild(ctx, gap, job.validatorCount) {
					return
				}
				last = gap
			}
			if !p.write(ctx, &job.block, job.validatorCount) {
				return
			}
			last = h

		case <-idle.C:
			// Nothing queued, but heights may have been offered and refused (a full queue). Rebuild them now
			// rather than when the next block commits.
			if len(p.queue) > 0 {
				continue
			}
			if !startAt() {
				if ctx.Err() != nil {
					return
				}
				continue // nothing offered yet
			}
			for target := p.latest.Load(); last < target; {
				if !p.rebuild(ctx, last+1, int(p.validatorCount.Load())) {
					return
				}
				last++
			}
		}
	}
}

// rebuild persists a height the writer never received. It returns false only when ctx ends.
func (p *consensusPersister) rebuild(ctx context.Context, height int64, validatorCount int) bool {
	for attempt := 1; ; attempt++ {
		src := p.getSource()
		if src == nil {
			n := p.gaps.Add(1)
			metrics.RecordConsensusPersistGap()
			p.logger.Printf("⚠️ [PERSIST] height %d was not handed off and no block source is configured; skipping (gaps=%d)", height, n)
			return p.advanceOnly(ctx, height)
		}
		cctx, cancel := p.call(ctx)
		blk, err := src.CommittedValidatorBlocks(cctx, height)
		cancel()
		if err == nil {
			p.logger.Printf("🔁 [PERSIST] rebuilt height %d from the block store (%d ValidatorBlocks)", height, len(blk.blocks))
			return p.write(ctx, blk, validatorCount)
		}
		if errors.Is(err, errCommittedBlockUnavailable) {
			n := p.gaps.Add(1)
			metrics.RecordConsensusPersistGap()
			p.logger.Printf("⚠️ [PERSIST] height %d is no longer in the block store; its rows cannot be rebuilt (gaps=%d): %v", height, n, err)
			return p.advanceOnly(ctx, height)
		}
		metrics.RecordConsensusPersistError("read_block")
		p.logger.Printf("⚠️ [PERSIST] could not read committed height %d (attempt %d): %v", height, attempt, err)
		if !p.sleep(ctx, attempt) {
			return false
		}
	}
}

// advanceOnly moves the watermark past a height whose rows cannot be produced.
func (p *consensusPersister) advanceOnly(ctx context.Context, height int64) bool {
	return p.write(ctx, &committedBlock{height: height}, 0)
}

// write persists one block, retrying until it succeeds or ctx ends.
func (p *consensusPersister) write(ctx context.Context, b *committedBlock, validatorCount int) bool {
	rec := consensusRecordsFor(b, validatorCount, p.logger)
	for attempt := 1; ; attempt++ {
		cctx, cancel := p.call(ctx)
		rejected, err := p.store.PersistCommittedBlock(cctx, p.writerID, rec)
		cancel()
		if err == nil {
			for _, r := range rejected {
				n := p.rejected.Add(1)
				metrics.RecordConsensusPersistRejected()
				p.logger.Printf("⚠️ [PERSIST] height %d: the database refused the %s row for batch %s; skipped (rejected=%d): %v",
					b.height, r.Table, r.BatchID, n, r.Err)
			}
			p.persisted.Store(b.height)
			metrics.SetConsensusPersistLag(max(p.latest.Load()-b.height, 0))
			if len(rec.Entries) > 0 || len(rec.Attestations) > 0 {
				p.logger.Printf("✅ [PERSIST] height %d: %d consensus entries, %d batch attestations",
					b.height, len(rec.Entries), len(rec.Attestations))
			}
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		metrics.RecordConsensusPersistError("persist_block")
		metrics.SetConsensusPersistLag(max(p.latest.Load()-(b.height-1), 0))
		p.logger.Printf("⚠️ [PERSIST] could not persist height %d (attempt %d; consensus is unaffected): %v", b.height, attempt, err)
		if !p.sleep(ctx, attempt) {
			return false
		}
	}
}

// sleep waits an exponential backoff for attempt, returning false if ctx ends first.
func (p *consensusPersister) sleep(ctx context.Context, attempt int) bool {
	d := p.retryBase
	for i := 1; i < attempt && d < p.retryMax; i++ {
		d *= 2
	}
	if d > p.retryMax {
		d = p.retryMax
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

// consensusRecordsFor derives the rows a committed block contributes. It is a pure function of the block,
// so the Commit hand-off and a block-store rebuild produce identical rows.
//
// The per-block mapping is exactly the one the Commit path always used — governance level -> state, an
// undecodable hex field stored as empty bytes, one self-attestation when a BLS signature is present; what
// changed is when and how often it is written. completed_at is the block time, not the wall clock.
func consensusRecordsFor(b *committedBlock, validatorCount int, logger *log.Logger) *database.CommittedConsensusRecords {
	rec := &database.CommittedConsensusRecords{Height: b.height}
	for i := range b.blocks {
		vb := &b.blocks[i]
		batchUUID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(vb.BundleID))

		merkleRoot, err := database.DecodeHexString(vb.GovernanceProof.MerkleRoot)
		if err != nil {
			logger.Printf("⚠️ [PERSIST] Failed to decode merkle_root for bundle %s: %v", vb.BundleID, err)
			merkleRoot = nil
		}
		blsSig, err := database.DecodeHexString(vb.GovernanceProof.BLSAggregateSignature)
		if err != nil {
			logger.Printf("⚠️ [PERSIST] Failed to decode BLS signature for bundle %s: %v", vb.BundleID, err)
			blsSig = nil
		}
		blsPub, err := database.DecodeHexString(vb.GovernanceProof.BLSValidatorSetPubKey)
		if err != nil {
			logger.Printf("⚠️ [PERSIST] Failed to decode BLS pubkey for bundle %s: %v", vb.BundleID, err)
			blsPub = nil
		}

		startTime, err := time.Parse(time.RFC3339, vb.Timestamp)
		if err != nil {
			startTime = b.time
		}

		state := "initiated"
		switch vb.GovernanceProof.GovernanceLevel {
		case "G2":
			state = "completed"
		case "G1":
			state = "quorum_met"
		case "G0":
			state = "collecting"
		}
		var completedAt *time.Time
		if state == "completed" || state == "quorum_met" {
			t := b.time
			completedAt = &t
		}

		quorumFraction := 0.0
		if validatorCount > 0 {
			quorumFraction = 1.0 / float64(validatorCount) // one self-attestation
		}

		resultJSON := map[string]interface{}{
			"bundle_id":             vb.BundleID,
			"governance_level":      vb.GovernanceProof.GovernanceLevel,
			"operation_commitment":  vb.OperationCommitment,
			"execution_stage":       vb.ExecutionProof.Stage,
			"proof_class":           vb.ExecutionProof.ProofClass,
			"cross_chain_operation": vb.CrossChainProof.OperationID,
		}
		if vb.GovernanceProof.G0Proof != nil {
			resultJSON["g0_complete"] = vb.GovernanceProof.G0Proof.G0ProofComplete
			resultJSON["g0_txid"] = vb.GovernanceProof.G0Proof.TXID
		}
		if vb.GovernanceProof.G1Proof != nil {
			resultJSON["g1_complete"] = vb.GovernanceProof.G1Proof.G1ProofComplete
			resultJSON["g1_threshold_satisfied"] = vb.GovernanceProof.G1Proof.ThresholdSatisfied
		}
		if vb.GovernanceProof.G2Proof != nil {
			resultJSON["g2_complete"] = vb.GovernanceProof.G2Proof.G2ProofComplete
			resultJSON["g2_payload_verified"] = vb.GovernanceProof.G2Proof.PayloadVerified
		}

		rec.Entries = append(rec.Entries, database.CommittedConsensusEntry{
			NewConsensusEntry: database.NewConsensusEntry{
				BatchID:            batchUUID,
				MerkleRoot:         merkleRoot,
				AnchorTxHash:       vb.AccumulateAnchorReference.TxHash,
				BlockNumber:        int64(vb.BlockHeight),
				TxCount:            len(vb.SyntheticTransactions),
				State:              state,
				AttestationCount:   1,
				RequiredCount:      (validatorCount * 2 / 3) + 1,
				QuorumFraction:     quorumFraction,
				AggregateSignature: blsSig,
				AggregatePubKey:    blsPub,
				StartTime:          startTime,
				ResultJSON:         resultJSON,
			},
			CompletedAt: completedAt,
		})

		// This validator's self-attestation, when the block carries a BLS signature.
		if len(blsSig) > 0 {
			valid := true
			rec.Attestations = append(rec.Attestations, database.NewBatchAttestation{
				BatchID:         batchUUID,
				ValidatorID:     vb.ValidatorID,
				MerkleRoot:      merkleRoot,
				BLSSignature:    blsSig,
				BLSPublicKey:    blsPub,
				TxCount:         len(vb.SyntheticTransactions),
				BlockHeight:     int64(vb.BlockHeight),
				AttestationTime: startTime,
				SignatureValid:  &valid,
			})
		}
	}
	return rec
}

// String is used in logs and tests.
func (b committedBlock) String() string {
	return fmt.Sprintf("height=%d blocks=%d", b.height, len(b.blocks))
}
