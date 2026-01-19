package ledger

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

// KV defines the key-value store interface
type KV interface {
	Get(key []byte) ([]byte, error)
	Set(key, value []byte) error
	// Optional: Has, Delete, Iterator, etc.
}

// LedgerStore provides high-level access to ledger data in the KV store.
//
// CONCURRENCY: LedgerStore assumes single-writer access and is designed to be called
// from the consensus commit thread only. If you need to use LedgerStore from multiple
// goroutines, you must wrap it with your own synchronization (e.g., mutex or channel).
//
// This design choice optimizes for the primary use case where all ledger updates
// happen during the BFT commit phase in a single thread.
type LedgerStore struct {
	kv KV
}

// NewLedgerStore creates a new LedgerStore instance
func NewLedgerStore(kv KV) *LedgerStore {
	return &LedgerStore{kv: kv}
}

// ====== KV Key Layout ======

var (
	// System ledger keys
	keySysMeta        = []byte("sysledger:meta")              // -> SystemLedgerMeta
	keySysLatestBlock = []byte("sysledger:latest_block")      // -> SystemLedgerBlockMeta
	keySysBlockPrefix = []byte("sysledger:block:")            // + big-endian height -> SystemLedgerBlockMeta

	// Anchor ledger keys
	keyAnchorMeta         = []byte("anchorledger:meta")         // -> AnchorLedgerMeta
	keyAnchorTargetPrefix = []byte("anchorledger:target:")     // + targetURL -> AnchorTargetState

	// Intent discovery state keys
	keyIntentLastBlock = []byte("intent:last_block")          // -> uint64 (last processed block height)

	// ABCI state keys (for CometBFT state recovery)
	keyABCIState = []byte("abci:state")                       // -> ABCIState (height + appHash)
)

// systemBlockKey generates a KV key for a specific system ledger block
func systemBlockKey(height uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, height)
	return append(keySysBlockPrefix, b...)
}

// anchorTargetKey generates a KV key for a specific anchor target
func anchorTargetKey(targetURL string) []byte {
	return append(keyAnchorTargetPrefix, []byte(targetURL)...)
}

// ====== System Ledger Store Methods ======

// UpdateSystemLedgerOnCommit updates the system ledger state when a block is committed
func (s *LedgerStore) UpdateSystemLedgerOnCommit(
	height uint64,
	hash string,
	t time.Time,
	accRef *SystemAccumulateAnchorRef, // may be nil
	executorVersion string,
	upstream []UpstreamExecutor,
) error {
	// 1. Save per-block meta
	meta := &SystemLedgerBlockMeta{
		Height: height,
		Hash:   hash,
		Time:   t,
	}
	if accRef != nil {
		meta.AccumulateAnchorHash = accRef.TxHash
		meta.AccumulateAnchorAccount = accRef.AccountURL
		meta.AccumulateMinorBlockIndex = accRef.MinorIndex
		meta.AccumulateMajorBlockIndex = accRef.MajorIndex
	}

	b, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal SystemLedgerBlockMeta: %w", err)
	}
	if err := s.kv.Set(systemBlockKey(height), b); err != nil {
		return fmt.Errorf("failed to set system block key: %w", err)
	}
	if err := s.kv.Set(keySysLatestBlock, b); err != nil {
		return fmt.Errorf("failed to set system latest block key: %w", err)
	}

	// 2. Update global meta
	gm, err := s.loadSystemLedgerMeta()
	if err != nil {
		// F.4 remediation: Handle ErrMetaNotFound as expected (first write)
		if err == ErrMetaNotFound {
			gm = &SystemLedgerMeta{}
		} else {
			return fmt.Errorf("failed to load system ledger meta: %w", err)
		}
	}
	if height > gm.LatestHeight {
		gm.LatestHeight = height
	}
	gm.ExecutorVersion = executorVersion
	gm.UpstreamVersions = upstream

	mb, err := json.Marshal(gm)
	if err != nil {
		return fmt.Errorf("failed to marshal SystemLedgerMeta: %w", err)
	}
	return s.kv.Set(keySysMeta, mb)
}

// loadSystemLedgerMeta loads the global system ledger metadata
func (s *LedgerStore) loadSystemLedgerMeta() (*SystemLedgerMeta, error) {
	b, err := s.kv.Get(keySysMeta)
	if err != nil || len(b) == 0 {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrMetaNotFound
	}
	var m SystemLedgerMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SystemLedgerMeta: %w", err)
	}
	return &m, nil
}

// GetSystemLedgerLatest retrieves the latest system ledger state
func (s *LedgerStore) GetSystemLedgerLatest(chainID string) (*SystemLedgerState, error) {
	gm, err := s.loadSystemLedgerMeta()
	if err != nil {
		return nil, fmt.Errorf("failed to load system ledger meta: %w", err)
	}

	b, err := s.kv.Get(keySysLatestBlock)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}
	var blockMeta SystemLedgerBlockMeta
	if err := json.Unmarshal(b, &blockMeta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SystemLedgerBlockMeta: %w", err)
	}

	return s.buildSystemLedgerState(chainID, gm, &blockMeta), nil
}

// buildSystemLedgerState constructs a SystemLedgerState from metadata and block info
func (s *LedgerStore) buildSystemLedgerState(
	chainID string,
	gm *SystemLedgerMeta,
	latest *SystemLedgerBlockMeta,
) *SystemLedgerState {
	// For now, mainChain & merkleState are the same simple chain summary
	root := latest.Hash // or compute a real Merkle root if you have one

	main := ChainSummary{
		Name:   "main",
		Type:   "block",
		Height: gm.LatestHeight,
		Count:  gm.LatestHeight,
		Roots:  []string{root},
	}

	data := SystemLedgerData{
		Type:                "systemLedger",
		URL:                 "certen://system/ledger",
		Index:               gm.LatestHeight,
		Timestamp:           latest.Time,
		ExecutorVersion:     gm.ExecutorVersion,
		BVNExecutorVersions: gm.UpstreamVersions,
	}

	return &SystemLedgerState{
		Type:          "systemLedger",
		MainChain:     main,
		MerkleState:   main,
		Chains:        []ChainSummary{main},
		Data:          data,
		ChainID:       chainID,
		LastBlockTime: latest.Time,
	}
}

// ====== Anchor Ledger Store Methods ======

// loadAnchorMeta loads the global anchor ledger metadata
func (s *LedgerStore) loadAnchorMeta() (*AnchorLedgerMeta, error) {
	b, err := s.kv.Get(keyAnchorMeta)
	if err != nil || len(b) == 0 {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrAnchorMetaNotFound
	}
	var m AnchorLedgerMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AnchorLedgerMeta: %w", err)
	}
	return &m, nil
}

// saveAnchorMeta saves the global anchor ledger metadata
func (s *LedgerStore) saveAnchorMeta(m *AnchorLedgerMeta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal AnchorLedgerMeta: %w", err)
	}
	return s.kv.Set(keyAnchorMeta, b)
}

// loadAnchorTarget loads the state for a specific anchor target
func (s *LedgerStore) loadAnchorTarget(url string) (*AnchorTargetState, error) {
	b, err := s.kv.Get(anchorTargetKey(url))
	if err != nil || len(b) == 0 {
		return &AnchorTargetState{TargetURL: url}, nil
	}
	var t AnchorTargetState
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AnchorTargetState: %w", err)
	}
	return &t, nil
}

// saveAnchorTarget saves the state for a specific anchor target
func (s *LedgerStore) saveAnchorTarget(t *AnchorTargetState) error {
	b, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("failed to marshal AnchorTargetState: %w", err)
	}
	return s.kv.Set(anchorTargetKey(t.TargetURL), b)
}

// MarkAnchorProduced marks an anchor as produced (sent from Certen)
func (s *LedgerStore) MarkAnchorProduced(
	certenBlockHeight uint64,
	targetURL string,
	txid string,
	t time.Time,
	majorIndex uint64,    // Accumulate major block index, if applicable
	majorTime time.Time,  // Accumulate major block time, if applicable
) error {
	meta, err := s.loadAnchorMeta()
	if err != nil {
		// F.4 remediation: Handle ErrAnchorMetaNotFound as expected (first write)
		if err == ErrAnchorMetaNotFound {
			meta = &AnchorLedgerMeta{}
		} else {
			return fmt.Errorf("failed to load anchor meta: %w", err)
		}
	}
	meta.LastSequenceNumber++
	if majorIndex > 0 {
		meta.LastMajorIndex = majorIndex
		meta.LastMajorTime = majorTime
	}
	meta.LastBlockTime = t

	if err := s.saveAnchorMeta(meta); err != nil {
		return fmt.Errorf("failed to save anchor meta: %w", err)
	}

	tgt, err := s.loadAnchorTarget(targetURL)
	if err != nil {
		return fmt.Errorf("failed to load anchor target: %w", err)
	}
	tgt.Received++
	tgt.LastAnchorHeight = certenBlockHeight
	tgt.LastAnchorTxID = txid
	tgt.LastAnchorTime = t

	return s.saveAnchorTarget(tgt)
}

// MarkAnchorDelivered marks an anchor as delivered (confirmed on target chain)
func (s *LedgerStore) MarkAnchorDelivered(
	targetURL string,
	txid string,
	t time.Time,
) error {
	tgt, err := s.loadAnchorTarget(targetURL)
	if err != nil {
		return fmt.Errorf("failed to load anchor target: %w", err)
	}
	tgt.Delivered++
	tgt.LastAnchorTxID = txid
	tgt.LastAnchorTime = t

	return s.saveAnchorTarget(tgt)
}

// GetAnchorLedger retrieves the complete anchor ledger state
func (s *LedgerStore) GetAnchorLedger(chainID string) (*AnchorLedgerState, error) {
	meta, err := s.loadAnchorMeta()
	if err != nil {
		return nil, fmt.Errorf("failed to load anchor meta: %w", err)
	}

	var seq []AnchorSequenceItem
	for _, url := range AnchorTargets {
		tgt, err := s.loadAnchorTarget(url)
		if err != nil {
			return nil, fmt.Errorf("failed to load anchor target %s: %w", url, err)
		}
		seq = append(seq, AnchorSequenceItem{
			URL:       tgt.TargetURL,
			Received:  tgt.Received,
			Delivered: tgt.Delivered,
		})
	}

	main := ChainSummary{
		Name:   "anchor-sequence",
		Type:   "transaction",
		Height: meta.LastSequenceNumber,
		Count:  meta.LastSequenceNumber,
		Roots:  []string{}, // optional: compute real root if you keep event log
	}

	data := AnchorLedgerData{
		Type:                     "anchorLedger",
		URL:                      "certen://anchors",
		MinorBlockSequenceNumber: meta.LastSequenceNumber,
		MajorBlockIndex:          meta.LastMajorIndex,
		MajorBlockTime:           meta.LastMajorTime,
		Sequence:                 seq,
	}

	return &AnchorLedgerState{
		Type:          "anchorLedger",
		MainChain:     main,
		MerkleState:   main,
		Chains:        []ChainSummary{main},
		Data:          data,
		ChainID:       chainID,
		LastBlockTime: meta.LastBlockTime,
	}, nil
}

// ====== Intent Discovery State Methods ======

// SaveIntentLastBlock persists the last processed block height for intent discovery
// NOTE: LedgerStore assumes single-writer access (called from consensus commit thread only).
// If you use it from multiple goroutines, wrap it with your own mutex.
func (s *LedgerStore) SaveIntentLastBlock(height uint64) error {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, height)
	return s.kv.Set(keyIntentLastBlock, b)
}

// LoadIntentLastBlock loads the last processed block height for intent discovery
// Returns 0 if no height has been persisted yet
func (s *LedgerStore) LoadIntentLastBlock() (uint64, error) {
	b, err := s.kv.Get(keyIntentLastBlock)
	if err != nil || len(b) == 0 {
		return 0, nil // No height persisted yet
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("invalid intent last block data: expected 8 bytes, got %d", len(b))
	}
	return binary.BigEndian.Uint64(b), nil
}

// ====== ABCI State Persistence for CometBFT Recovery ======

// SaveABCIState persists the ABCI application state for CometBFT recovery.
// This must be called during Commit() to ensure the state is durable.
func (s *LedgerStore) SaveABCIState(state *ABCIState) error {
	b, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal ABCIState: %w", err)
	}
	return s.kv.Set(keyABCIState, b)
}

// LoadABCIState loads the persisted ABCI state for recovery after restart.
// Returns nil, nil if no state has been persisted yet (fresh start).
func (s *LedgerStore) LoadABCIState() (*ABCIState, error) {
	b, err := s.kv.Get(keyABCIState)
	if err != nil || len(b) == 0 {
		return nil, nil // No state persisted yet - fresh start
	}
	var state ABCIState
	if err := json.Unmarshal(b, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ABCIState: %w", err)
	}
	return &state, nil
}

// ====== Historical System Ledger Queries ======

// GetSystemLedgerAtHeight builds a SystemLedgerState for a specific block height
// This provides time-travel capability for debugging and dashboards
func (s *LedgerStore) GetSystemLedgerAtHeight(chainID string, height uint64) (*SystemLedgerState, error) {
	// Read the specific block metadata instead of latest
	b, err := s.kv.Get(systemBlockKey(height))
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("block metadata not found for height %d", height)
	}

	var blockMeta SystemLedgerBlockMeta
	if err := json.Unmarshal(b, &blockMeta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SystemLedgerBlockMeta for height %d: %w", height, err)
	}

	// Use the same build logic but with the specific block metadata
	return s.buildSystemLedgerStateFromBlock(chainID, &blockMeta)
}

// buildSystemLedgerStateFromBlock builds a SystemLedgerState from a specific block metadata
func (s *LedgerStore) buildSystemLedgerStateFromBlock(chainID string, blockMeta *SystemLedgerBlockMeta) (*SystemLedgerState, error) {
	// Load global meta for executor versions
	sysMeta, err := s.loadSystemLedgerMeta()
	if err != nil {
		return nil, fmt.Errorf("failed to load system meta: %w", err)
	}
	if sysMeta == nil {
		sysMeta = &SystemLedgerMeta{
			ExecutorVersion:   "1.0.0",
			UpstreamVersions:  []UpstreamExecutor{},
		}
	}

	main := ChainSummary{
		Name:   "main",
		Type:   "transaction",
		Height: blockMeta.Height,
		Count:  blockMeta.Height,
		Roots:  []string{blockMeta.Hash},
	}

	data := SystemLedgerData{
		Type:                "systemLedger",
		URL:                 fmt.Sprintf("certen://%s", chainID),
		Index:               blockMeta.Height,
		Timestamp:           blockMeta.Time,
		ExecutorVersion:     sysMeta.ExecutorVersion,
		BVNExecutorVersions: sysMeta.UpstreamVersions,
	}

	return &SystemLedgerState{
		Type:          "systemLedger",
		MainChain:     main,
		MerkleState:   main,
		Chains:        []ChainSummary{main},
		Data:          data,
		ChainID:       chainID,
		LastBlockTime: blockMeta.Time,
	}, nil
}