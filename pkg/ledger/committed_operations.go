// Copyright 2026 Certen Protocol

package ledger

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

// The committed-operation index (RB3-F141): for every ValidatorBlock the chain accepted, the first height at
// which that validator's block for that operation committed. It is the app's own record of what consensus
// committed - written in Commit, rebuilt from the block store for any height the app committed without it -
// so a node can ask "has my block for this operation committed?" and get the chain's answer, where the
// transaction index cannot give one (the last inclusion of a hash wins there, in both directions).

// CommittedOperation is where a validator's ValidatorBlock for an operation first committed.
type CommittedOperation struct {
	Height    int64     `json:"height"`
	BundleID  string    `json:"bundle_id"`
	TxHash    string    `json:"tx_hash"` // hex sha256 of the committed transaction bytes (CometBFT's tx hash)
	BlockTime time.Time `json:"block_time"`
}

// CommittedOperationEntry is one accepted ValidatorBlock of a committed block.
type CommittedOperationEntry struct {
	ValidatorID string
	OperationID string
	Committed   CommittedOperation
}

var (
	keyCommittedOperationPrefix = []byte("abci:committed_op:")        // + validator id + 0x00 + operation id -> CommittedOperation
	keyCommittedOperationsUpTo  = []byte("abci:committed_ops_upto")   // -> big-endian int64: every height at or below it is indexed
	keyRulesFirstVerdictPrefix  = []byte("abci:rules_first_verdict:") // + version -> big-endian int64 height
)

func committedOperationKey(validatorID, operationID string) []byte {
	k := append([]byte(nil), keyCommittedOperationPrefix...)
	k = append(k, validatorID...)
	k = append(k, 0)
	return append(k, operationID...)
}

// ErrCommittedOperationsGap is a block recorded above a height the index does not yet cover.
var ErrCommittedOperationsGap = fmt.Errorf("committed-operation index gap")

// GetCommittedOperation returns where the validator's block for the operation first committed, or nil when
// no such block has committed at or below CommittedOperationsUpTo.
func (s *LedgerStore) GetCommittedOperation(validatorID, operationID string) (*CommittedOperation, error) {
	if validatorID == "" || operationID == "" {
		return nil, fmt.Errorf("a committed operation is named by its validator and operation")
	}
	b, err := s.read(committedOperationKey(validatorID, operationID), "committed operation")
	if err != nil || b == nil {
		return nil, err
	}
	var op CommittedOperation
	if err := json.Unmarshal(b, &op); err != nil {
		return nil, fmt.Errorf("committed operation %s/%s: %w", validatorID, operationID, err)
	}
	return &op, nil
}

// CommittedOperationsUpTo is the height through which every committed block is indexed (0: none).
func (s *LedgerStore) CommittedOperationsUpTo() (int64, error) {
	b, err := s.read(keyCommittedOperationsUpTo, "committed-operation index height")
	if err != nil || b == nil {
		return 0, err
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("committed-operation index height is %d bytes, not 8", len(b))
	}
	return int64(binary.BigEndian.Uint64(b)), nil
}

// RecordCommittedBlock indexes one committed block's accepted ValidatorBlocks and advances the covered
// height to it. The first commit of an operation is kept: a later block naming the same validator and
// operation never replaces it. Recording a height already covered is a replay and changes nothing; a height
// above the next one is refused, because the index would claim heights it never read.
func (s *LedgerStore) RecordCommittedBlock(height int64, entries []CommittedOperationEntry) error {
	upTo, err := s.CommittedOperationsUpTo()
	if err != nil {
		return err
	}
	if height > upTo+1 {
		return fmt.Errorf("%w: height %d recorded while the index covers only %d", ErrCommittedOperationsGap, height, upTo)
	}
	for _, e := range entries {
		existing, err := s.GetCommittedOperation(e.ValidatorID, e.OperationID)
		if err != nil {
			return err
		}
		if existing != nil {
			continue
		}
		b, err := json.Marshal(e.Committed)
		if err != nil {
			return fmt.Errorf("marshal committed operation: %w", err)
		}
		if err := s.kv.Set(committedOperationKey(e.ValidatorID, e.OperationID), b); err != nil {
			return fmt.Errorf("record committed operation %s/%s: %w", e.ValidatorID, e.OperationID, err)
		}
	}
	if height <= upTo {
		return nil
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(height))
	return s.kv.Set(keyCommittedOperationsUpTo, b)
}

func rulesFirstVerdictKey(version uint64) []byte {
	return append(append([]byte(nil), keyRulesFirstVerdictPrefix...), []byte(fmt.Sprintf("%d", version))...)
}

// RulesFirstVerdict is the height of the first committed block that a rules version decided in a way no
// older version does (0: none) - from then on only that version reproduces the chain.
func (s *LedgerStore) RulesFirstVerdict(version uint64) (int64, error) {
	b, err := s.read(rulesFirstVerdictKey(version), fmt.Sprintf("rules v%d first verdict", version))
	if err != nil || b == nil {
		return 0, err
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("rules v%d first verdict is %d bytes, not 8", version, len(b))
	}
	return int64(binary.BigEndian.Uint64(b)), nil
}

// SaveRulesFirstVerdict records the first such height for a version. A later one never replaces it.
func (s *LedgerStore) SaveRulesFirstVerdict(version uint64, height int64) error {
	have, err := s.RulesFirstVerdict(version)
	if err != nil {
		return err
	}
	if have != 0 && have <= height {
		return nil
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(height))
	return s.kv.Set(rulesFirstVerdictKey(version), b)
}

// StartCommittedOperations records where the chain begins: a genesis with an initial height above 1 has no
// blocks below it, so the index covers them from the start. It changes only an index that covers nothing.
func (s *LedgerStore) StartCommittedOperations(initialHeight int64) error {
	upTo, err := s.CommittedOperationsUpTo()
	if err != nil || upTo != 0 || initialHeight <= 1 {
		return err
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(initialHeight-1))
	return s.kv.Set(keyCommittedOperationsUpTo, b)
}

// The kinds watermark: the height through which every committed block has been checked to hold no transaction of a
// kind a later rules version added, decided the way the version before it decided it (consensus/committed_operations.go,
// checkCommittedKinds). Kept per rules version, because each version that adds a kind has to check the whole chain
// for it once.
func kindsCheckedKey(version uint64) []byte {
	return []byte(fmt.Sprintf("abci:kinds_checked_through:v%d", version))
}

// KindsCheckedThrough is the height through which committed blocks are checked for rules version (0: none).
func (s *LedgerStore) KindsCheckedThrough(version uint64) (int64, error) {
	b, err := s.read(kindsCheckedKey(version), fmt.Sprintf("rules v%d kinds watermark", version))
	if err != nil || b == nil {
		return 0, err
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("rules v%d kinds watermark is %d bytes, not 8", version, len(b))
	}
	return int64(binary.BigEndian.Uint64(b)), nil
}

// SaveKindsCheckedThrough records that every committed block through height is checked for rules version. It never
// lowers the watermark.
func (s *LedgerStore) SaveKindsCheckedThrough(version uint64, height int64) error {
	have, err := s.KindsCheckedThrough(version)
	if err != nil || height <= have {
		return err
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(height))
	return s.kv.Set(kindsCheckedKey(version), b)
}

// AdvanceKindsChecked moves the watermark to height when height is the next one - a block the binary of that rules
// version committed itself. A height above the next leaves it where it is: the heights between were never checked, and
// the next start checks them.
func (s *LedgerStore) AdvanceKindsChecked(version uint64, height int64) error {
	have, err := s.KindsCheckedThrough(version)
	if err != nil || height != have+1 {
		return err
	}
	return s.SaveKindsCheckedThrough(version, height)
}
