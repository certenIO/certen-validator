package ledger

import (
	"encoding/json"
	"fmt"
)

// The Accumulate validator-set spine, held in CERTEN's consensus state (RB6, docs/proof/GOVROOT_V3.md "consensus-held
// spine"). Every validator verifies each Accumulate major block once, deterministically, when it is committed here; a
// proof v2 is then judged in consensus against these checkpoints, with no I/O and no node relying on its own view.

var keyAccumulateSpine = []byte("abci:accumulate_spine") // -> AccumulateSpineLog

// AccumulateSpineLog is the spine as the chain has verified it: its genesis, one checkpoint per verified major block,
// and each distinct validator set they reference.
type AccumulateSpineLog struct {
	Genesis     *AccumulateSpineGenesis     `json:"genesis,omitempty"`
	Checkpoints []AccumulateSpineCheckpoint `json:"checkpoints"`
	Sets        []AccumulateSpineSet        `json:"sets"`
}

// AccumulateSpineGenesis is the spine's starting point: the incarnation's genesis facts, accepted only when they
// recompute the incarnation of CERTEN's BLS registry in force.
type AccumulateSpineGenesis struct {
	Incarnation     string `json:"incarnation"` // 0x-hex
	Height          int64  `json:"height"`      // the CERTEN block that accepted it
	MinorBlockIndex uint64 `json:"minor_block_index"`
	RootChainAnchor string `json:"root_chain_anchor"` // hex32
	StateTreeAnchor string `json:"state_tree_anchor"` // hex32
	TimeUnix        uint64 `json:"time_unix"`
	SetHash         string `json:"set_hash"` // the genesis validator set (AccumulateSpineSet.Hash)
}

// AccumulateSpineCheckpoint is the spine's state after one verified major block: what a proof certified from this
// major block onward starts from.
type AccumulateSpineCheckpoint struct {
	Major           uint64 `json:"major"`
	Height          int64  `json:"height"` // the CERTEN block that accepted it
	LastMinorBlock  uint64 `json:"last_minor_block"`
	RootChainAnchor string `json:"root_chain_anchor"` // hex32
	StateTreeAnchor string `json:"state_tree_anchor"` // hex32
	SetHash         string `json:"set_hash"`
	// NetworkUpdates counts the writes to the network definition applied from genesis up to this checkpoint.
	NetworkUpdates uint64 `json:"network_updates"`
}

// AccumulateSpineSet is one validator set: the network definition and globals records in force, as encoded on chain.
// Hash is sha256(networkRecord) || sha256(globalsRecord), hashed again, hex.
type AccumulateSpineSet struct {
	Hash          string `json:"hash"`
	NetworkRecord string `json:"network_record"` // hex
	GlobalsRecord string `json:"globals_record"` // hex
}

// SetByHash returns the set with hash h.
func (l *AccumulateSpineLog) SetByHash(h string) (*AccumulateSpineSet, bool) {
	for i := range l.Sets {
		if l.Sets[i].Hash == h {
			return &l.Sets[i], true
		}
	}
	return nil, false
}

// Checkpoint returns the checkpoint after major block n.
func (l *AccumulateSpineLog) Checkpoint(n uint64) (*AccumulateSpineCheckpoint, bool) {
	if n == 0 || n > uint64(len(l.Checkpoints)) {
		return nil, false
	}
	c := &l.Checkpoints[n-1]
	return c, c.Major == n
}

// SaveAccumulateSpine persists the spine log.
func (s *LedgerStore) SaveAccumulateSpine(l *AccumulateSpineLog) error {
	b, err := json.Marshal(l)
	if err != nil {
		return fmt.Errorf("failed to marshal AccumulateSpineLog: %w", err)
	}
	return s.kv.Set(keyAccumulateSpine, b)
}

// LoadAccumulateSpine returns the spine log: empty when the chain has verified none, an error when it could not be
// read - never empty for an unreadable log, which would read as "no spine" and refuse every v3 proof on one node only.
func (s *LedgerStore) LoadAccumulateSpine() (*AccumulateSpineLog, error) {
	b, err := s.read(keyAccumulateSpine, "Accumulate spine")
	if err != nil {
		return nil, err
	}
	if b == nil {
		return &AccumulateSpineLog{}, nil
	}
	var l AccumulateSpineLog
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AccumulateSpineLog: %w", err)
	}
	return &l, nil
}
