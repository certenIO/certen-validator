// Copyright 2026 Certen Protocol

package execution

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// NonSettlementRecord is a member failure waiting to be attested (RB3-F49). It is queued the moment the
// member leaves the batch path, and attested once the chain's finalized time is past the member's
// deadline - before then, "not settled" is not yet the member's outcome.
type NonSettlementRecord struct {
	Facts NonSettlementFacts `json:"facts"`
	Cause string             `json:"cause"`

	// The proof cycle's write-back identity, as a settlement's cycle carries it.
	UserID       string  `json:"user_id,omitempty"`
	AccountURL   string  `json:"account_url"`
	AccumTxHash  string  `json:"accum_tx_hash"`
	BVN          string  `json:"bvn,omitempty"`
	MemberChains []int64 `json:"member_chains"`
	MemberLegs   int     `json:"member_legs"`
	// ProofClass is the lane the member was queued in; empty on records queued before it was kept.
	ProofClass string `json:"proof_class,omitempty"`

	QueuedAt  time.Time `json:"queued_at"`
	Attempts  int       `json:"attempts,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	// ClaimBlock is the finalized block the non-settlement was first observed at; every attempt claims it there, so
	// peers whose view of the chain trails this node's reach the same block (RB5-F46). 0 until first observed.
	ClaimBlock uint64 `json:"claim_block,omitempty"`
}

func (r *NonSettlementRecord) key() string {
	return r.Facts.IntentID + "|" + strconv.FormatInt(r.Facts.ChainID, 10)
}

// NonSettlementQueue holds the records durably: a failure found before its deadline must survive a
// restart until it is attested, or it is recorded nowhere again.
type NonSettlementQueue struct {
	mu   sync.Mutex
	path string
	recs map[string]*NonSettlementRecord
}

// OpenNonSettlementQueue loads the queue at path. An unreadable queue is an ERROR, not an empty one:
// treating it as empty would forget failures already found.
func OpenNonSettlementQueue(path string) (*NonSettlementQueue, error) {
	q := &NonSettlementQueue{path: path, recs: map[string]*NonSettlementRecord{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return q, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading non-settlement queue %s: %w", path, err)
	}
	var list []*NonSettlementRecord
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("decoding non-settlement queue %s: %w", path, err)
	}
	for _, r := range list {
		if r != nil {
			q.recs[r.key()] = r
		}
	}
	return q, nil
}

// Put records r, replacing a record for the same member.
func (q *NonSettlementQueue) Put(r *NonSettlementRecord) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	prev := q.recs[r.key()]
	q.recs[r.key()] = r
	if err := q.saveLocked(); err != nil {
		if prev != nil {
			q.recs[r.key()] = prev
		} else {
			delete(q.recs, r.key())
		}
		return err
	}
	return nil
}

// Remove drops the member's record.
func (q *NonSettlementQueue) Remove(intentID string, chainID int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	k := intentID + "|" + strconv.FormatInt(chainID, 10)
	prev, ok := q.recs[k]
	if !ok {
		return nil
	}
	delete(q.recs, k)
	if err := q.saveLocked(); err != nil {
		q.recs[k] = prev
		return err
	}
	return nil
}

// All returns the records, oldest first.
func (q *NonSettlementQueue) All() []*NonSettlementRecord {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]*NonSettlementRecord, 0, len(q.recs))
	for _, r := range q.recs {
		c := *r
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].QueuedAt.Before(out[j].QueuedAt) })
	return out
}

// saveLocked writes the queue atomically (temp file, then rename). Caller holds q.mu.
func (q *NonSettlementQueue) saveLocked() error {
	list := make([]*NonSettlementRecord, 0, len(q.recs))
	for _, r := range q.recs {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].key() < list[j].key() })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(q.path), 0o700); err != nil {
		return fmt.Errorf("non-settlement queue directory: %w", err)
	}
	tmp := q.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("writing non-settlement queue: %w", err)
	}
	if err := os.Rename(tmp, q.path); err != nil {
		return fmt.Errorf("replacing non-settlement queue: %w", err)
	}
	return nil
}
