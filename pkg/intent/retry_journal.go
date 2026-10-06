// Copyright 2026 Certen Protocol

package intent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Intents waiting on this validator for their consensus-bound proof (RB6-F12).
//
// An on_demand intent whose proof is not available yet is retried off the block workers' path, and its block is
// passed by the watermark as searched. The retry lived only in memory: a restart, a deploy or a stop lost it, and
// the intent was never processed again nor recorded failed - it stayed `authorized` for good, which is how intents
// stranded in intent_lifecycle. Every retry is now kept here from the moment it is queued until it ends (processed,
// or failed and recorded so), and the retries kept are resumed when discovery starts.

// PendingRetry is one intent whose retry has not ended.
type PendingRetry struct {
	IntentID    string    `json:"intent_id"`
	BlockHeight uint64    `json:"block_height"`
	Attempts    int       `json:"attempts"`
	FirstSeen   time.Time `json:"first_seen"`
	LastError   string    `json:"last_error"`
}

// RetryJournal keeps pending retries durably.
type RetryJournal interface {
	Keep(r PendingRetry) error
	List() ([]PendingRetry, error)
	Drop(intentID string) error
}

// FileRetryJournal keeps the set in one JSON file, replaced atomically on every change.
type FileRetryJournal struct {
	path string
	mu   sync.Mutex
}

// OpenFileRetryJournal opens (creating if needed) the journal at path; an unreadable file is an error.
func OpenFileRetryJournal(path string) (*FileRetryJournal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("retry journal: %w", err)
	}
	j := &FileRetryJournal{path: path}
	if _, err := j.load(); err != nil {
		return nil, err
	}
	return j, nil
}

// Path reports where the journal is stored.
func (j *FileRetryJournal) Path() string { return j.path }

func (j *FileRetryJournal) load() (map[string]PendingRetry, error) {
	raw, err := os.ReadFile(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]PendingRetry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("retry journal %s: %w", j.path, err)
	}
	var list []PendingRetry
	if err := json.Unmarshal(raw, &list); err != nil {
		// Unreadable is not empty: the retries it held would be lost.
		return nil, fmt.Errorf("retry journal %s does not decode: %w", j.path, err)
	}
	m := make(map[string]PendingRetry, len(list))
	for _, r := range list {
		m[r.IntentID] = r
	}
	return m, nil
}

func (j *FileRetryJournal) save(m map[string]PendingRetry) error {
	list := make([]PendingRetry, 0, len(m))
	for _, r := range m {
		list = append(list, r)
	}
	sortPendingRetries(list)
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(j.path, raw); err != nil {
		return fmt.Errorf("retry journal: %w", err)
	}
	return nil
}

// Keep records r, replacing the entry of the same intent; the first time it was kept is preserved.
func (j *FileRetryJournal) Keep(r PendingRetry) error {
	if r.IntentID == "" || r.BlockHeight == 0 {
		return fmt.Errorf("retry journal: a pending retry needs its intent and its block")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	m, err := j.load()
	if err != nil {
		return err
	}
	if prev, ok := m[r.IntentID]; ok && !prev.FirstSeen.IsZero() {
		r.FirstSeen = prev.FirstSeen
	}
	if r.FirstSeen.IsZero() {
		r.FirstSeen = time.Now().UTC()
	}
	m[r.IntentID] = r
	return j.save(m)
}

// List returns the pending retries, oldest block first.
func (j *FileRetryJournal) List() ([]PendingRetry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	m, err := j.load()
	if err != nil {
		return nil, err
	}
	out := make([]PendingRetry, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sortPendingRetries(out)
	return out, nil
}

// Drop removes the retry of an intent whose retry has ended.
func (j *FileRetryJournal) Drop(intentID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	m, err := j.load()
	if err != nil {
		return err
	}
	if _, ok := m[intentID]; !ok {
		return nil
	}
	delete(m, intentID)
	return j.save(m)
}

func sortPendingRetries(list []PendingRetry) {
	sort.Slice(list, func(a, b int) bool {
		if list[a].BlockHeight != list[b].BlockHeight {
			return list[a].BlockHeight < list[b].BlockHeight
		}
		return list[a].IntentID < list[b].IntentID
	})
}

// writeFileAtomic replaces path with raw: written and synced beside it, then renamed over it.
func writeFileAtomic(path string, raw []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
